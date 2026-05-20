import asyncio
import time
import uuid
import json
import structlog
from typing import AsyncGenerator
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from app.models.request import ChatCompletionRequest
from app.middleware.auth import auth_middleware
from app.middleware.rate_limit import rate_limit_middleware, increment_token_usage
from app.middleware.pii_engine import pii_scan_request
from app.middleware.guardrails import guardrails_middleware
from app.middleware.response_scanner import scan_response
from app.services.llm_router import route_request, stream_request
from app.services.audit_service import log_transaction, log_guardrail_incident, fire_and_forget_audit
from app.services.cost_calculator import calculate_cost

log = structlog.get_logger()
router = APIRouter()


async def _run_pipeline(request: Request, body: ChatCompletionRequest) -> None:
    """Execute the 4-step pre-LLM interceptor pipeline in order."""
    request.state.parsed_body = body
    await auth_middleware(request)
    await rate_limit_middleware(request)
    await pii_scan_request(request)
    await guardrails_middleware(request)


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    # Initialize pipeline state
    request.state.pipeline_timing = {}
    request.state._pipeline_start = time.monotonic()
    request.state.pii_detected = []
    request.state.response_pii_detected = []
    request.state.prompt_hash = ""
    request.state.guardrail_triggered = None
    request.state.guardrail_layer = None

    body_bytes = await request.body()
    try:
        body_dict = json.loads(body_bytes)
        body = ChatCompletionRequest.model_validate(body_dict)
    except Exception as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_request_body", "message": str(exc)})

    model_requested = body.model

    # Run interceptor pipeline
    try:
        await _run_pipeline(request, body)
    except HTTPException as exc:
        # Log guardrail/policy blocks asynchronously even on pipeline rejection
        if exc.status_code == 451:
            claims = getattr(request.state, "jwt_claims", {})
            tx_id = uuid.uuid4()
            fire_and_forget_audit(
                log_transaction(
                    org_id=claims.get("org_id", "unknown"),
                    app_source=claims.get("app_source", "unknown"),
                    model_requested=model_requested,
                    model_used="",
                    provider="",
                    prompt_hash=getattr(request.state, "prompt_hash", ""),
                    pii_detected=getattr(request.state, "pii_detected", []),
                    response_pii_detected=[],
                    input_tokens=0,
                    output_tokens=0,
                    cost_usd=0.0,
                    compliance_status="blocked",
                    guardrail_triggered=getattr(request.state, "guardrail_triggered", None),
                    latency_ms=int((time.monotonic() - request.state._pipeline_start) * 1000),
                    industry_type=request.headers.get("X-Industry-Type", ""),
                    routing_reason="guardrail_block",
                    transaction_id=tx_id,
                )
            )
            fire_and_forget_audit(
                log_guardrail_incident(
                    org_id=claims.get("org_id", "unknown"),
                    transaction_id=tx_id,
                    policy_profile=request.headers.get("X-Industry-Type", ""),
                    violation_category=getattr(request.state, "guardrail_triggered", "unknown"),
                    detection_layer=getattr(request.state, "guardrail_layer", "unknown"),
                    prompt_hash=getattr(request.state, "prompt_hash", ""),
                )
            )
        raise

    claims = request.state.jwt_claims
    org_id = claims.get("org_id", "unknown")

    if body.stream:
        return StreamingResponse(
            _stream_response(body, request, model_requested),
            media_type="text/event-stream",
            headers={"X-VisorShield-Request-ID": request.state.request_id},
        )

    # Non-streaming
    pipeline_start = request.state._pipeline_start
    try:
        result, model_used, provider, routing_reason = await route_request(body, request)
    except HTTPException:
        raise
    except Exception as exc:
        log.error("llm_call_failed", error=str(exc), org_id=org_id, request_id=request.state.request_id)
        raise HTTPException(status_code=502, detail={"error": "upstream_error", "message": str(exc)})

    latency_ms = int((time.monotonic() - pipeline_start) * 1000)

    # Extract response text for scanning
    usage = result.get("usage", {})
    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)

    response_text = ""
    for choice in result.get("choices", []):
        msg = choice.get("message", {})
        content = msg.get("content", "")
        if content:
            response_text += content

    # Step 5: Response scanner
    masked_response = await scan_response(response_text, request)

    # Patch response with masked content
    for choice in result.get("choices", []):
        msg = choice.get("message", {})
        if msg.get("content"):
            msg["content"] = masked_response

    cost_usd = calculate_cost(model_used, input_tokens, output_tokens)

    # Async audit logging (non-blocking)
    fire_and_forget_audit(
        log_transaction(
            org_id=org_id,
            app_source=claims.get("app_source", "unknown"),
            model_requested=model_requested,
            model_used=model_used,
            provider=provider,
            prompt_hash=getattr(request.state, "prompt_hash", ""),
            pii_detected=getattr(request.state, "pii_detected", []),
            response_pii_detected=getattr(request.state, "response_pii_detected", []),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            compliance_status="pass",
            guardrail_triggered=None,
            latency_ms=latency_ms,
            industry_type=request.headers.get("X-Industry-Type", ""),
            routing_reason=routing_reason,
        )
    )

    # Update token counts in Redis (non-blocking)
    fire_and_forget_audit(increment_token_usage(request, input_tokens, output_tokens))

    response = JSONResponse(content=result)
    response.headers["X-VisorShield-Request-ID"] = request.state.request_id
    return response


async def _stream_response(
    body: ChatCompletionRequest,
    request: Request,
    model_requested: str,
) -> AsyncGenerator[str, None]:
    """
    Pipe SSE chunks (already in OpenAI format from stream_request) while buffering
    the full response text for post-stream PII scanning and audit logging.
    """
    from app.services.llm_router import _detect_provider
    claims = request.state.jwt_claims
    org_id = claims.get("org_id", "unknown")
    pipeline_start = request.state._pipeline_start
    buffered_content = []
    input_tokens = 0
    output_tokens = 0
    model_used = body.model
    provider = _detect_provider(body.model)
    routing_reason = "stream"

    try:
        async for line in stream_request(body, request):
            # stream_request yields bare lines; emit as proper SSE frames
            stripped = line.rstrip("\n")
            if stripped:
                yield f"{stripped}\n\n" if not stripped.endswith("\n") else f"{stripped}\n"
            # Parse OpenAI-format chunks to buffer content + usage
            if stripped.startswith("data: ") and stripped != "data: [DONE]":
                try:
                    chunk_data = json.loads(stripped[6:])
                    for choice in chunk_data.get("choices", []):
                        content = choice.get("delta", {}).get("content", "")
                        if content:
                            buffered_content.append(content)
                    chunk_usage = chunk_data.get("usage")
                    if chunk_usage:
                        input_tokens = chunk_usage.get("prompt_tokens", input_tokens)
                        output_tokens = chunk_usage.get("completion_tokens", output_tokens)
                    model_used = chunk_data.get("model", model_used)
                    # Derive provider from actual model name
                    provider = _detect_provider(model_used)
                except Exception:
                    pass
    except Exception as exc:
        log.error("stream_failed", error=str(exc), org_id=org_id, request_id=request.state.request_id)
        yield "data: [DONE]\n\n"
        return

    # Post-stream response scan (step 5)
    full_response = "".join(buffered_content)
    if full_response:
        await scan_response(full_response, request)

    latency_ms = int((time.monotonic() - pipeline_start) * 1000)
    cost_usd = calculate_cost(model_used, input_tokens, output_tokens)

    fire_and_forget_audit(
        log_transaction(
            org_id=org_id,
            app_source=claims.get("app_source", "unknown"),
            model_requested=model_requested,
            model_used=model_used,
            provider=provider,
            prompt_hash=getattr(request.state, "prompt_hash", ""),
            pii_detected=getattr(request.state, "pii_detected", []),
            response_pii_detected=getattr(request.state, "response_pii_detected", []),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            compliance_status="pass",
            guardrail_triggered=None,
            latency_ms=latency_ms,
            industry_type=request.headers.get("X-Industry-Type", ""),
            routing_reason=routing_reason,
        )
    )

    fire_and_forget_audit(increment_token_usage(request, input_tokens, output_tokens))

    yield "data: [DONE]\n\n"
