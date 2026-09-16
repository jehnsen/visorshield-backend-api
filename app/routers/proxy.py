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
from app.middleware.pii_engine import pii_scan_request, rehydrate_pii
from app.middleware.guardrails import guardrails_middleware
from app.middleware.response_scanner import scan_response
from app.services.llm_router import route_request, stream_request
from app.services.audit_service import log_transaction, log_guardrail_incident, fire_and_forget_audit
from app.services.cost_calculator import calculate_cost
from app.policies import VALID_INDUSTRY_TYPES
from app.config import settings

log = structlog.get_logger()
router = APIRouter()


def _require_valid_industry_type(request: Request) -> str:
    """
    Enforce a recognized X-Industry-Type header before any pipeline step runs.

    Fail-closed: an unknown or missing profile would cause PII masking to fall
    back to a generic entity list and would skip the guardrail check entirely,
    so the request is rejected outright — consistent with the PII fail-closed rule.
    """
    industry_type = request.headers.get("X-Industry-Type", "").strip()
    if industry_type not in VALID_INDUSTRY_TYPES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_industry_type",
                "message": "X-Industry-Type header is required and must be one of: "
                + ", ".join(sorted(VALID_INDUSTRY_TYPES)),
                "allowed": sorted(VALID_INDUSTRY_TYPES),
            },
        )
    return industry_type


async def _run_pipeline(request: Request, body: ChatCompletionRequest) -> None:
    """Execute the 4-step pre-LLM interceptor pipeline in order."""
    request.state.parsed_body = body
    _require_valid_industry_type(request)
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
                    industry_type=claims.get("industry_type") or request.headers.get("X-Industry-Type", ""),
                    routing_reason="guardrail_block",
                    transaction_id=tx_id,
                )
            )
            fire_and_forget_audit(
                log_guardrail_incident(
                    org_id=claims.get("org_id", "unknown"),
                    transaction_id=tx_id,
                    policy_profile=claims.get("industry_type") or request.headers.get("X-Industry-Type", ""),
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

    # Step 5: Response scanner — scan each choice independently. Concatenating all
    # choices into one blob (n > 1) and writing it back to every choice both
    # corrupts multi-choice responses and cross-contaminates them.
    #
    # Order per choice: scan (mask model-introduced PII) → rehydrate (restore the
    # caller's own PII that we masked out of the prompt). Rehydration must come
    # after the scan so restored values aren't re-flagged/re-masked.
    ph_map = getattr(request.state, "pii_placeholder_map", {})
    all_response_pii: list = []
    rehydrated_total = 0
    for choice in result.get("choices", []):
        msg = choice.get("message", {})
        content = msg.get("content", "")
        if not content:
            continue
        scanned = await scan_response(content, request)
        all_response_pii.extend(getattr(request.state, "response_pii_detected", []))
        if settings.PII_REHYDRATION_ENABLED:
            scanned, n = rehydrate_pii(scanned, ph_map)
            rehydrated_total += n
        msg["content"] = scanned

    request.state.response_pii_detected = sorted(set(all_response_pii))
    if rehydrated_total:
        log.info(
            "pii_rehydrated",
            org_id=org_id,
            request_id=request.state.request_id,
            pipeline_step="response_scanner",
            substitutions=rehydrated_total,
        )

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
            industry_type=claims.get("industry_type") or request.headers.get("X-Industry-Type", ""),
            routing_reason=routing_reason,
        )
    )

    # Update token counts in Redis (non-blocking)
    fire_and_forget_audit(increment_token_usage(request, input_tokens, output_tokens))

    response = JSONResponse(content=result)
    response.headers["X-VisorShield-Request-ID"] = request.state.request_id
    pii_masked = bool(
        getattr(request.state, "pii_detected", [])
        or getattr(request.state, "response_pii_detected", [])
    )
    response.headers["X-VisorShield-PII-Masked"] = "true" if pii_masked else "false"
    response.headers["X-VisorShield-Model-Used"] = model_used
    return response


async def _stream_response(
    body: ChatCompletionRequest,
    request: Request,
    model_requested: str,
) -> AsyncGenerator[str, None]:
    """
    Stream an SSE response with step-5 PII scanning enforced on the client path.

    Default (compliance) mode: the full upstream response is buffered, run through
    scan_response(), and only the *masked* text is emitted to the client. Nothing
    reaches the caller until PII scanning has passed — no raw LLM output is ever
    streamed.

    Pass-through mode (JWT claim ``allow_streaming_passthrough: true``, an explicit
    per-org opt-in): raw chunks are streamed live for low TTFB. The scan still runs
    afterwards, and if it changed anything a trailing correction frame carrying the
    masked text is appended so raw PII is never left uncorrected.
    """
    from app.services.llm_router import _detect_provider
    claims = request.state.jwt_claims
    org_id = claims.get("org_id", "unknown")
    pipeline_start = request.state._pipeline_start
    passthrough = bool(claims.get("allow_streaming_passthrough", False))
    buffered_content = []
    input_tokens = 0
    output_tokens = 0
    model_used = body.model
    provider = _detect_provider(body.model)
    routing_reason = "stream" if passthrough else "stream_buffered"

    try:
        async for line in stream_request(body, request):
            stripped = line.rstrip("\n")
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
            # Only forward raw chunks live when the org opted into pass-through.
            if passthrough and stripped:
                yield f"{stripped}\n\n" if not stripped.endswith("\n") else f"{stripped}\n"
    except Exception as exc:
        log.error("stream_failed", error=str(exc), org_id=org_id, request_id=request.state.request_id)
        yield "data: [DONE]\n\n"
        return

    # Step 5: response scan — enforced on the streaming path, not audit-only.
    full_response = "".join(buffered_content)
    masked_response = await scan_response(full_response, request) if full_response else ""

    # Rehydrate the caller's own PII (masked out of the prompt) in the buffered
    # path. Pass-through mode already streamed raw chunks with placeholders in
    # them — that is the documented cost of the opt-in.
    if full_response and not passthrough and settings.PII_REHYDRATION_ENABLED:
        ph_map = getattr(request.state, "pii_placeholder_map", {})
        masked_response, n = rehydrate_pii(masked_response, ph_map)
        if n:
            log.info(
                "pii_rehydrated",
                org_id=org_id,
                request_id=getattr(request.state, "request_id", ""),
                pipeline_step="response_scanner",
                substitutions=n,
            )

    def _sse_chunk(text: str) -> str:
        payload = {
            "id": f"chatcmpl-{getattr(request.state, 'request_id', '')}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model_used,
            "choices": [
                {"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": "stop"}
            ],
        }
        return f"data: {json.dumps(payload)}\n\n"

    if not passthrough:
        # Client has received nothing yet — emit the scanned/masked response now.
        if full_response:
            yield _sse_chunk(masked_response)
    elif masked_response != full_response:
        # Raw chunks already went out and the scan changed something. Per the
        # fail-closed PII policy, follow up with the masked full text.
        log.warning(
            "stream_passthrough_pii_masked",
            org_id=org_id,
            request_id=getattr(request.state, "request_id", ""),
            pipeline_step="response_scanner",
        )
        yield _sse_chunk(
            "\n\n[VisorShield: PII was detected in the streamed response above. "
            "Masked version follows]\n" + masked_response
        )

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
            industry_type=claims.get("industry_type") or request.headers.get("X-Industry-Type", ""),
            routing_reason=routing_reason,
        )
    )

    fire_and_forget_audit(increment_token_usage(request, input_tokens, output_tokens))

    yield "data: [DONE]\n\n"
