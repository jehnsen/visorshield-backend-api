import time
import structlog
import httpx
from typing import AsyncGenerator, Tuple, Dict, Any
from fastapi import Request
from app.config import settings
from app.models.request import ChatCompletionRequest
from app.services.cost_calculator import should_use_cheap_model, CHEAP_MODEL_MAP

log = structlog.get_logger()

OPENAI_BASE_URL = "https://api.openai.com/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"

ANTHROPIC_MODEL_MAP = {
    "claude-sonnet-4-5": "claude-sonnet-4-5-20251001",
    "claude-haiku-4-5": "claude-haiku-4-5-20251001",
    "claude-opus-4-5": "claude-opus-4-5-20251001",
}

OPENAI_MODELS = {"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"}
ANTHROPIC_MODELS = set(ANTHROPIC_MODEL_MAP.keys())


def _detect_provider(model: str) -> str:
    if model in OPENAI_MODELS:
        return "openai"
    if model in ANTHROPIC_MODELS:
        return "anthropic"
    return settings.DEFAULT_PROVIDER


def _openai_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }


def _anthropic_headers() -> Dict[str, str]:
    return {
        "x-api-key": settings.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }


def _to_anthropic_payload(body: ChatCompletionRequest) -> Dict[str, Any]:
    system_msgs = [m for m in body.messages if m.role == "system"]
    non_system = [m for m in body.messages if m.role != "system"]

    payload: Dict[str, Any] = {
        "model": ANTHROPIC_MODEL_MAP.get(body.model, body.model),
        "max_tokens": body.max_tokens or 4096,
        "messages": [{"role": m.role, "content": m.content} for m in non_system],
        "stream": body.stream or False,
    }
    if system_msgs:
        payload["system"] = system_msgs[0].content
    if body.temperature is not None:
        payload["temperature"] = body.temperature
    return payload


async def _call_openai(
    client: httpx.AsyncClient, body: ChatCompletionRequest
) -> httpx.Response:
    payload = body.model_dump(exclude_none=True)
    return await client.post(
        f"{OPENAI_BASE_URL}/chat/completions",
        json=payload,
        headers=_openai_headers(),
        timeout=120.0,
    )


async def _call_anthropic(
    client: httpx.AsyncClient, body: ChatCompletionRequest
) -> httpx.Response:
    payload = _to_anthropic_payload(body)
    return await client.post(
        f"{ANTHROPIC_BASE_URL}/messages",
        json=payload,
        headers=_anthropic_headers(),
        timeout=120.0,
    )


def _normalize_anthropic_response(data: Dict, model: str) -> Dict:
    """Convert Anthropic response to OpenAI-compatible format."""
    import time as t
    content = data.get("content", [])
    text_content = " ".join(c.get("text", "") for c in content if c.get("type") == "text")
    return {
        "id": data.get("id", ""),
        "object": "chat.completion",
        "created": int(t.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text_content},
                "finish_reason": data.get("stop_reason", "stop"),
            }
        ],
        "usage": {
            "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
            "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
            "total_tokens": (
                data.get("usage", {}).get("input_tokens", 0)
                + data.get("usage", {}).get("output_tokens", 0)
            ),
        },
    }


async def route_request(
    body: ChatCompletionRequest,
    request: Request,
) -> Tuple[Dict[str, Any], str, str, str]:
    """
    Returns (response_dict, model_used, provider, routing_reason).
    Implements cost-based routing and provider fallback.
    """
    claims = getattr(request.state, "jwt_claims", {})
    allowed_models = claims.get("allowed_models", [])

    use_cheap, routing_reason = should_use_cheap_model(body.messages)

    target_model = body.model
    if use_cheap:
        provider_guess = _detect_provider(body.model)
        cheap = CHEAP_MODEL_MAP.get(provider_guess, body.model)
        if not allowed_models or cheap in allowed_models:
            target_model = cheap

    provider = _detect_provider(target_model)

    async with httpx.AsyncClient() as client:
        response = await _try_provider(client, body, target_model, provider)

        if response is None:
            # Fallback to secondary provider
            fallback_provider = "anthropic" if provider == "openai" else "openai"
            fallback_model = CHEAP_MODEL_MAP.get(fallback_provider, target_model)
            log.warning(
                "provider_fallback",
                primary=provider,
                fallback=fallback_provider,
                request_id=getattr(request.state, "request_id", ""),
                pipeline_step="llm_router",
            )
            body.model = fallback_model
            response = await _try_provider(client, body, fallback_model, fallback_provider)
            provider = fallback_provider
            target_model = fallback_model
            routing_reason = f"fallback_to_{fallback_provider}"

        if response is None:
            from fastapi import HTTPException
            # Failure-mode contract: LLM provider 5xx → retry once → fallback → 502
            raise HTTPException(status_code=502, detail={"error": "all_providers_failed"})

        if provider == "anthropic":
            result = _normalize_anthropic_response(response, target_model)
        else:
            result = response

    return result, target_model, provider, routing_reason


async def _try_provider(
    client: httpx.AsyncClient,
    body: ChatCompletionRequest,
    model: str,
    provider: str,
) -> Dict | None:
    original_model = body.model
    body.model = model
    try:
        if provider == "openai":
            resp = await _call_openai(client, body)
        else:
            resp = await _call_anthropic(client, body)

        if resp.status_code >= 500:
            log.warning(
                "provider_5xx",
                provider=provider,
                status=resp.status_code,
                pipeline_step="llm_router",
            )
            # Retry once
            if provider == "openai":
                resp = await _call_openai(client, body)
            else:
                resp = await _call_anthropic(client, body)

        if resp.status_code >= 500:
            return None

        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError:
        return None
    except Exception as exc:
        log.error("provider_call_failed", provider=provider, error=str(exc), pipeline_step="llm_router")
        return None
    finally:
        body.model = original_model


async def stream_request(
    body: ChatCompletionRequest,
    request: Request,
) -> AsyncGenerator[str, None]:
    """
    Yields OpenAI-format SSE lines from either OpenAI or Anthropic.
    Anthropic's event-based stream is normalised to OpenAI chunk format chunk-by-chunk.
    """
    claims = getattr(request.state, "jwt_claims", {})
    use_cheap, _ = should_use_cheap_model(body.messages)
    target_model = body.model
    provider = _detect_provider(target_model)

    if use_cheap:
        cheap = CHEAP_MODEL_MAP.get(provider, target_model)
        allowed = claims.get("allowed_models", [])
        if not allowed or cheap in allowed:
            target_model = cheap
            provider = _detect_provider(target_model)

    body.model = target_model

    async with httpx.AsyncClient() as client:
        if provider == "openai":
            payload = body.model_dump(exclude_none=True)
            url = f"{OPENAI_BASE_URL}/chat/completions"
            headers = _openai_headers()
            async with client.stream("POST", url, json=payload, headers=headers, timeout=120.0) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line:
                        yield line + "\n"
        else:
            async for chunk in _stream_anthropic_normalised(client, body, target_model):
                yield chunk


async def _stream_anthropic_normalised(
    client: httpx.AsyncClient,
    body: ChatCompletionRequest,
    model: str,
) -> AsyncGenerator[str, None]:
    """
    Consumes Anthropic's event-based SSE stream and emits OpenAI-format data lines.

    Anthropic event types handled:
      message_start      → emit first chunk with role delta
      content_block_delta (text_delta) → emit content delta chunk
      message_delta      → emit finish_reason chunk + usage
      message_stop       → emit [DONE]
      ping / content_block_start / content_block_stop → skipped
    """
    import json as _json
    import time as _time

    payload = _to_anthropic_payload(body)
    url = f"{ANTHROPIC_BASE_URL}/messages"
    headers = _anthropic_headers()

    completion_id: str = f"chatcmpl-ant-{int(_time.time())}"
    created_ts: int = int(_time.time())
    current_event: str = ""
    _input_tokens: int = 0  # captured from message_start

    def _make_chunk(delta: dict, finish_reason=None, usage=None) -> str:
        chunk: dict = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created_ts,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish_reason,
                    "logprobs": None,
                }
            ],
        }
        if usage:
            chunk["usage"] = usage
        return f"data: {_json.dumps(chunk, separators=(',', ':'))}\n"

    async with client.stream("POST", url, json=payload, headers=headers, timeout=120.0) as resp:
        resp.raise_for_status()

        async for raw_line in resp.aiter_lines():
            if not raw_line:
                continue

            if raw_line.startswith("event: "):
                current_event = raw_line[7:].strip()
                continue

            if not raw_line.startswith("data: "):
                continue

            data_str = raw_line[6:].strip()
            if not data_str or data_str == "[DONE]":
                continue

            try:
                event_data = _json.loads(data_str)
            except _json.JSONDecodeError:
                continue

            etype = event_data.get("type", current_event)

            if etype == "message_start":
                msg = event_data.get("message", {})
                completion_id = f"chatcmpl-{msg.get('id', int(_time.time()))}"
                _input_tokens = msg.get("usage", {}).get("input_tokens", 0)
                # Emit role chunk
                yield _make_chunk({"role": "assistant", "content": ""})

            elif etype == "content_block_delta":
                delta_obj = event_data.get("delta", {})
                if delta_obj.get("type") == "text_delta":
                    text = delta_obj.get("text", "")
                    if text:
                        yield _make_chunk({"content": text})

            elif etype == "message_delta":
                delta_obj = event_data.get("delta", {})
                stop_reason = delta_obj.get("stop_reason", "stop")
                # Map Anthropic stop reasons to OpenAI finish_reason values
                finish_reason = {
                    "end_turn": "stop",
                    "max_tokens": "length",
                    "stop_sequence": "stop",
                    "tool_use": "tool_calls",
                }.get(stop_reason, "stop")

                usage_data = event_data.get("usage", {})
                usage = None
                if usage_data:
                    usage = {
                        "prompt_tokens": _input_tokens,
                        "completion_tokens": usage_data.get("output_tokens", 0),
                        "total_tokens": usage_data.get("output_tokens", 0),
                    }
                yield _make_chunk({}, finish_reason=finish_reason, usage=usage)

            elif etype == "message_stop":
                yield "data: [DONE]\n"

            # ping / content_block_start / content_block_stop are intentionally skipped
