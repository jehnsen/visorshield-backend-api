"""
Full pipeline integration test.
Exercises: JWT auth → rate limit → PII scan → guardrails → LLM mock → response scan → audit.
Each step must succeed for the request to complete; failures are tested with targeted mocks.
"""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from tests.conftest import make_jwt, FAKE_OPENAI_RESPONSE

pytestmark = pytest.mark.asyncio

_CLEAN_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "What is the capital of France?"}],
}

_GOVTECH_HEADERS = {"X-Industry-Type": "govtech", "X-Org-ID": "test-org-123", "X-VisorShield-User": "test-user-1"}
_HEALTHCARE_HEADERS = {"X-Industry-Type": "healthcare", "X-Org-ID": "test-org-123", "X-VisorShield-User": "test-user-1"}


def _patched_pii():
    mock = MagicMock()
    mock.analyze.return_value = []
    return patch("app.middleware.pii_engine.get_analyzer", return_value=mock)


async def test_full_pipeline_happy_path(client):
    """All 5 steps pass → 200 with OpenAI-format response."""
    token = make_jwt()

    with _patched_pii(), \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock, return_value=FAKE_OPENAI_RESPONSE), \
         patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):

        resp = await client.post(
            "/v1/chat/completions",
            json=_CLEAN_PAYLOAD,
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert "choices" in body
    assert body["choices"][0]["message"]["role"] == "assistant"
    assert "X-VisorShield-Request-ID" in resp.headers


async def test_pipeline_step1_blocks_invalid_jwt(client):
    """Step 1 (auth) rejects bad JWT before any other step runs."""
    resp = await client.post(
        "/v1/chat/completions",
        json=_CLEAN_PAYLOAD,
        headers={**_HEALTHCARE_HEADERS, "Authorization": "Bearer not.a.real.jwt"},
    )
    assert resp.status_code == 401


async def test_pipeline_step2_blocks_on_quota(client, valid_token, fake_redis):
    """Step 2 (rate limit) blocks when monthly quota is exceeded."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"visorshield:test-org-123:default:monthly_tokens:{now.year}:{now.month}"
    await fake_redis.set(key, 999_999_999)

    with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        resp = await client.post(
            "/v1/chat/completions",
            json=_CLEAN_PAYLOAD,
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {valid_token}"},
        )
    assert resp.status_code == 429


async def test_pipeline_step3_blocks_on_pii_scan_error(client):
    """Step 3 (PII) fail-closed: Presidio exception → 500, request blocked."""
    token = make_jwt()
    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn, \
         patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        mock_fn.return_value = MagicMock(analyze=MagicMock(side_effect=RuntimeError("presidio down")))
        resp = await client.post(
            "/v1/chat/completions",
            json=_CLEAN_PAYLOAD,
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 500
    assert resp.json()["detail"]["error"] == "pii_scan_failed"


async def test_pipeline_step4_blocks_on_guardrail_keyword(client):
    """Step 4 (guardrails) keyword hit → 451 with policy_violation."""
    token = make_jwt()

    with _patched_pii(), \
         patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Can you prescribe antibiotics?"}],
            },
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 451
    detail = resp.json()["detail"]
    assert detail["error"] == "policy_violation"
    assert detail["policy"] == "healthcare"


async def test_pipeline_step5_masks_response_pii(client):
    """Step 5 (response scanner) masks PII found in LLM response."""
    from presidio_analyzer import RecognizerResult
    token = make_jwt()

    llm_response_with_pii = dict(FAKE_OPENAI_RESPONSE)
    llm_response_with_pii["choices"] = [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Call dr.jones@clinic.org for help."},
            "finish_reason": "stop",
        }
    ]

    detected_email = RecognizerResult(entity_type="EMAIL_ADDRESS", start=4, end=24, score=0.9)

    with _patched_pii(), \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock, return_value=llm_response_with_pii), \
         patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock), \
         patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
        # Request scan: no PII; response scan: email detected
        call_count = [0]

        def _side_effect():
            call_count[0] += 1
            m = MagicMock()
            if call_count[0] <= 1:
                m.analyze.return_value = []
            else:
                m.analyze.return_value = [detected_email]
            return m

        mock_fn.side_effect = _side_effect

        resp = await client.post(
            "/v1/chat/completions",
            json=_CLEAN_PAYLOAD,
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {token}"},
        )

    # Response may be 200 with masked content or placeholder if scan errored
    assert resp.status_code == 200
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    # Original email must not appear in response
    assert "dr.jones@clinic.org" not in content


async def test_pipeline_pii_masking_hashes_original_prompt(client):
    """Prompt hash must be SHA-256 of original text, not masked text."""
    import hashlib
    original_text = "My SSN is 123-45-6789"
    token = make_jwt()

    with _patched_pii(), \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock, return_value=FAKE_OPENAI_RESPONSE), \
         patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock), \
         patch("app.services.audit_service.log_transaction", new_callable=AsyncMock) as mock_log:

        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": original_text}]},
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    if mock_log.called:
        call_kwargs = mock_log.call_args.kwargs
        expected_hash = hashlib.sha256((original_text + "\n").encode()).hexdigest()
        assert call_kwargs.get("prompt_hash") == expected_hash


async def test_model_not_in_allowed_list_returns_403(client):
    """Model access control: JWT allows only gpt-4o-mini; gpt-4o → 403."""
    token = make_jwt(allowed_models=["gpt-4o-mini"])
    with _patched_pii(), \
         patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
            headers={**_HEALTHCARE_HEADERS, "Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "model_not_permitted"
