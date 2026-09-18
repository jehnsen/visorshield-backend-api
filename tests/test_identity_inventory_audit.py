import pytest
import uuid
from unittest.mock import patch, AsyncMock, MagicMock
from tests.conftest import make_jwt, FAKE_OPENAI_RESPONSE
from app.services.audit_integrity import canonical_transaction_fields, recompute_record_hash

pytestmark = pytest.mark.asyncio

HEADERS = {"X-Industry-Type": "healthcare", "X-Org-ID": "test-org-123", "X-VisorShield-User": "alice@example.com"}
CHAT_PAYLOAD = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}


def _patched_pii():
    mock = MagicMock()
    mock.analyze.return_value = []
    return patch("app.middleware.pii_engine.get_analyzer", return_value=mock)


# ── X-VisorShield-User is a required header ────────────────────────────────

async def test_missing_visorshield_user_header_is_rejected(client, valid_token):
    headers = {k: v for k, v in HEADERS.items() if k != "X-VisorShield-User"}
    resp = await client.post(
        "/v1/chat/completions",
        json=CHAT_PAYLOAD,
        headers={**headers, "Authorization": f"Bearer {valid_token}"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "missing_visorshield_user_header"


async def test_visorshield_user_header_present_passes(client, valid_token):
    with _patched_pii(), \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock, return_value=FAKE_OPENAI_RESPONSE):
        resp = await client.post(
            "/v1/chat/completions",
            json=CHAT_PAYLOAD,
            headers={**HEADERS, "Authorization": f"Bearer {valid_token}"},
        )
    assert resp.status_code == 200


async def test_identity_resolution_failure_fails_open_not_closed(client, valid_token):
    """
    A broken identity lookup (get_or_create_user raising/erroring) must not
    block the request — it's an enrichment, not a security gate. The org/key
    active check is the actual gate and is exercised separately.
    """
    with _patched_pii(), \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock, return_value=FAKE_OPENAI_RESPONSE), \
         patch("app.services.identity_service.get_or_create_user", new_callable=AsyncMock, return_value=None):
        resp = await client.post(
            "/v1/chat/completions",
            json=CHAT_PAYLOAD,
            headers={**HEADERS, "Authorization": f"Bearer {valid_token}"},
        )
    assert resp.status_code == 200


# ── Audit hash chain: pure canonicalization/hash determinism (no DB) ───────

def _sample_fields(**overrides):
    base = dict(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        org_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        app_source="HR-Portal",
        model_requested="gpt-4o",
        model_used="gpt-4o-mini",
        provider="openai",
        prompt_hash="a" * 64,
        pii_detected=["EMAIL_ADDRESS", "PERSON"],
        response_pii_detected=[],
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.00012345,
        compliance_status="pass",
        guardrail_triggered=None,
        latency_ms=250,
        industry_type="healthcare",
        routing_reason="normal_routing",
        user_id=None,
        external_user_id="alice@example.com",
        created_at="2026-09-16T00:00:00+00:00",
    )
    base.update(overrides)
    return canonical_transaction_fields(**base)


def test_canonical_fields_are_order_independent_for_pii_lists():
    """PII entity lists must hash the same regardless of detection order."""
    fields_a = _sample_fields(pii_detected=["PERSON", "EMAIL_ADDRESS"])
    fields_b = _sample_fields(pii_detected=["EMAIL_ADDRESS", "PERSON"])
    assert fields_a == fields_b


def test_record_hash_changes_if_any_field_changes():
    fields = _sample_fields()
    h1 = recompute_record_hash(fields, prev_hash=None)

    tampered = _sample_fields(compliance_status="blocked")
    h2 = recompute_record_hash(tampered, prev_hash=None)

    assert h1 != h2


def test_record_hash_is_deterministic():
    fields = _sample_fields()
    h1 = recompute_record_hash(fields, prev_hash="deadbeef")
    h2 = recompute_record_hash(fields, prev_hash="deadbeef")
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex digest


def test_record_hash_depends_on_prev_hash():
    """Same record content chained after a different prior link must differ — this is what makes a chain, not just per-row hashes."""
    fields = _sample_fields()
    h_genesis = recompute_record_hash(fields, prev_hash=None)
    h_chained = recompute_record_hash(fields, prev_hash="some-other-prior-hash")
    assert h_genesis != h_chained
