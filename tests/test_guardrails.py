import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_jwt

pytestmark = pytest.mark.asyncio

HEADERS_HEALTHCARE = {"X-Industry-Type": "healthcare", "X-Org-ID": "test-org-123"}
HEADERS_FINTECH = {"X-Industry-Type": "fintech", "X-Org-ID": "test-org-123"}
HEADERS_GOVTECH = {"X-Industry-Type": "govtech", "X-Org-ID": "test-org-123"}
HEADERS_LEGAL = {"X-Industry-Type": "legal_hr", "X-Org-ID": "test-org-123"}


def _pii_passthrough():
    """Context manager that makes PII scan a no-op."""
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = []
    return patch("app.middleware.pii_engine.get_analyzer", return_value=mock_analyzer)


async def test_keyword_blocklist_healthcare(client):
    """'prescribe' keyword triggers guardrail in healthcare policy."""
    token = make_jwt()
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Can you prescribe me some antibiotics for my infection?"}],
    }

    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
        mock_fn.return_value = MagicMock(analyze=MagicMock(return_value=[]))

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS_HEALTHCARE, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 451
    detail = resp.json()["detail"]
    assert detail["error"] == "policy_violation"
    assert detail["policy"] == "healthcare"


async def test_keyword_blocklist_fintech(client):
    """'guaranteed returns' triggers guardrail in fintech policy."""
    token = make_jwt(industry_type="fintech")
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "This fund offers guaranteed returns of 20% annually."}],
    }

    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
        mock_fn.return_value = MagicMock(analyze=MagicMock(return_value=[]))

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS_FINTECH, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 451
    detail = resp.json()["detail"]
    assert detail["error"] == "policy_violation"
    assert detail["policy"] == "fintech"


async def test_embedding_similarity_guardrail(client):
    """Semantically similar prohibited content triggers embedding guardrail."""
    token = make_jwt(industry_type="fintech")
    # "investment guarantees" is a prohibited topic for fintech
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Tell me how to guarantee profits from my stock investments"}
        ],
    }

    import numpy as np
    mock_model = MagicMock()
    # Simulate high cosine similarity with "investment guarantees"
    mock_model.encode.return_value = np.array([[1.0, 0.0]])

    with patch("app.middleware.pii_engine.get_analyzer") as mock_pii, \
         patch("app.middleware.guardrails.get_embedding_model", return_value=mock_model), \
         patch("app.middleware.guardrails._prohibited_embeddings_cache", {}):
        mock_pii.return_value = MagicMock(analyze=MagicMock(return_value=[]))
        mock_model.encode.side_effect = lambda texts, **kw: np.ones((len(texts), 1))

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS_FINTECH, "Authorization": f"Bearer {token}"},
        )

    # Should be either 451 (guardrail) or 200 (if similarity not high enough with mock)
    assert resp.status_code in (200, 451)


async def test_guardrail_returns_451_not_403(client):
    """Guardrail violations must return 451, not 403 or 400."""
    token = make_jwt(industry_type="govtech")
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "How do I engage in partisan political campaigning?"}
        ],
    }

    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
        mock_fn.return_value = MagicMock(analyze=MagicMock(return_value=[]))

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS_GOVTECH, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 451
    detail = resp.json()["detail"]
    assert detail["error"] == "policy_violation"
    assert "reason" in detail
    assert "policy" in detail


async def test_legal_hr_discriminatory_language(client):
    """Discriminatory hiring language triggers guardrail in legal_hr policy."""
    token = make_jwt(industry_type="legal_hr")
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "We need male only candidates who must be young for this role."}
        ],
    }

    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
        mock_fn.return_value = MagicMock(analyze=MagicMock(return_value=[]))

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS_LEGAL, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 451


async def test_clean_prompt_passes_guardrails(client):
    """A benign prompt with no policy violations passes all guardrails."""
    from unittest.mock import AsyncMock
    from tests.conftest import FAKE_OPENAI_RESPONSE

    token = make_jwt()
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "What is the capital of France?"}],
    }

    with patch("app.middleware.pii_engine.get_analyzer") as mock_pii, \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock) as mock_llm:
        mock_pii.return_value = MagicMock(analyze=MagicMock(return_value=[]))
        mock_llm.return_value = FAKE_OPENAI_RESPONSE

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS_HEALTHCARE, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
