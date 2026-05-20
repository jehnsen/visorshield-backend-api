import pytest
import time
import jwt
from unittest.mock import patch, AsyncMock
from tests.conftest import make_jwt, FAKE_OPENAI_RESPONSE
from app.config import settings

pytestmark = pytest.mark.asyncio


CHAT_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello, world!"}],
}

HEALTHCARE_HEADERS = {
    "X-Industry-Type": "healthcare",
    "X-Org-ID": "test-org-123",
}


@pytest.fixture
def mock_llm():
    with patch("app.services.llm_router._try_provider", new_callable=AsyncMock) as mock:
        mock.return_value = FAKE_OPENAI_RESPONSE
        yield mock


async def test_happy_path(client, valid_token, mock_llm):
    """Full happy path: valid JWT, no PII, no guardrail hit."""
    with patch("app.middleware.pii_engine.get_analyzer") as mock_analyzer_fn:
        mock_analyzer = mock_analyzer_fn.return_value
        mock_analyzer.analyze.return_value = []

        resp = await client.post(
            "/v1/chat/completions",
            json=CHAT_PAYLOAD,
            headers={
                **HEALTHCARE_HEADERS,
                "Authorization": f"Bearer {valid_token}",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "choices" in data
    assert data["choices"][0]["message"]["role"] == "assistant"
    assert "X-VisorShield-Request-ID" in resp.headers


async def test_missing_auth(client):
    """Request without Authorization header returns 401."""
    resp = await client.post("/v1/chat/completions", json=CHAT_PAYLOAD)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "missing_or_invalid_token"


async def test_model_not_permitted(client):
    """JWT allows only gpt-4o-mini; requesting gpt-4o returns 403."""
    token = make_jwt(allowed_models=["gpt-4o-mini"])
    payload = {**CHAT_PAYLOAD, "model": "gpt-4o"}

    with patch("app.middleware.pii_engine.get_analyzer") as mock_analyzer_fn:
        mock_analyzer = mock_analyzer_fn.return_value
        mock_analyzer.analyze.return_value = []

        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={
                **HEALTHCARE_HEADERS,
                "Authorization": f"Bearer {token}",
            },
        )

    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "model_not_permitted"


async def test_quota_exceeded(client, valid_token, fake_redis):
    """Monthly token quota exhausted returns 429 with reset_date."""
    import datetime
    from calendar import monthrange
    now = datetime.datetime.now(datetime.timezone.utc)
    monthly_key = f"visorshield:test-org-123:default:monthly_tokens:{now.year}:{now.month}"
    await fake_redis.set(monthly_key, 10_000_000)  # exceed 1M budget

    resp = await client.post(
        "/v1/chat/completions",
        json=CHAT_PAYLOAD,
        headers={**HEALTHCARE_HEADERS, "Authorization": f"Bearer {valid_token}"},
    )

    assert resp.status_code == 429
    detail = resp.json()["detail"]
    assert detail["error"] == "quota_exceeded"
    assert "reset_date" in detail


async def test_invalid_jwt(client):
    """Tampered JWT returns 401."""
    resp = await client.post(
        "/v1/chat/completions",
        json=CHAT_PAYLOAD,
        headers={**HEALTHCARE_HEADERS, "Authorization": "Bearer tampered.jwt.token"},
    )
    assert resp.status_code == 401


async def test_health_endpoint(client):
    """Health endpoint returns service status."""
    with patch("app.main.check_db_health", new_callable=AsyncMock, return_value=True), \
         patch("app.main.get_redis") as mock_redis_fn:
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis_fn.return_value = mock_redis

        resp = await client.get("/health")

    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "status" in data
    assert "services" in data
