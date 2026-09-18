import pytest
import jwt
import time
import fakeredis.aioredis
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings


def make_jwt(
    org_id="test-org-123",
    app_source="test-app",
    allowed_models=None,
    role="user",
    requests_per_second=100,
    monthly_token_budget=1_000_000,
    industry_type="healthcare",
    expire_offset=3600,
):
    if allowed_models is None:
        allowed_models = ["gpt-4o", "gpt-4o-mini", "claude-sonnet-4-5", "claude-haiku-4-5"]
    payload = {
        "sub": "user-abc",
        "org_id": org_id,
        "app_source": app_source,
        "allowed_models": allowed_models,
        "role": role,
        "requests_per_second": requests_per_second,
        "monthly_token_budget": monthly_token_budget,
        "industry_type": industry_type,
        "exp": int(time.time()) + expire_offset,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


FAKE_OPENAI_RESPONSE = {
    "id": "chatcmpl-test",
    "object": "chat.completion",
    "created": int(time.time()),
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Hello! How can I help you?"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
}


@pytest.fixture
def valid_token():
    return make_jwt()


@pytest.fixture
def admin_token():
    return make_jwt(role="admin")


@pytest.fixture
def compliance_token():
    return make_jwt(role="compliance_officer")


@pytest.fixture
def fake_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture(autouse=True)
def patch_redis(fake_redis):
    with patch("app.middleware.rate_limit._redis_client", fake_redis):
        yield fake_redis


@pytest.fixture(autouse=True)
def patch_db():
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    # Every module that opens its own AsyncSessionLocal() for fire-and-forget
    # writes (audit rows, identity/inventory auto-discovery upserts) needs the
    # same mock, or it falls through to a real DB connection attempt.
    with patch("app.services.audit_service.AsyncSessionLocal") as audit_factory, \
         patch("app.services.identity_service.AsyncSessionLocal") as identity_factory, \
         patch("app.services.inventory_service.AsyncSessionLocal") as inventory_factory:
        audit_factory.return_value = mock_session
        identity_factory.return_value = mock_session
        inventory_factory.return_value = mock_session
        yield mock_session


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
