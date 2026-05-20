import pytest
import time
import jwt
from tests.conftest import make_jwt
from app.config import settings

pytestmark = pytest.mark.asyncio

BASIC_PAYLOAD = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
HEADERS = {"X-Industry-Type": "healthcare"}


async def test_valid_jwt_passes(client, valid_token):
    """Valid JWT allows request to proceed past auth layer."""
    from unittest.mock import patch, AsyncMock, MagicMock
    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn, \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock) as mock_llm:
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = []
        mock_fn.return_value = mock_analyzer
        from tests.conftest import FAKE_OPENAI_RESPONSE
        mock_llm.return_value = FAKE_OPENAI_RESPONSE

        resp = await client.post(
            "/v1/chat/completions",
            json=BASIC_PAYLOAD,
            headers={**HEADERS, "Authorization": f"Bearer {valid_token}"},
        )

    assert resp.status_code == 200


async def test_missing_bearer_returns_401(client):
    resp = await client.post(
        "/v1/chat/completions",
        json=BASIC_PAYLOAD,
        headers={**HEADERS},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "missing_or_invalid_token"


async def test_invalid_signature_returns_401(client):
    bad_token = jwt.encode(
        {"sub": "x", "org_id": "org1", "exp": int(time.time()) + 3600},
        "wrong-secret",
        algorithm="HS256",
    )
    resp = await client.post(
        "/v1/chat/completions",
        json=BASIC_PAYLOAD,
        headers={**HEADERS, "Authorization": f"Bearer {bad_token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "invalid_token"


async def test_expired_token_returns_401(client):
    expired_token = make_jwt(expire_offset=-100)
    resp = await client.post(
        "/v1/chat/completions",
        json=BASIC_PAYLOAD,
        headers={**HEADERS, "Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "token_expired"


async def test_model_access_control_forbidden(client):
    """JWT with restricted allowed_models blocks disallowed model."""
    token = make_jwt(allowed_models=["gpt-4o-mini"])
    payload = {**BASIC_PAYLOAD, "model": "gpt-4o"}

    from unittest.mock import patch, MagicMock
    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn:
        mock_fn.return_value = MagicMock(analyze=MagicMock(return_value=[]))
        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["error"] == "model_not_permitted"
    assert "gpt-4o" == detail["model"]


async def test_empty_allowed_models_permits_all(client):
    """Empty allowed_models list means no restriction."""
    token = make_jwt(allowed_models=[])

    from unittest.mock import patch, AsyncMock, MagicMock
    with patch("app.middleware.pii_engine.get_analyzer") as mock_fn, \
         patch("app.services.llm_router._try_provider", new_callable=AsyncMock) as mock_llm:
        mock_fn.return_value = MagicMock(analyze=MagicMock(return_value=[]))
        from tests.conftest import FAKE_OPENAI_RESPONSE
        mock_llm.return_value = FAKE_OPENAI_RESPONSE

        resp = await client.post(
            "/v1/chat/completions",
            json=BASIC_PAYLOAD,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200


async def test_missing_org_id_returns_401(client):
    """JWT without org_id claim is rejected."""
    token = jwt.encode(
        {"sub": "user", "exp": int(time.time()) + 3600, "role": "user"},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    resp = await client.post(
        "/v1/chat/completions",
        json=BASIC_PAYLOAD,
        headers={**HEADERS, "Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "missing_org_id_in_token"
