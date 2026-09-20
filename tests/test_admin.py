"""Admin router tests — org CRUD, API key lifecycle, policy embeddings."""
import pytest
import uuid
from unittest.mock import patch, AsyncMock, MagicMock
from tests.conftest import make_jwt, monthly_quota_key

pytestmark = pytest.mark.asyncio

ADMIN_TOKEN_FIXTURE = "admin_token"


def _admin_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Organization endpoints ─────────────────────────────────────────────────

async def test_create_org_success(client, admin_token):
    """
    get_db is overridden via app.dependency_overrides — patching the module
    attribute has no effect, because Depends(get_db) captured the original
    function when the route was defined (and the test then hit real Postgres).
    """
    from app.main import app
    from app.db.database import get_db
    from app.models.audit import Organization

    org_id = uuid.uuid4()
    session = MagicMock()
    session.flush = AsyncMock()

    async def _refresh(org):
        # Simulate the DB assigning server-side values on flush/refresh.
        org.id = org_id
        org.is_active = True

    session.refresh = AsyncMock(side_effect=_refresh)

    async def _override_get_db():
        yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
            resp = await client.post(
                "/admin/organizations",
                json={
                    "name": "Test Hospital",
                    "industry_type": "healthcare",
                    "monthly_token_budget": 500_000,
                },
                headers=_admin_headers(admin_token),
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == str(org_id)
    assert body["name"] == "Test Hospital"
    assert body["industry_type"] == "healthcare"
    assert body["monthly_token_budget"] == 500_000
    assert body["is_active"] is True

    added = session.add.call_args.args[0]
    assert isinstance(added, Organization)
    assert added.name == "Test Hospital"
    session.flush.assert_awaited_once()


async def test_create_org_invalid_industry_type(client, admin_token):
    with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        resp = await client.post(
            "/admin/organizations",
            json={"name": "Bad Org", "industry_type": "illegal_type"},
            headers=_admin_headers(admin_token),
        )
    assert resp.status_code in (401, 422)


async def test_create_org_requires_admin_role(client, valid_token):
    """Non-admin JWT should be rejected by admin endpoints."""
    with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        resp = await client.post(
            "/admin/organizations",
            json={"name": "X", "industry_type": "govtech"},
            headers=_admin_headers(valid_token),
        )
    # role=user does not have admin access
    assert resp.status_code in (401, 403)


# ── Quota exceeded ────────────────────────────────────────────────────────

async def test_quota_exceeded_response_format(client, valid_token, fake_redis):
    """Quota-exceeded 429 must include reset_date."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    monthly_key = monthly_quota_key()
    await fake_redis.set(monthly_key, 100_000_000)

    with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock):
        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            headers={
                "Authorization": f"Bearer {valid_token}",
                "X-Industry-Type": "healthcare",
                "X-VisorShield-User": "test-user-1",
            },
        )

    assert resp.status_code == 429
    detail = resp.json()["detail"]
    assert detail["error"] == "quota_exceeded"
    assert "reset_date" in detail


# ── API key revocation ────────────────────────────────────────────────────

async def test_revoked_api_key_is_rejected(client):
    """Token whose API key is marked inactive in DB must return 401."""
    from tests.conftest import make_jwt
    token = make_jwt()

    with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock) as mock_val:
        from fastapi import HTTPException
        mock_val.side_effect = HTTPException(status_code=401, detail={"error": "api_key_revoked"})

        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            headers={
                "Authorization": f"Bearer {token}",
                "X-Industry-Type": "healthcare",
                "X-VisorShield-User": "test-user-1",
            },
        )

    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "api_key_revoked"


async def test_deactivated_org_is_rejected(client):
    """Token whose org is deactivated must return 403."""
    token = make_jwt()

    with patch("app.middleware.auth._validate_api_key_active", new_callable=AsyncMock) as mock_val:
        from fastapi import HTTPException
        mock_val.side_effect = HTTPException(status_code=403, detail={"error": "organization_deactivated"})

        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            headers={
                "Authorization": f"Bearer {token}",
                "X-Industry-Type": "healthcare",
                "X-VisorShield-User": "test-user-1",
            },
        )

    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "organization_deactivated"
