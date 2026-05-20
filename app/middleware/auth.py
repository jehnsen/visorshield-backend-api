import time
import uuid as _uuid_mod
import jwt
import structlog
from fastapi import Request, HTTPException
from sqlalchemy import select, and_
from app.config import settings
from app.db.database import AsyncSessionLocal

log = structlog.get_logger()


async def _validate_api_key_active(sub: str, org_id: str) -> None:
    """
    Verify that the API key (sub) and org are both active in the database.
    Raises 401/403 on revoked or deactivated entries.
    """
    try:
        from app.models.audit import APIKey, Organization
        api_key_uuid = _uuid_mod.UUID(sub)
        org_uuid = _uuid_mod.UUID(org_id)
    except (ValueError, AttributeError):
        # Malformed UUIDs — let auth proceed without DB check rather than crashing
        return

    try:
        async with AsyncSessionLocal() as session:
            # Check org is active
            org_result = await session.execute(
                select(Organization.is_active).where(Organization.id == org_uuid)
            )
            org_row = org_result.scalar_one_or_none()
            if org_row is None:
                raise HTTPException(status_code=401, detail={"error": "organization_not_found"})
            if not org_row:
                raise HTTPException(status_code=403, detail={"error": "organization_deactivated"})

            # Check API key is active
            key_result = await session.execute(
                select(APIKey.is_active).where(
                    and_(APIKey.id == api_key_uuid, APIKey.org_id == org_uuid)
                )
            )
            key_row = key_result.scalar_one_or_none()
            if key_row is None:
                raise HTTPException(status_code=401, detail={"error": "api_key_not_found"})
            if not key_row:
                raise HTTPException(status_code=401, detail={"error": "api_key_revoked"})
    except HTTPException:
        raise
    except Exception as exc:
        # DB down — allow through (fail-open on auth DB check to avoid full outage)
        log.warning(
            "auth_db_check_failed",
            error=str(exc),
            pipeline_step="auth",
        )


async def auth_middleware(request: Request) -> dict:
    """Validates Bearer JWT, checks org/key active status, enforces model ACL."""
    start = time.monotonic()

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": "missing_or_invalid_token"})

    token = auth_header[len("Bearer "):].strip()
    if not token:
        raise HTTPException(status_code=401, detail={"error": "missing_or_invalid_token"})

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"error": "token_expired"})
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail={"error": "invalid_token", "message": str(exc)})

    org_id = payload.get("org_id")
    sub = payload.get("sub", "")
    app_source = payload.get("app_source", "unknown")
    allowed_models = payload.get("allowed_models", [])
    role = payload.get("role", "user")
    rpm_limit = int(payload.get("rpm_limit", 60))
    monthly_token_budget = int(payload.get("monthly_token_budget", 1_000_000))

    if not org_id:
        raise HTTPException(status_code=401, detail={"error": "missing_org_id_in_token"})

    # Verify the org and API key are still active in the database
    await _validate_api_key_active(sub, org_id)

    # Model access control — only checked when a parsed body is already on state
    body = getattr(request.state, "parsed_body", None)
    if body and hasattr(body, "model"):
        requested_model = body.model
        if allowed_models and requested_model not in allowed_models:
            log.warning(
                "model_not_permitted",
                org_id=org_id,
                requested_model=requested_model,
                allowed_models=allowed_models,
                request_id=getattr(request.state, "request_id", None),
                pipeline_step="auth",
            )
            raise HTTPException(
                status_code=403,
                detail={"error": "model_not_permitted", "model": requested_model, "allowed": allowed_models},
            )

    claims = {
        "org_id": org_id,
        "app_source": app_source,
        "allowed_models": allowed_models,
        "role": role,
        "rpm_limit": rpm_limit,
        "monthly_token_budget": monthly_token_budget,
        "sub": sub,
    }

    elapsed = (time.monotonic() - start) * 1000
    request.state.pipeline_timing["auth"] = elapsed
    request.state.jwt_claims = claims

    log.info(
        "auth_passed",
        org_id=org_id,
        app_source=app_source,
        request_id=getattr(request.state, "request_id", None),
        pipeline_step="auth",
        elapsed_ms=round(elapsed, 2),
    )

    return claims
