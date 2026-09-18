import time
import uuid as _uuid_mod
import jwt
import structlog
from fastapi import Request, HTTPException
from sqlalchemy import select, and_
from app.config import settings
from app.db.database import AsyncSessionLocal

log = structlog.get_logger()


async def _validate_api_key_active(sub: str, org_id: str) -> dict:
    """
    Verify that the API key (sub) and org are both active in the database, and
    return the org's admin-configurable limits (monthly_token_budget,
    requests_per_second_limit, allowed_models).

    These DB values are the source of truth and take precedence over the JWT's
    own copies of the same fields in auth_middleware — otherwise a budget or
    model-list change made via PATCH /admin/organizations/{id} would have no
    effect until every outstanding token expired and was reminted. Returns {}
    only when the DB check itself was skipped (malformed UUIDs) or explicitly
    allowed to fail open; callers must not treat an empty dict as "no limits".

    Raises 401/403 on revoked or deactivated entries.

    Fail-closed by default: if the DB is unreachable, the request is BLOCKED
    (503) rather than silently treated as passing — an outage must never look
    like a valid, unlimited key. Set AUTH_FAIL_OPEN_ON_DB_ERROR to opt back
    into the old fail-open behavior outside production.
    """
    try:
        from app.models.audit import APIKey, Organization
        api_key_uuid = _uuid_mod.UUID(sub)
        org_uuid = _uuid_mod.UUID(org_id)
    except (ValueError, AttributeError):
        # Malformed UUIDs — let auth proceed on JWT claims alone rather than crashing
        return {}

    try:
        async with AsyncSessionLocal() as session:
            # Check org is active and pull its current enforcement limits
            org_result = await session.execute(
                select(
                    Organization.is_active,
                    Organization.monthly_token_budget,
                    Organization.requests_per_second_limit,
                    Organization.allowed_models,
                ).where(Organization.id == org_uuid)
            )
            org_row = org_result.one_or_none()
            if org_row is None:
                raise HTTPException(status_code=401, detail={"error": "organization_not_found"})
            if not org_row.is_active:
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

        return {
            "monthly_token_budget": org_row.monthly_token_budget,
            "requests_per_second": org_row.requests_per_second_limit,
            "allowed_models": org_row.allowed_models,
        }
    except HTTPException:
        raise
    except Exception as exc:
        if settings.AUTH_FAIL_OPEN_ON_DB_ERROR:
            log.warning(
                "auth_db_check_failed_fail_open",
                error=str(exc),
                pipeline_step="auth",
            )
            return {}
        log.error(
            "auth_db_check_failed_fail_closed",
            error=str(exc),
            pipeline_step="auth",
        )
        raise HTTPException(status_code=503, detail={"error": "auth_db_unavailable"})


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
    role = payload.get("role", "user")
    # Opt-in only: when false (default) SSE responses are buffered and PII-scanned
    # before any byte reaches the client. See app/routers/proxy.py::_stream_response.
    allow_streaming_passthrough = bool(payload.get("allow_streaming_passthrough", False))

    if not org_id:
        raise HTTPException(status_code=401, detail={"error": "missing_org_id_in_token"})

    # industry_type is a required JWT claim (see CLAUDE.md JWT Claims Schema).
    # The X-Industry-Type header must match it exactly: a client sending a
    # header that differs from the org's own token claim would otherwise pick
    # a weaker PII entity list / blocklist than the org was actually issued —
    # a client-selectable policy downgrade, not just a formatting mismatch.
    industry_type = payload.get("industry_type")
    if not industry_type:
        raise HTTPException(status_code=401, detail={"error": "missing_industry_type_in_token"})

    header_industry_type = request.headers.get("X-Industry-Type", "").strip()
    if not header_industry_type:
        raise HTTPException(status_code=422, detail={"error": "missing_industry_type_header"})
    if header_industry_type != industry_type:
        log.warning(
            "industry_type_mismatch",
            org_id=org_id,
            token_industry_type=industry_type,
            header_industry_type=header_industry_type,
            request_id=getattr(request.state, "request_id", None),
            pipeline_step="auth",
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "industry_type_mismatch",
                "message": "X-Industry-Type header does not match the token's industry_type claim",
            },
        )

    # X-VisorShield-User identifies the human/service behind this call. A JWT
    # is issued per app/org, not per person, so without this header every
    # caller under a shared API key is indistinguishable — "who is using
    # which AI service" (FinOps, identity-aware policy) is unanswerable.
    # Required, like the other identifying headers above.
    external_user_id = request.headers.get("X-VisorShield-User", "").strip()
    if not external_user_id:
        raise HTTPException(status_code=422, detail={"error": "missing_visorshield_user_header"})

    from app.services.identity_service import get_or_create_user
    identity = await get_or_create_user(org_id, external_user_id)

    # Verify the org and API key are still active, and pull the org's current
    # admin-configured limits — these override the JWT's own copies below so
    # that changes made via /admin/organizations take effect immediately.
    db_state = await _validate_api_key_active(sub, org_id)

    allowed_models = (
        db_state["allowed_models"]
        if "allowed_models" in db_state and db_state["allowed_models"] is not None
        else payload.get("allowed_models", [])
    )
    requests_per_second = int(
        db_state["requests_per_second"]
        if "requests_per_second" in db_state and db_state["requests_per_second"] is not None
        else payload.get("requests_per_second", 10)
    )
    monthly_token_budget = int(
        db_state["monthly_token_budget"]
        if "monthly_token_budget" in db_state and db_state["monthly_token_budget"] is not None
        else payload.get("monthly_token_budget", 1_000_000)
    )

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
        "requests_per_second": requests_per_second,
        "monthly_token_budget": monthly_token_budget,
        "allow_streaming_passthrough": allow_streaming_passthrough,
        "industry_type": industry_type,
        "sub": sub,
        "external_user_id": external_user_id,
        "user_id": identity.get("id") if identity else None,
        "department_id": identity.get("department_id") if identity else None,
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
