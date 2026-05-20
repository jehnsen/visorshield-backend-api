import uuid
import secrets
import structlog
import bcrypt
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, delete, update
from app.db.database import get_db
from app.dependencies import require_admin
from app.models.audit import Organization, APIKey, Transaction
from app.models.embeddings import PolicyEmbedding
from app.services.report_service import generate_monthly_summary
from app.middleware.guardrails import invalidate_embedding_cache

log = structlog.get_logger()
router = APIRouter(prefix="/admin", tags=["admin"])

_VALID_INDUSTRY_TYPES = {"healthcare", "fintech", "govtech", "legal_hr"}


class CreateOrgRequest(BaseModel):
    name: str
    industry_type: str
    monthly_token_budget: int = Field(default=1_000_000, gt=0)
    requests_per_second_limit: int = Field(default=10, gt=0, le=10_000)
    allowed_models: list[str] = ["gpt-4o-mini"]


class UpdateOrgRequest(BaseModel):
    name: Optional[str] = None
    industry_type: Optional[str] = None
    monthly_token_budget: Optional[int] = Field(default=None, gt=0)
    requests_per_second_limit: Optional[int] = Field(default=None, gt=0, le=10_000)
    allowed_models: Optional[List[str]] = None


class CreateAPIKeyRequest(BaseModel):
    org_id: str
    label: Optional[str] = None


class UpsertEmbeddingsRequest(BaseModel):
    policy_profile: str
    topics: List[str]


@router.post("/organizations", status_code=201)
async def create_organization(
    body: CreateOrgRequest,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    if body.industry_type not in _VALID_INDUSTRY_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_industry_type", "valid": sorted(_VALID_INDUSTRY_TYPES)},
        )

    org = Organization(
        name=body.name,
        industry_type=body.industry_type,
        monthly_token_budget=body.monthly_token_budget,
        requests_per_second_limit=body.requests_per_second_limit,
        allowed_models=body.allowed_models,
    )
    db.add(org)
    await db.flush()
    await db.refresh(org)

    return {
        "id": str(org.id),
        "name": org.name,
        "industry_type": org.industry_type,
        "monthly_token_budget": org.monthly_token_budget,
        "requests_per_second_limit": org.requests_per_second_limit,
        "allowed_models": org.allowed_models,
        "is_active": org.is_active,
        "created_at": org.created_at.isoformat() if org.created_at else None,
    }


@router.patch("/organizations/{org_id}")
async def update_organization(
    org_id: str,
    body: UpdateOrgRequest,
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_admin()),
):
    """Update mutable org fields. Partial update — only provided fields are changed."""
    try:
        org_uuid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"error": "invalid_org_id"})

    result = await db.execute(select(Organization).where(Organization.id == org_uuid))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail={"error": "organization_not_found"})

    changed = {}
    if body.name is not None:
        org.name = body.name
        changed["name"] = body.name
    if body.industry_type is not None:
        if body.industry_type not in _VALID_INDUSTRY_TYPES:
            raise HTTPException(
                status_code=422,
                detail={"error": "invalid_industry_type", "valid": sorted(_VALID_INDUSTRY_TYPES)},
            )
        org.industry_type = body.industry_type
        changed["industry_type"] = body.industry_type
    if body.monthly_token_budget is not None:
        org.monthly_token_budget = body.monthly_token_budget
        changed["monthly_token_budget"] = body.monthly_token_budget
    if body.requests_per_second_limit is not None:
        org.requests_per_second_limit = body.requests_per_second_limit
        changed["requests_per_second_limit"] = body.requests_per_second_limit
    if body.allowed_models is not None:
        org.allowed_models = body.allowed_models
        changed["allowed_models"] = body.allowed_models

    await db.flush()
    log.info("admin_org_updated", org_id=org_id, changed=list(changed.keys()),
             admin=claims.get("sub"), pipeline_step="admin")
    return {"id": org_id, "updated": changed}


@router.delete("/organizations/{org_id}", status_code=200)
async def deactivate_organization(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_admin()),
):
    """Soft-delete an organization. Sets is_active=False and revokes all its API keys."""
    try:
        org_uuid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"error": "invalid_org_id"})

    result = await db.execute(select(Organization).where(Organization.id == org_uuid))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail={"error": "organization_not_found"})
    if not org.is_active:
        raise HTTPException(status_code=409, detail={"error": "organization_already_deactivated"})

    org.is_active = False
    # Revoke all API keys for this org
    await db.execute(
        update(APIKey).where(APIKey.org_id == org_uuid).values(is_active=False)
    )
    await db.flush()
    log.warning("admin_org_deactivated", org_id=org_id, admin=claims.get("sub"), pipeline_step="admin")
    return {"id": org_id, "is_active": False, "api_keys_revoked": True}


@router.delete("/api-keys/{key_id}", status_code=200)
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_admin()),
):
    """Revoke a single API key by ID."""
    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"error": "invalid_key_id"})

    result = await db.execute(select(APIKey).where(APIKey.id == key_uuid))
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail={"error": "api_key_not_found"})
    if not key.is_active:
        raise HTTPException(status_code=409, detail={"error": "api_key_already_revoked"})

    key.is_active = False
    await db.flush()
    log.warning("admin_key_revoked", key_id=key_id, org_id=str(key.org_id),
                admin=claims.get("sub"), pipeline_step="admin")
    return {"id": key_id, "is_active": False}


@router.post("/api-keys", status_code=201)
async def create_api_key(
    body: CreateAPIKeyRequest,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    org_result = await db.execute(
        select(Organization).where(
            and_(Organization.id == uuid.UUID(body.org_id), Organization.is_active == True)
        )
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail={"error": "organization_not_found"})

    raw_key = f"vs_{secrets.token_urlsafe(32)}"
    key_hash = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    api_key = APIKey(
        org_id=uuid.UUID(body.org_id),
        key_hash=key_hash,
        label=body.label,
    )
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    return {
        "id": str(api_key.id),
        "org_id": str(api_key.org_id),
        "label": api_key.label,
        "key": raw_key,
        "note": "Store this key securely. It will not be shown again.",
        "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
    }


@router.get("/organizations/{org_id}/usage")
async def get_org_usage(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    org_result = await db.execute(
        select(Organization).where(Organization.id == uuid.UUID(org_id))
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail={"error": "organization_not_found"})

    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)

    usage_result = await db.execute(
        select(
            func.coalesce(func.sum(Transaction.input_tokens), 0).label("input_tokens"),
            func.coalesce(func.sum(Transaction.output_tokens), 0).label("output_tokens"),
            func.coalesce(func.sum(Transaction.cost_usd), 0).label("cost_usd"),
            func.count(Transaction.id).label("request_count"),
        ).where(
            and_(
                Transaction.org_id == uuid.UUID(org_id),
                Transaction.created_at >= month_start,
            )
        )
    )
    row = usage_result.one()
    total_tokens = int(row.input_tokens) + int(row.output_tokens)

    return {
        "org_id": org_id,
        "org_name": org.name,
        "period": f"{now.year}-{now.month:02d}",
        "monthly_token_budget": org.monthly_token_budget,
        "tokens_used": total_tokens,
        "tokens_remaining": max(0, org.monthly_token_budget - total_tokens),
        "budget_used_pct": round((total_tokens / max(1, org.monthly_token_budget)) * 100, 2),
        "cost_usd": float(row.cost_usd),
        "request_count": row.request_count,
    }


@router.post("/organizations/{org_id}/policy-embeddings", status_code=200)
async def upsert_policy_embeddings(
    org_id: str,
    body: UpsertEmbeddingsRequest,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    """
    Compute and store pgvector embeddings for a list of prohibited topics for a specific org.
    These override the default in-process embeddings for Layer 2 guardrail checks.
    """
    org_result = await db.execute(
        select(Organization).where(
            and_(Organization.id == uuid.UUID(org_id), Organization.is_active == True)
        )
    )
    if not org_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail={"error": "organization_not_found"})

    valid_profiles = {"healthcare", "fintech", "govtech", "legal_hr"}
    if body.policy_profile not in valid_profiles:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_policy_profile", "valid": list(valid_profiles)},
        )
    if not body.topics:
        raise HTTPException(status_code=422, detail={"error": "topics_must_not_be_empty"})

    from app.middleware.guardrails import get_embedding_model
    import asyncio

    loop = asyncio.get_event_loop()
    model = get_embedding_model()
    embeddings = await loop.run_in_executor(
        None, lambda: model.encode(body.topics, normalize_embeddings=True)
    )

    org_uuid = uuid.UUID(org_id)
    for topic, emb in zip(body.topics, embeddings):
        existing = await db.execute(
            select(PolicyEmbedding).where(
                and_(
                    PolicyEmbedding.org_id == org_uuid,
                    PolicyEmbedding.policy_profile == body.policy_profile,
                    PolicyEmbedding.topic == topic,
                )
            )
        )
        row = existing.scalar_one_or_none()
        if row:
            row.embedding = emb.tolist()
            row.updated_at = datetime.now(timezone.utc)
        else:
            db.add(
                PolicyEmbedding(
                    org_id=org_uuid,
                    policy_profile=body.policy_profile,
                    topic=topic,
                    embedding=emb.tolist(),
                )
            )

    await db.flush()
    invalidate_embedding_cache(org_id, body.policy_profile)

    return {
        "org_id": org_id,
        "policy_profile": body.policy_profile,
        "topics_upserted": len(body.topics),
        "note": "In-memory cache invalidated. New embeddings active on next request.",
    }


@router.get("/organizations/{org_id}/policy-embeddings")
async def list_policy_embeddings(
    org_id: str,
    policy_profile: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    """List all stored pgvector topic embeddings for an org (topics only, not vectors)."""
    filters = [PolicyEmbedding.org_id == uuid.UUID(org_id)]
    if policy_profile:
        filters.append(PolicyEmbedding.policy_profile == policy_profile)

    result = await db.execute(
        select(PolicyEmbedding.id, PolicyEmbedding.policy_profile, PolicyEmbedding.topic, PolicyEmbedding.updated_at)
        .where(and_(*filters))
        .order_by(PolicyEmbedding.policy_profile, PolicyEmbedding.topic)
    )
    rows = result.all()

    return {
        "org_id": org_id,
        "count": len(rows),
        "items": [
            {
                "id": str(r.id),
                "policy_profile": r.policy_profile,
                "topic": r.topic,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rows
        ],
    }


@router.delete("/organizations/{org_id}/policy-embeddings/{policy_profile}", status_code=204)
async def delete_policy_embeddings(
    org_id: str,
    policy_profile: str,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    """Delete all custom embeddings for an org+profile, reverting to default in-process embeddings."""
    await db.execute(
        delete(PolicyEmbedding).where(
            and_(
                PolicyEmbedding.org_id == uuid.UUID(org_id),
                PolicyEmbedding.policy_profile == policy_profile,
            )
        )
    )
    invalidate_embedding_cache(org_id, policy_profile)


@router.post("/reports/monthly")
async def monthly_report(
    org_id: Optional[str] = Query(None),
    year: Optional[int] = Query(None),
    month: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    summary = await generate_monthly_summary(db, org_id=org_id, year=year, month=month)
    return summary
