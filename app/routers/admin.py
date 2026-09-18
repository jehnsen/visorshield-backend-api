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
from app.models.identity import Department, Group, User, UserGroupMembership
from app.models.inventory import AIProvider, AIModel, AIApp, BrowserInstallation
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


class CreateDepartmentRequest(BaseModel):
    org_id: str
    name: str


class CreateGroupRequest(BaseModel):
    org_id: str
    name: str


class UpdateUserRequest(BaseModel):
    department_id: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_active: Optional[bool] = None


class SetSanctionRequest(BaseModel):
    is_sanctioned: bool


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


# ── Identity: departments, groups, users ───────────────────────────────────
# Users themselves are auto-provisioned from X-VisorShield-User (see
# app/services/identity_service.py) — these endpoints are for curating them
# (assigning a department/groups) and for the "who is using AI" rollup that
# was previously unanswerable.

@router.post("/departments", status_code=201)
async def create_department(
    body: CreateDepartmentRequest,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    dept = Department(org_id=uuid.UUID(body.org_id), name=body.name)
    db.add(dept)
    await db.flush()
    await db.refresh(dept)
    return {"id": str(dept.id), "org_id": str(dept.org_id), "name": dept.name}


@router.get("/departments")
async def list_departments(
    org_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    result = await db.execute(select(Department).where(Department.org_id == uuid.UUID(org_id)))
    return {"items": [{"id": str(d.id), "org_id": str(d.org_id), "name": d.name} for d in result.scalars().all()]}


@router.post("/groups", status_code=201)
async def create_group(
    body: CreateGroupRequest,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    group = Group(org_id=uuid.UUID(body.org_id), name=body.name)
    db.add(group)
    await db.flush()
    await db.refresh(group)
    return {"id": str(group.id), "org_id": str(group.org_id), "name": group.name}


@router.get("/groups")
async def list_groups(
    org_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    result = await db.execute(select(Group).where(Group.org_id == uuid.UUID(org_id)))
    return {"items": [{"id": str(g.id), "org_id": str(g.org_id), "name": g.name} for g in result.scalars().all()]}


@router.post("/groups/{group_id}/members/{user_id}", status_code=201)
async def add_group_member(
    group_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    group_uuid, user_uuid = uuid.UUID(group_id), uuid.UUID(user_id)
    existing = await db.execute(
        select(UserGroupMembership).where(
            and_(UserGroupMembership.group_id == group_uuid, UserGroupMembership.user_id == user_uuid)
        )
    )
    if existing.scalar_one_or_none() is None:
        db.add(UserGroupMembership(group_id=group_uuid, user_id=user_uuid))
        await db.flush()
    return {"group_id": group_id, "user_id": user_id}


@router.get("/users")
async def list_users(
    org_id: str = Query(...),
    department_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    """
    The rollup that answers "who is using AI here" — every caller identity
    auto-provisioned from X-VisorShield-User, with whatever department an
    admin has assigned so far.
    """
    filters = [User.org_id == uuid.UUID(org_id)]
    if department_id:
        filters.append(User.department_id == uuid.UUID(department_id))

    total = (await db.execute(select(func.count(User.id)).where(and_(*filters)))).scalar()
    result = await db.execute(
        select(User)
        .where(and_(*filters))
        .order_by(User.last_seen_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    users = result.scalars().all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": str(u.id),
                "org_id": str(u.org_id),
                "external_id": u.external_id,
                "email": u.email,
                "display_name": u.display_name,
                "department_id": str(u.department_id) if u.department_id else None,
                "is_active": u.is_active,
                "first_seen_at": u.first_seen_at.isoformat() if u.first_seen_at else None,
                "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
            }
            for u in users
        ],
    }


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_admin()),
):
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail={"error": "user_not_found"})

    changed = {}
    if body.department_id is not None:
        user.department_id = uuid.UUID(body.department_id) if body.department_id else None
        changed["department_id"] = body.department_id
    if body.email is not None:
        user.email = body.email
        changed["email"] = body.email
    if body.display_name is not None:
        user.display_name = body.display_name
        changed["display_name"] = body.display_name
    if body.is_active is not None:
        user.is_active = body.is_active
        changed["is_active"] = body.is_active

    await db.flush()
    log.info("admin_user_updated", user_id=user_id, changed=list(changed.keys()),
              admin=claims.get("sub"), pipeline_step="admin")
    return {"id": user_id, "updated": changed}


# ── AI inventory: providers, models, apps, browser installations ──────────
# Rows here are auto-discovered from observed traffic (see
# app/services/inventory_service.py) — these endpoints list and sanction
# what's been found, they don't hand-enter the catalog.

@router.get("/inventory/providers")
async def list_providers(
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    result = await db.execute(select(AIProvider).order_by(AIProvider.name))
    return {
        "items": [
            {"id": str(p.id), "name": p.name, "last_seen_at": p.last_seen_at.isoformat() if p.last_seen_at else None}
            for p in result.scalars().all()
        ]
    }


@router.get("/inventory/models")
async def list_models(
    provider_id: Optional[str] = Query(None),
    is_sanctioned: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    filters = []
    if provider_id:
        filters.append(AIModel.provider_id == uuid.UUID(provider_id))
    if is_sanctioned is not None:
        filters.append(AIModel.is_sanctioned == is_sanctioned)

    q = select(AIModel).order_by(AIModel.name)
    if filters:
        q = q.where(and_(*filters))
    result = await db.execute(q)
    return {
        "items": [
            {
                "id": str(m.id),
                "provider_id": str(m.provider_id),
                "name": m.name,
                "is_sanctioned": m.is_sanctioned,
                "first_seen_at": m.first_seen_at.isoformat() if m.first_seen_at else None,
                "last_seen_at": m.last_seen_at.isoformat() if m.last_seen_at else None,
            }
            for m in result.scalars().all()
        ]
    }


@router.patch("/inventory/models/{model_id}")
async def set_model_sanctioned(
    model_id: str,
    body: SetSanctionRequest,
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_admin()),
):
    result = await db.execute(select(AIModel).where(AIModel.id == uuid.UUID(model_id)))
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail={"error": "model_not_found"})
    model.is_sanctioned = body.is_sanctioned
    await db.flush()
    log.warning("admin_model_sanction_changed", model_id=model_id, is_sanctioned=body.is_sanctioned,
                admin=claims.get("sub"), pipeline_step="admin")
    return {"id": model_id, "is_sanctioned": body.is_sanctioned}


@router.get("/inventory/apps")
async def list_apps(
    org_id: str = Query(...),
    is_sanctioned: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    filters = [AIApp.org_id == uuid.UUID(org_id)]
    if is_sanctioned is not None:
        filters.append(AIApp.is_sanctioned == is_sanctioned)
    result = await db.execute(select(AIApp).where(and_(*filters)).order_by(AIApp.app_source))
    return {
        "items": [
            {
                "id": str(a.id),
                "org_id": str(a.org_id),
                "app_source": a.app_source,
                "category": a.category,
                "is_sanctioned": a.is_sanctioned,
                "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
                "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            }
            for a in result.scalars().all()
        ]
    }


@router.patch("/inventory/apps/{app_id}")
async def set_app_sanctioned(
    app_id: str,
    body: SetSanctionRequest,
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_admin()),
):
    """Flip an app's sanctioned status — the "shadow AI" control surface."""
    result = await db.execute(select(AIApp).where(AIApp.id == uuid.UUID(app_id)))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail={"error": "app_not_found"})
    app.is_sanctioned = body.is_sanctioned
    await db.flush()
    log.warning("admin_app_sanction_changed", app_id=app_id, is_sanctioned=body.is_sanctioned,
                admin=claims.get("sub"), pipeline_step="admin")
    return {"id": app_id, "is_sanctioned": body.is_sanctioned}


@router.get("/inventory/devices")
async def list_devices(
    org_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_admin()),
):
    result = await db.execute(
        select(BrowserInstallation).where(BrowserInstallation.org_id == uuid.UUID(org_id))
        .order_by(BrowserInstallation.last_seen_at.desc())
    )
    return {
        "items": [
            {
                "id": str(d.id),
                "org_id": str(d.org_id),
                "device_id": d.device_id,
                "user_id": str(d.user_id) if d.user_id else None,
                "extension_version": d.extension_version,
                "first_seen_at": d.first_seen_at.isoformat() if d.first_seen_at else None,
                "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
            }
            for d in result.scalars().all()
        ]
    }
