import uuid
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from app.db.database import get_db
from app.dependencies import require_compliance_or_admin
from app.models.audit import Transaction, GuardrailIncident

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/transactions")
async def list_transactions(
    org_id: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    compliance_status: Optional[str] = Query(None),
    industry_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_compliance_or_admin()),
):
    filters = []
    if org_id:
        filters.append(Transaction.org_id == uuid.UUID(org_id))
    if date_from:
        filters.append(Transaction.created_at >= date_from)
    if date_to:
        filters.append(Transaction.created_at <= date_to)
    if compliance_status:
        filters.append(Transaction.compliance_status == compliance_status)
    if industry_type:
        filters.append(Transaction.industry_type == industry_type)

    offset = (page - 1) * page_size

    count_q = select(func.count(Transaction.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()

    q = select(Transaction).order_by(Transaction.created_at.desc()).offset(offset).limit(page_size)
    if filters:
        q = q.where(and_(*filters))

    result = await db.execute(q)
    transactions = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": str(tx.id),
                "org_id": str(tx.org_id),
                "app_source": tx.app_source,
                "model_requested": tx.model_requested,
                "model_used": tx.model_used,
                "provider": tx.provider,
                "prompt_hash": tx.prompt_hash,
                "pii_detected": tx.pii_detected,
                "response_pii_detected": tx.response_pii_detected,
                "input_tokens": tx.input_tokens,
                "output_tokens": tx.output_tokens,
                "cost_usd": float(tx.cost_usd) if tx.cost_usd else 0.0,
                "compliance_status": tx.compliance_status,
                "guardrail_triggered": tx.guardrail_triggered,
                "latency_ms": tx.latency_ms,
                "industry_type": tx.industry_type,
                "routing_reason": tx.routing_reason,
                "created_at": tx.created_at.isoformat() if tx.created_at else None,
            }
            for tx in transactions
        ],
    }


@router.get("/transactions/{transaction_id}")
async def get_transaction(
    transaction_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_compliance_or_admin()),
):
    result = await db.execute(select(Transaction).where(Transaction.id == transaction_id))
    tx = result.scalar_one_or_none()
    if not tx:
        raise HTTPException(status_code=404, detail={"error": "transaction_not_found"})

    return {
        "id": str(tx.id),
        "org_id": str(tx.org_id),
        "app_source": tx.app_source,
        "model_requested": tx.model_requested,
        "model_used": tx.model_used,
        "provider": tx.provider,
        "prompt_hash": tx.prompt_hash,
        "pii_detected": tx.pii_detected,
        "response_pii_detected": tx.response_pii_detected,
        "input_tokens": tx.input_tokens,
        "output_tokens": tx.output_tokens,
        "cost_usd": float(tx.cost_usd) if tx.cost_usd else 0.0,
        "compliance_status": tx.compliance_status,
        "guardrail_triggered": tx.guardrail_triggered,
        "latency_ms": tx.latency_ms,
        "industry_type": tx.industry_type,
        "routing_reason": tx.routing_reason,
        "created_at": tx.created_at.isoformat() if tx.created_at else None,
    }


@router.get("/incidents")
async def list_incidents(
    org_id: Optional[str] = Query(None),
    policy_profile: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_compliance_or_admin()),
):
    filters = []
    if org_id:
        filters.append(GuardrailIncident.org_id == uuid.UUID(org_id))
    if policy_profile:
        filters.append(GuardrailIncident.policy_profile == policy_profile)

    offset = (page - 1) * page_size
    count_q = select(func.count(GuardrailIncident.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()

    q = select(GuardrailIncident).order_by(GuardrailIncident.created_at.desc()).offset(offset).limit(page_size)
    if filters:
        q = q.where(and_(*filters))

    result = await db.execute(q)
    incidents = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": str(inc.id),
                "org_id": str(inc.org_id),
                "transaction_id": str(inc.transaction_id) if inc.transaction_id else None,
                "policy_profile": inc.policy_profile,
                "violation_category": inc.violation_category,
                "detection_layer": inc.detection_layer,
                "prompt_hash": inc.prompt_hash,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
            }
            for inc in incidents
        ],
    }


@router.get("/summary")
async def audit_summary(
    org_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _claims: dict = Depends(require_compliance_or_admin()),
):
    filters = []
    if org_id:
        filters.append(Transaction.org_id == uuid.UUID(org_id))

    tx_q = select(
        func.count(Transaction.id).label("total_requests"),
        func.coalesce(func.sum(Transaction.input_tokens), 0).label("total_input_tokens"),
        func.coalesce(func.sum(Transaction.output_tokens), 0).label("total_output_tokens"),
        func.coalesce(func.sum(Transaction.cost_usd), 0).label("total_cost_usd"),
        func.count(Transaction.id).filter(Transaction.compliance_status == "pass").label("compliant"),
    )
    if filters:
        tx_q = tx_q.where(and_(*filters))
    row = (await db.execute(tx_q)).one()

    # PII events
    pii_q = select(Transaction.pii_detected, Transaction.response_pii_detected)
    if filters:
        pii_q = pii_q.where(and_(*filters))
    pii_rows = (await db.execute(pii_q)).all()
    pii_events = sum(len(r.pii_detected or []) + len(r.response_pii_detected or []) for r in pii_rows)

    # Guardrail hits
    g_filters = []
    if org_id:
        g_filters.append(GuardrailIncident.org_id == uuid.UUID(org_id))
    g_q = select(func.count(GuardrailIncident.id))
    if g_filters:
        g_q = g_q.where(and_(*g_filters))
    guardrail_hits = (await db.execute(g_q)).scalar() or 0

    total = row.total_requests or 1
    return {
        "total_requests": row.total_requests,
        "total_tokens": int(row.total_input_tokens) + int(row.total_output_tokens),
        "total_cost_usd": float(row.total_cost_usd),
        "pii_events_prevented": pii_events,
        "guardrail_hits": guardrail_hits,
        "compliance_rate_pct": round((row.compliant / total) * 100, 2),
    }
