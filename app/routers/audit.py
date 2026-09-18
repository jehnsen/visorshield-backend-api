import csv
import io
import json
import uuid
from datetime import datetime
from typing import Optional, List, Literal
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from app.db.database import get_db
from app.dependencies import require_compliance_or_admin
from app.models.audit import Transaction, GuardrailIncident
from app.services.audit_integrity import canonical_transaction_fields, recompute_record_hash

router = APIRouter(prefix="/audit", tags=["audit"])

_TRANSACTION_EXPORT_FIELDS = [
    "id", "org_id", "chain_seq", "prev_hash", "record_hash", "app_source",
    "model_requested", "model_used", "provider", "prompt_hash", "pii_detected",
    "response_pii_detected", "input_tokens", "output_tokens", "cost_usd",
    "compliance_status", "guardrail_triggered", "latency_ms", "industry_type",
    "routing_reason", "user_id", "external_user_id", "created_at",
]


def _tx_export_row(tx: Transaction) -> dict:
    return {
        "id": str(tx.id),
        "org_id": str(tx.org_id),
        "chain_seq": tx.chain_seq,
        "prev_hash": tx.prev_hash,
        "record_hash": tx.record_hash,
        "app_source": tx.app_source,
        "model_requested": tx.model_requested,
        "model_used": tx.model_used,
        "provider": tx.provider,
        "prompt_hash": tx.prompt_hash,
        "pii_detected": tx.pii_detected,
        "response_pii_detected": tx.response_pii_detected,
        "input_tokens": tx.input_tokens,
        "output_tokens": tx.output_tokens,
        "cost_usd": float(tx.cost_usd) if tx.cost_usd is not None else 0.0,
        "compliance_status": tx.compliance_status,
        "guardrail_triggered": tx.guardrail_triggered,
        "latency_ms": tx.latency_ms,
        "industry_type": tx.industry_type,
        "routing_reason": tx.routing_reason,
        "user_id": str(tx.user_id) if tx.user_id else None,
        "external_user_id": tx.external_user_id,
        "created_at": tx.created_at.isoformat() if tx.created_at else None,
    }


def _resolve_org_scope(claims: dict, requested_org_id: Optional[str]) -> Optional[uuid.UUID]:
    """
    Determine which org's records the caller is allowed to read.

    - role == "admin": may target any org via the ?org_id query param, or all
      orgs when it is omitted (returns None => no org filter).
    - role == "compliance_officer": always locked to the org_id in their token.
      Supplying a ?org_id for a different org is rejected with 403; omitting it
      simply scopes to their own org.

    The scope is derived from the verified JWT claims, never from a bare
    caller-supplied query param.
    """
    role = claims.get("role", "user")
    token_org = claims.get("org_id")

    requested_uuid: Optional[uuid.UUID] = None
    if requested_org_id:
        try:
            requested_uuid = uuid.UUID(requested_org_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=422, detail={"error": "invalid_org_id"})

    if role == "admin":
        return requested_uuid  # None => all orgs

    # compliance_officer — require_compliance_or_admin() already gated the role
    try:
        token_org_uuid = uuid.UUID(token_org)
    except (ValueError, TypeError):
        raise HTTPException(status_code=403, detail={"error": "org_scope_unavailable"})

    if requested_uuid is not None and requested_uuid != token_org_uuid:
        raise HTTPException(status_code=403, detail={"error": "org_scope_forbidden"})
    return token_org_uuid


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
    claims: dict = Depends(require_compliance_or_admin()),
):
    filters = []
    org_scope = _resolve_org_scope(claims, org_id)
    if org_scope is not None:
        filters.append(Transaction.org_id == org_scope)
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
    claims: dict = Depends(require_compliance_or_admin()),
):
    org_scope = _resolve_org_scope(claims, None)
    result = await db.execute(select(Transaction).where(Transaction.id == transaction_id))
    tx = result.scalar_one_or_none()
    # 404 (not 403) when out of scope so record existence isn't leaked cross-tenant
    if not tx or (org_scope is not None and tx.org_id != org_scope):
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
    claims: dict = Depends(require_compliance_or_admin()),
):
    filters = []
    org_scope = _resolve_org_scope(claims, org_id)
    if org_scope is not None:
        filters.append(GuardrailIncident.org_id == org_scope)
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
    claims: dict = Depends(require_compliance_or_admin()),
):
    org_scope = _resolve_org_scope(claims, org_id)
    filters = []
    if org_scope is not None:
        filters.append(Transaction.org_id == org_scope)

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
    if org_scope is not None:
        g_filters.append(GuardrailIncident.org_id == org_scope)
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


@router.get("/usage-by-user")
async def usage_by_user(
    org_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_compliance_or_admin()),
):
    """
    "Who is using which AI service" — cost/tokens/requests grouped by the
    caller identity resolved from X-VisorShield-User. This was previously
    unanswerable: transactions only carried org_id/app_source, so every
    caller behind a shared API key looked the same.
    """
    org_scope = _resolve_org_scope(claims, org_id)
    filters = []
    if org_scope is not None:
        filters.append(Transaction.org_id == org_scope)

    q = (
        select(
            Transaction.external_user_id,
            Transaction.user_id,
            func.count(Transaction.id).label("request_count"),
            func.coalesce(func.sum(Transaction.input_tokens), 0).label("input_tokens"),
            func.coalesce(func.sum(Transaction.output_tokens), 0).label("output_tokens"),
            func.coalesce(func.sum(Transaction.cost_usd), 0).label("cost_usd"),
        )
        .group_by(Transaction.external_user_id, Transaction.user_id)
        .order_by(func.coalesce(func.sum(Transaction.cost_usd), 0).desc())
    )
    if filters:
        q = q.where(and_(*filters))

    count_q = select(func.count(func.distinct(Transaction.external_user_id)))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()

    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    rows = result.all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "external_user_id": r.external_user_id,
                "user_id": str(r.user_id) if r.user_id else None,
                "request_count": r.request_count,
                "total_tokens": int(r.input_tokens) + int(r.output_tokens),
                "total_cost_usd": float(r.cost_usd),
            }
            for r in rows
        ],
    }


@router.get("/export")
async def export_transactions(
    format: Literal["csv", "json"] = Query("csv"),
    org_id: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    compliance_status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_compliance_or_admin()),
):
    """
    Bulk export for external auditors/SIEM ingestion. Includes the hash-chain
    fields (chain_seq/prev_hash/record_hash) so the export itself can be
    independently re-verified offline, not just via GET /audit/verify.

    Capped at MAX_EXPORT_ROWS per call — pull incrementally with date_from
    for anything larger, rather than this holding one unbounded result set
    in memory.
    """
    MAX_EXPORT_ROWS = 50_000
    org_scope = _resolve_org_scope(claims, org_id)
    filters = []
    if org_scope is not None:
        filters.append(Transaction.org_id == org_scope)
    if date_from:
        filters.append(Transaction.created_at >= date_from)
    if date_to:
        filters.append(Transaction.created_at <= date_to)
    if compliance_status:
        filters.append(Transaction.compliance_status == compliance_status)

    q = select(Transaction).order_by(Transaction.org_id, Transaction.chain_seq).limit(MAX_EXPORT_ROWS)
    if filters:
        q = q.where(and_(*filters))
    result = await db.execute(q)
    rows = [_tx_export_row(tx) for tx in result.scalars().all()]

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    if format == "json":
        content = json.dumps(rows, default=str)

        def _iter_json():
            yield content

        return StreamingResponse(
            _iter_json(),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=visorshield_audit_export_{timestamp}.json"},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_TRANSACTION_EXPORT_FIELDS)
    writer.writeheader()
    for row in rows:
        row = dict(row)
        row["pii_detected"] = ",".join(row["pii_detected"] or [])
        row["response_pii_detected"] = ",".join(row["response_pii_detected"] or [])
        writer.writerow(row)

    def _iter_csv():
        yield buf.getvalue()

    return StreamingResponse(
        _iter_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=visorshield_audit_export_{timestamp}.csv"},
    )


@router.get("/verify")
async def verify_chain(
    org_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    claims: dict = Depends(require_compliance_or_admin()),
):
    """
    Recompute this org's hash chain from the stored rows and report the first
    broken link, if any. This is what makes "immutable audit" a checkable
    claim rather than a policy statement: any row edited in place (bypassing
    the append-only trigger, e.g. by a superuser) changes that row's own
    hash and desyncs every later link, and this endpoint proves it.
    """
    org_scope = _resolve_org_scope(claims, org_id)
    if org_scope is None:
        raise HTTPException(status_code=422, detail={"error": "org_id_required"})

    result = await db.execute(
        select(Transaction).where(Transaction.org_id == org_scope).order_by(Transaction.chain_seq)
    )
    rows = result.scalars().all()

    prev_hash = None
    expected_seq = 1
    for tx in rows:
        if tx.chain_seq != expected_seq:
            return {
                "valid": False,
                "verified_count": expected_seq - 1,
                "broken_at_transaction_id": str(tx.id),
                "reason": "chain_seq_gap",
            }
        if tx.prev_hash != prev_hash:
            return {
                "valid": False,
                "verified_count": expected_seq - 1,
                "broken_at_transaction_id": str(tx.id),
                "reason": "prev_hash_mismatch",
            }
        fields = canonical_transaction_fields(
            id=tx.id,
            org_id=tx.org_id,
            app_source=tx.app_source,
            model_requested=tx.model_requested,
            model_used=tx.model_used,
            provider=tx.provider,
            prompt_hash=tx.prompt_hash,
            pii_detected=tx.pii_detected,
            response_pii_detected=tx.response_pii_detected,
            input_tokens=tx.input_tokens,
            output_tokens=tx.output_tokens,
            cost_usd=tx.cost_usd,
            compliance_status=tx.compliance_status,
            guardrail_triggered=tx.guardrail_triggered,
            latency_ms=tx.latency_ms,
            industry_type=tx.industry_type,
            routing_reason=tx.routing_reason,
            user_id=tx.user_id,
            external_user_id=tx.external_user_id,
            created_at=tx.created_at,
        )
        expected_hash = recompute_record_hash(fields, prev_hash)
        if expected_hash != tx.record_hash:
            return {
                "valid": False,
                "verified_count": expected_seq - 1,
                "broken_at_transaction_id": str(tx.id),
                "reason": "record_hash_mismatch",
            }
        prev_hash = tx.record_hash
        expected_seq += 1

    return {"valid": True, "verified_count": len(rows)}
