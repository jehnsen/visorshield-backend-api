import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit import Transaction, GuardrailIncident


async def generate_monthly_summary(
    db: AsyncSession,
    org_id: Optional[str] = None,
    year: Optional[int] = None,
    month: Optional[int] = None,
) -> Dict[str, Any]:
    """Generate monthly usage and compliance summary. PDF export is a future feature."""
    now = datetime.now(timezone.utc)
    year = year or now.year
    month = month or now.month

    start = datetime(year, month, 1, tzinfo=timezone.utc)
    if month == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month + 1, 1, tzinfo=timezone.utc)

    filters = [Transaction.created_at >= start, Transaction.created_at < end]
    if org_id:
        filters.append(Transaction.org_id == uuid.UUID(org_id))

    result = await db.execute(
        select(
            func.count(Transaction.id).label("total_requests"),
            func.coalesce(func.sum(Transaction.input_tokens), 0).label("total_input_tokens"),
            func.coalesce(func.sum(Transaction.output_tokens), 0).label("total_output_tokens"),
            func.coalesce(func.sum(Transaction.cost_usd), 0).label("total_cost_usd"),
            func.count(Transaction.id).filter(Transaction.compliance_status == "pass").label("compliant_requests"),
            func.count(Transaction.id).filter(Transaction.compliance_status != "pass").label("non_compliant_requests"),
        ).where(and_(*filters))
    )
    row = result.one()

    # PII events
    pii_result = await db.execute(
        select(Transaction.pii_detected, Transaction.response_pii_detected)
        .where(and_(*filters))
    )
    pii_events = 0
    for row_pii in pii_result:
        pii_events += len(row_pii.pii_detected or [])
        pii_events += len(row_pii.response_pii_detected or [])

    # Guardrail hits
    guard_filters = [GuardrailIncident.created_at >= start, GuardrailIncident.created_at < end]
    if org_id:
        guard_filters.append(GuardrailIncident.org_id == uuid.UUID(org_id))
    guard_result = await db.execute(
        select(func.count(GuardrailIncident.id)).where(and_(*guard_filters))
    )
    guardrail_hits = guard_result.scalar() or 0

    total = row.total_requests or 1
    compliance_rate = round((row.compliant_requests / total) * 100, 2)

    return {
        "period": f"{year}-{month:02d}",
        "org_id": org_id,
        "total_requests": row.total_requests,
        "total_input_tokens": int(row.total_input_tokens),
        "total_output_tokens": int(row.total_output_tokens),
        "total_tokens": int(row.total_input_tokens) + int(row.total_output_tokens),
        "total_cost_usd": float(row.total_cost_usd),
        "pii_events_prevented": pii_events,
        "guardrail_hits": guardrail_hits,
        "compliance_rate_pct": compliance_rate,
        "compliant_requests": row.compliant_requests,
        "non_compliant_requests": row.non_compliant_requests,
        "note": "PDF report generation is a planned future feature. This endpoint returns JSON summary.",
    }
