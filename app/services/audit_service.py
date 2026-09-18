import asyncio
import uuid
import time
from datetime import datetime, timezone
import structlog
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.models.audit import Transaction, GuardrailIncident
from app.db.database import AsyncSessionLocal
from app.services.audit_integrity import append_chain_link, canonical_transaction_fields
from app.services.metrics import record_guardrail_incident

log = structlog.get_logger()

# Lazy import to avoid circular dependency at module load time
def _get_webhook_service():
    from app.services import webhook_service
    return webhook_service


async def log_transaction(
    org_id: str,
    app_source: str,
    model_requested: str,
    model_used: str,
    provider: str,
    prompt_hash: str,
    pii_detected: List[str],
    response_pii_detected: List[str],
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    compliance_status: str,
    guardrail_triggered: Optional[str],
    latency_ms: int,
    industry_type: str,
    routing_reason: str,
    transaction_id: Optional[uuid.UUID] = None,
    user_id: Optional[str] = None,
    external_user_id: Optional[str] = None,
) -> uuid.UUID:
    if transaction_id is None:
        transaction_id = uuid.uuid4()

    org_uuid = uuid.UUID(org_id) if isinstance(org_id, str) else org_id
    user_uuid = uuid.UUID(user_id) if user_id else None
    created_at = datetime.now(timezone.utc)

    fields = canonical_transaction_fields(
        id=transaction_id,
        org_id=org_uuid,
        app_source=app_source,
        model_requested=model_requested,
        model_used=model_used,
        provider=provider,
        prompt_hash=prompt_hash,
        pii_detected=pii_detected,
        response_pii_detected=response_pii_detected,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost_usd,
        compliance_status=compliance_status,
        guardrail_triggered=guardrail_triggered,
        latency_ms=latency_ms,
        industry_type=industry_type,
        routing_reason=routing_reason,
        user_id=user_uuid,
        external_user_id=external_user_id,
        created_at=created_at,
    )

    async with AsyncSessionLocal() as session:
        try:
            record_hash, prev_hash, chain_seq = await append_chain_link(session, org_uuid, fields)
        except Exception as exc:
            await session.rollback()
            log.error("audit_chain_append_failed", error=str(exc), transaction_id=str(transaction_id))
            return transaction_id

        tx = Transaction(
            id=transaction_id,
            org_id=org_uuid,
            app_source=app_source,
            model_requested=model_requested,
            model_used=model_used,
            provider=provider,
            prompt_hash=prompt_hash,
            pii_detected=pii_detected,
            response_pii_detected=response_pii_detected,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            compliance_status=compliance_status,
            guardrail_triggered=guardrail_triggered,
            latency_ms=latency_ms,
            industry_type=industry_type,
            routing_reason=routing_reason,
            user_id=user_uuid,
            external_user_id=external_user_id,
            chain_seq=chain_seq,
            prev_hash=prev_hash,
            record_hash=record_hash,
            created_at=created_at,
        )
        session.add(tx)
        try:
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("audit_log_failed", error=str(exc), transaction_id=str(transaction_id))
            return transaction_id

    # Inventory auto-discovery — best-effort, never blocks or fails the audit
    # write above (each helper swallows its own errors; see inventory_service.py).
    from app.services.inventory_service import record_provider_model_usage, record_app_usage
    if provider and model_used:
        await record_provider_model_usage(provider, model_used)
    if app_source:
        await record_app_usage(org_id, app_source)

    return transaction_id


async def log_guardrail_incident(
    org_id: str,
    transaction_id: uuid.UUID,
    policy_profile: str,
    violation_category: str,
    detection_layer: str,
    prompt_hash: str,
    request_id: str = "",
) -> None:
    async with AsyncSessionLocal() as session:
        incident = GuardrailIncident(
            org_id=uuid.UUID(org_id) if isinstance(org_id, str) else org_id,
            transaction_id=transaction_id,
            policy_profile=policy_profile,
            violation_category=violation_category,
            detection_layer=detection_layer,
            prompt_hash=prompt_hash,
        )
        session.add(incident)
        try:
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("guardrail_incident_log_failed", error=str(exc))

    record_guardrail_incident(
        org_id=org_id,
        policy_profile=policy_profile,
        detection_layer=detection_layer,
        violation_category=violation_category,
    )

    # Fire webhook alert (non-blocking, errors swallowed inside the service)
    ws = _get_webhook_service()
    await ws.send_guardrail_alert(
        org_id=org_id,
        transaction_id=str(transaction_id),
        policy_profile=policy_profile,
        violation_category=violation_category,
        detection_layer=detection_layer,
        prompt_hash=prompt_hash,
        request_id=request_id,
    )


# Strong references to in-flight audit tasks. Without this the event loop only
# keeps a weak reference and may garbage-collect a task mid-write.
_background_tasks: set = set()


def _on_audit_task_done(task: "asyncio.Task") -> None:
    _background_tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("audit_task_failed", error=str(exc), error_type=type(exc).__name__)


def fire_and_forget_audit(coro) -> None:
    """Schedule audit logging as a background task (non-blocking).

    Holds a strong reference until completion so the task can't be GC'd
    mid-flight, and drains the task's exception via a done callback so a failed
    write is logged instead of surfacing as "Task exception was never retrieved".
    """
    try:
        task = asyncio.create_task(coro)
    except RuntimeError:
        # No running event loop (e.g. called from a sync context). Close the
        # coroutine to avoid an "never awaited" warning and log the drop.
        coro.close()
        log.warning("audit_task_no_event_loop")
        return
    _background_tasks.add(task)
    task.add_done_callback(_on_audit_task_done)
