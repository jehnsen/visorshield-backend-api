"""
Browser-extension surface: POST /v1/extension/*

The extension is the primary capture point for staff who use chatgpt.com
directly and never touch an API. VisorShield is NOT in the network path for
that traffic — the content script captures the composer's text, sends it here,
and types the masked result back into the page. So this surface returns a
decision plus the masked text; it never forwards anything to a provider.

Pipeline reuse is deliberate. Steps 1-4 are exactly the proxy's:

    [1] auth_middleware      -> JWT, org/key active, claims on request.state
    [2] rate_limit_middleware-> Redis spike arrest + monthly quota
    [3] Presidio scan        -> same analyzer, same PH recognizers, fail-closed
    [4] guardrails_middleware-> keyword + prompt-injection + embedding, 451

Step 5 (response scanning) is /response-scan, driven by the extension when the
org's policy sets ``audit_responses``, since only the page can see the answer.

What differs from the proxy, and why:

  * The masked prompt and the placeholder->original map are RETURNED to the
    caller instead of being forwarded. The map is the re-identification key; it
    is never persisted server-side and never logged. The extension keeps it in
    ``chrome.storage.session`` (cleared when the browser closes).
  * There is no model, no provider, no token usage and no cost, because no
    completion happens here. Audit rows therefore record zero tokens and an
    empty provider — a scan is a compliance event, not a spend event.
"""
import time
import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import and_, func, select

from app.middleware.auth import auth_middleware
from app.middleware.guardrails import guardrails_middleware
from app.middleware.pii_engine import _scan_text, _apply_regex_patterns
from app.middleware.rate_limit import rate_limit_middleware
from app.models.audit import Transaction
from app.models.extension import (
    ExtensionEventAck,
    ExtensionEventBatch,
    ExtensionHeartbeatRequest,
    ExtensionHeartbeatResponse,
    ExtensionPolicy,
    ExtensionResponseScanRequest,
    ExtensionResponseScanResponse,
    ExtensionScanRequest,
    ExtensionScanResponse,
)
from app.models.request import ChatCompletionRequest, ChatMessage
from app.policies import VALID_INDUSTRY_TYPES, get_policy
from app.services.audit_service import (
    fire_and_forget_audit,
    log_guardrail_incident,
    log_transaction,
)

log = structlog.get_logger()
router = APIRouter(prefix="/v1/extension", tags=["extension"])

# Entity types that make a prompt high-risk on their own. Government IDs are
# the ones that turn a careless paste into a reportable DPA incident.
_HIGH_RISK_ENTITIES = frozenset({"PH_TIN", "PH_SSS", "PH_PHILSYS", "US_SSN", "CREDIT_CARD"})

# Total entity count at which a prompt is medium risk even with nothing severe
# in it. Several ordinary identifiers together still re-identify a person.
_MEDIUM_RISK_ENTITY_COUNT = 3


def _require_valid_industry_type(request: Request) -> str:
    """
    Same fail-closed rule as the proxy: an unknown profile would silently
    downgrade PII masking to a generic entity list and skip the guardrail
    policy entirely, so reject it outright rather than scan with the wrong
    template.
    """
    industry_type = request.headers.get("X-Industry-Type", "").strip()
    if industry_type not in VALID_INDUSTRY_TYPES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_industry_type",
                "message": "X-Industry-Type header is required and must be one of: "
                + ", ".join(sorted(VALID_INDUSTRY_TYPES)),
                "allowed": sorted(VALID_INDUSTRY_TYPES),
            },
        )
    return industry_type


def _risk_level(summary: dict[str, int]) -> str:
    if any(etype in _HIGH_RISK_ENTITIES for etype in summary):
        return "high"
    if sum(summary.values()) >= _MEDIUM_RISK_ENTITY_COUNT:
        return "medium"
    return "low"


async def _prior_flags_this_month(org_id: str) -> int:
    """
    Count of this org's flagged scans so far this calendar month, shown to the
    user during review ("this is the 3rd time this month"). Best-effort: a DB
    error must not block a scan that has already passed policy, so it degrades
    to 0 rather than raising.
    """
    try:
        from app.db.database import AsyncSessionLocal

        now = datetime.now(timezone.utc)
        month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(Transaction.id)).where(
                    and_(
                        Transaction.org_id == uuid.UUID(org_id),
                        Transaction.created_at >= month_start,
                        Transaction.compliance_status != "pass",
                    )
                )
            )
            return int(result.scalar() or 0)
    except Exception as exc:
        log.warning("prior_flags_lookup_failed", error=str(exc), pipeline_step="extension")
        return 0


@router.post("/scan", response_model=ExtensionScanResponse)
async def scan_prompt(request: Request, body: ExtensionScanRequest) -> ExtensionScanResponse:
    """
    Scan a composer prompt and return the masked text plus its entity map.

    Blocks with 451 on a policy violation, exactly as the proxy does, so the
    extension's existing error handling applies unchanged.
    """
    request.state.pipeline_timing = {}
    request.state._pipeline_start = time.monotonic()
    request.state.pii_detected = []
    request.state.prompt_hash = ""
    request.state.guardrail_triggered = None
    request.state.guardrail_layer = None

    industry_type = _require_valid_industry_type(request)

    # [1] + [2] — identical to the proxy path.
    await auth_middleware(request)
    await rate_limit_middleware(request)

    claims = request.state.jwt_claims
    org_id = claims.get("org_id", "unknown")
    request_id = getattr(request.state, "request_id", "")
    transaction_id = uuid.uuid4()

    # Hash the ORIGINAL prompt before masking — audit stores the hash, never text.
    import hashlib

    request.state.prompt_hash = hashlib.sha256(body.prompt.encode()).hexdigest()

    policy = get_policy(industry_type)

    # [3] PII scan. Fail-closed: any Presidio error blocks, matching the rule
    # that the engine must never fail open.
    scan_start = time.monotonic()
    try:
        masked_prompt, detected_types, placeholder_map = _scan_text(
            body.prompt, policy.pii_entities
        )
        masked_prompt = _apply_regex_patterns(masked_prompt, policy.regex_patterns)
    except Exception as exc:
        log.error(
            "pii_scan_failed",
            error=str(exc),
            org_id=org_id,
            request_id=request_id,
            pipeline_step="pii_engine",
        )
        raise HTTPException(
            status_code=500,
            detail={"error": "pii_scan_failed", "message": "Request blocked for safety"},
        )
    request.state.pipeline_timing["pii_engine"] = (time.monotonic() - scan_start) * 1000
    request.state.pii_detected = detected_types

    # [4] Guardrails. Reuses the middleware unmodified by presenting the prompt
    # in the shape it reads from (parsed_body.messages), so keyword, injection
    # and embedding layers all stay in one place.
    request.state.parsed_body = ChatCompletionRequest(
        model="extension-scan",
        messages=[ChatMessage(role="user", content=body.prompt)],
    )
    try:
        await guardrails_middleware(request)
    except HTTPException as exc:
        if exc.status_code == 451:
            _audit_blocked_scan(request, industry_type, transaction_id, claims)
        raise

    # Per-type counts drive both the risk level and the review UI's summary.
    summary: dict[str, int] = {}
    for placeholder in placeholder_map:
        # "[PERSON_1]" -> "PERSON"
        etype = placeholder.strip("[]").rsplit("_", 1)[0]
        summary[etype] = summary.get(etype, 0) + 1

    entities = [
        {"type": ph.strip("[]").rsplit("_", 1)[0], "placeholder": ph, "original": original}
        for ph, original in placeholder_map.items()
    ]
    clean = not entities
    latency_ms = int((time.monotonic() - request.state._pipeline_start) * 1000)

    fire_and_forget_audit(
        log_transaction(
            org_id=org_id,
            app_source=f"extension:{body.site}",
            model_requested="",
            model_used="",
            provider="",
            prompt_hash=request.state.prompt_hash,
            pii_detected=detected_types,
            response_pii_detected=[],
            # No completion happens here, so there is no spend to record.
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            compliance_status="pass" if clean else "masked",
            guardrail_triggered=None,
            latency_ms=latency_ms,
            industry_type=industry_type,
            routing_reason="extension_scan",
            transaction_id=transaction_id,
        )
    )

    log.info(
        "extension_scan_complete",
        org_id=org_id,
        request_id=request_id,
        pipeline_step="extension",
        pii_types=detected_types,
        entity_count=len(entities),
        site=body.site,
        elapsed_ms=latency_ms,
    )

    return ExtensionScanResponse(
        transaction_id=str(transaction_id),
        status="clean" if clean else "masked",
        risk_level=_risk_level(summary),
        masked_prompt=body.prompt if clean else masked_prompt,
        entities=entities,
        summary=summary,
        prior_flags_this_month=await _prior_flags_this_month(org_id),
        policy_profile=industry_type,
    )


def _audit_blocked_scan(
    request: Request, industry_type: str, transaction_id: uuid.UUID, claims: dict
) -> None:
    """Record a 451'd scan as both a transaction and an incident, as the proxy does."""
    fire_and_forget_audit(
        log_transaction(
            org_id=claims.get("org_id", "unknown"),
            app_source="extension",
            model_requested="",
            model_used="",
            provider="",
            prompt_hash=getattr(request.state, "prompt_hash", ""),
            pii_detected=getattr(request.state, "pii_detected", []),
            response_pii_detected=[],
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            compliance_status="blocked",
            guardrail_triggered=getattr(request.state, "guardrail_triggered", None),
            latency_ms=int((time.monotonic() - request.state._pipeline_start) * 1000),
            industry_type=industry_type,
            routing_reason="guardrail_block",
            transaction_id=transaction_id,
        )
    )
    fire_and_forget_audit(
        log_guardrail_incident(
            org_id=claims.get("org_id", "unknown"),
            transaction_id=transaction_id,
            policy_profile=industry_type,
            violation_category=getattr(request.state, "guardrail_triggered", "unknown"),
            detection_layer=getattr(request.state, "guardrail_layer", "unknown"),
            prompt_hash=getattr(request.state, "prompt_hash", ""),
            request_id=getattr(request.state, "request_id", ""),
        )
    )


@router.post("/response-scan", response_model=ExtensionResponseScanResponse)
async def scan_assistant_response(
    request: Request, body: ExtensionResponseScanRequest
) -> ExtensionResponseScanResponse:
    """
    Step 5 for the extension: audit PII the model introduced into its answer.

    Returns types and placeholders only — never originals. The extension is
    reporting what the page already displayed; handing back values it did not
    ask for would widen exposure for no benefit.
    """
    request.state.pipeline_timing = {}
    industry_type = _require_valid_industry_type(request)
    await auth_middleware(request)

    claims = request.state.jwt_claims
    org_id = claims.get("org_id", "unknown")
    policy = get_policy(industry_type)

    try:
        _, detected, placeholder_map = _scan_text(body.text, policy.pii_entities)
    except Exception as exc:
        log.error(
            "response_pii_scan_failed",
            error=str(exc),
            org_id=org_id,
            pipeline_step="response_scanner",
        )
        raise HTTPException(
            status_code=500,
            detail={"error": "response_scan_failed", "message": "Scan could not be completed"},
        )

    if detected:
        log.warning(
            "extension_response_pii_detected",
            org_id=org_id,
            transaction_id=body.transaction_id,
            pipeline_step="response_scanner",
            detected_types=detected,
        )

    return ExtensionResponseScanResponse(
        new_entities=[
            {"type": ph.strip("[]").rsplit("_", 1)[0], "placeholder": ph}
            for ph in placeholder_map
        ]
    )


@router.get("/policy", response_model=ExtensionPolicy)
async def get_extension_policy(request: Request) -> ExtensionPolicy:
    """
    Device-side policy for the calling org, cached ~10 minutes by the worker.

    Currently the documented defaults for every org. Per-org overrides belong in
    a column on ``organizations``; until that exists, serving the strict default
    is the safe behaviour rather than inventing a laxer one.
    """
    await auth_middleware(request)
    return ExtensionPolicy()


@router.post("/events", response_model=ExtensionEventAck, status_code=202)
async def report_events(request: Request, body: ExtensionEventBatch) -> ExtensionEventAck:
    """
    Metadata-only telemetry sink.

    The model has no field capable of holding prompt text, so a client that
    tries to smuggle some gets it dropped by validation rather than stored.
    """
    await auth_middleware(request)
    claims = request.state.jwt_claims

    for event in body.events:
        log.info(
            "extension_event",
            org_id=claims.get("org_id", "unknown"),
            event_type=event.type,
            transaction_id=event.transaction_id,
            category=event.category,
            pipeline_step="extension",
        )

    return ExtensionEventAck(accepted=len(body.events))


@router.post("/heartbeat", response_model=ExtensionHeartbeatResponse)
async def heartbeat(
    request: Request, body: ExtensionHeartbeatRequest
) -> ExtensionHeartbeatResponse:
    """Liveness ping. Lets the dashboard show which devices are actually protected."""
    await auth_middleware(request)
    claims = request.state.jwt_claims

    log.info(
        "extension_heartbeat",
        org_id=claims.get("org_id", "unknown"),
        device_id=body.device_id,
        version=body.extension_version,
        pipeline_step="extension",
    )
    return ExtensionHeartbeatResponse(ok=True)
