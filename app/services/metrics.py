"""
Prometheus metrics for VisorShield.

The core governance-product demo is "how many requests did we block, by
policy, by org" — this module turns the data VisorShield already produces
(pipeline_timing, GuardrailIncident rows) into that counter, plus enough
surrounding metrics (total requests, per-step latency) to compute a block
rate. Call sites: app/routers/proxy.py (pipeline blocks + outcomes) and
app/services/audit_service.py (guardrail incidents, mirroring the audit
table so this metric and GET /audit/incidents never disagree).
"""
from typing import Dict, Optional
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

REQUESTS_TOTAL = Counter(
    "visorshield_requests_total",
    "Total /v1/chat/completions requests, by org, industry policy profile and outcome",
    ["org_id", "industry_type", "outcome"],
)

REQUESTS_BLOCKED_TOTAL = Counter(
    "visorshield_requests_blocked_total",
    "Requests blocked by the interceptor pipeline, by org, industry policy profile, "
    "pipeline step and reason",
    ["org_id", "industry_type", "pipeline_step", "reason"],
)

GUARDRAIL_INCIDENTS_TOTAL = Counter(
    "visorshield_guardrail_incidents_total",
    "Guardrail policy violations logged to the audit trail, by org, policy profile, "
    "detection layer and violation category",
    ["org_id", "policy_profile", "detection_layer", "violation_category"],
)

PIPELINE_STEP_DURATION_MS = Histogram(
    "visorshield_pipeline_step_duration_ms",
    "Time spent in each interceptor pipeline step (from request.state.pipeline_timing)",
    ["pipeline_step"],
    buckets=(1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000),
)


def _label(value: Optional[str]) -> str:
    return value if value else "unknown"


def record_blocked(org_id: Optional[str], industry_type: Optional[str], pipeline_step: str, reason: str) -> None:
    org_id = _label(org_id)
    industry_type = _label(industry_type)
    REQUESTS_BLOCKED_TOTAL.labels(
        org_id=org_id, industry_type=industry_type, pipeline_step=pipeline_step, reason=_label(reason)
    ).inc()
    REQUESTS_TOTAL.labels(org_id=org_id, industry_type=industry_type, outcome="blocked").inc()


def record_outcome(org_id: Optional[str], industry_type: Optional[str], outcome: str) -> None:
    REQUESTS_TOTAL.labels(org_id=_label(org_id), industry_type=_label(industry_type), outcome=outcome).inc()


def record_guardrail_incident(
    org_id: Optional[str], policy_profile: Optional[str], detection_layer: Optional[str], violation_category: Optional[str]
) -> None:
    GUARDRAIL_INCIDENTS_TOTAL.labels(
        org_id=_label(org_id),
        policy_profile=_label(policy_profile),
        detection_layer=_label(detection_layer),
        violation_category=_label(violation_category),
    ).inc()


def record_pipeline_timing(pipeline_timing: Optional[Dict[str, float]]) -> None:
    for step, elapsed_ms in (pipeline_timing or {}).items():
        try:
            PIPELINE_STEP_DURATION_MS.labels(pipeline_step=step).observe(float(elapsed_ms))
        except (TypeError, ValueError):
            continue


def render_metrics() -> bytes:
    return generate_latest()


__all__ = [
    "record_blocked",
    "record_outcome",
    "record_guardrail_incident",
    "record_pipeline_timing",
    "render_metrics",
    "CONTENT_TYPE_LATEST",
]
