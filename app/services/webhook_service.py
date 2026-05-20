import hashlib
import hmac
import json
import time
import structlog
import httpx
from typing import Optional
from app.config import settings

log = structlog.get_logger()


def _sign_payload(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 signature for webhook payload verification."""
    mac = hmac.HMAC(secret.encode(), payload, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


async def send_guardrail_alert(
    org_id: str,
    transaction_id: str,
    policy_profile: str,
    violation_category: str,
    detection_layer: str,
    prompt_hash: str,
    request_id: str = "",
) -> None:
    """
    POST a guardrail incident alert to the configured webhook URL.
    No-ops silently if WEBHOOK_URL is not set.
    """
    if not settings.WEBHOOK_URL:
        return

    min_severity = settings.WEBHOOK_MIN_SEVERITY.lower()
    if min_severity != "all" and detection_layer != min_severity:
        return

    event = {
        "event": "guardrail.incident",
        "timestamp": int(time.time()),
        "request_id": request_id,
        "data": {
            "org_id": org_id,
            "transaction_id": transaction_id,
            "policy_profile": policy_profile,
            "violation_category": violation_category,
            "detection_layer": detection_layer,
            "prompt_hash": prompt_hash,
        },
    }

    payload_bytes = json.dumps(event, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VisorShield/1.0",
        "X-VisorShield-Event": "guardrail.incident",
        "X-VisorShield-Delivery": request_id or transaction_id,
    }

    if settings.WEBHOOK_SECRET:
        headers["X-VisorShield-Signature"] = _sign_payload(payload_bytes, settings.WEBHOOK_SECRET)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(settings.WEBHOOK_URL, content=payload_bytes, headers=headers)
            if resp.status_code >= 400:
                log.warning(
                    "webhook_delivery_failed",
                    status=resp.status_code,
                    url=settings.WEBHOOK_URL,
                    org_id=org_id,
                    pipeline_step="webhook",
                )
            else:
                log.info(
                    "webhook_delivered",
                    status=resp.status_code,
                    org_id=org_id,
                    detection_layer=detection_layer,
                    pipeline_step="webhook",
                )
    except Exception as exc:
        # Webhook delivery failure must never affect the main request path
        log.error(
            "webhook_error",
            error=str(exc),
            url=settings.WEBHOOK_URL,
            org_id=org_id,
            pipeline_step="webhook",
        )


async def send_quota_alert(
    org_id: str,
    used_tokens: int,
    budget_tokens: int,
    reset_date: str,
) -> None:
    """Alert when an org exceeds its monthly token quota."""
    if not settings.WEBHOOK_URL:
        return

    event = {
        "event": "quota.exceeded",
        "timestamp": int(time.time()),
        "data": {
            "org_id": org_id,
            "used_tokens": used_tokens,
            "budget_tokens": budget_tokens,
            "reset_date": reset_date,
        },
    }

    payload_bytes = json.dumps(event, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VisorShield/1.0",
        "X-VisorShield-Event": "quota.exceeded",
    }

    if settings.WEBHOOK_SECRET:
        headers["X-VisorShield-Signature"] = _sign_payload(payload_bytes, settings.WEBHOOK_SECRET)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(settings.WEBHOOK_URL, content=payload_bytes, headers=headers)
    except Exception as exc:
        log.error("webhook_error", error=str(exc), event="quota.exceeded", org_id=org_id)
