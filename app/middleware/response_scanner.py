import time
import structlog
from fastapi import Request, HTTPException
from app.middleware.pii_engine import pii_scan_response

log = structlog.get_logger()

# Placeholder returned to client when response PII scan fails.
# Never expose the original LLM response if scanning errors — consistent with fail-closed PII policy.
_SCAN_FAILURE_PLACEHOLDER = (
    "[Response blocked: post-response safety scan encountered an error. "
    "Contact support with your X-VisorShield-Request-ID.]"
)


async def scan_response(text: str, request: Request) -> str:
    """
    Step 5: Scan LLM response for PII and mask before returning to client.
    Fail-closed: on any Presidio error, replaces response with a safe placeholder
    rather than returning potentially unmasked content. Logs the error for debugging.
    """
    start = time.monotonic()

    claims = getattr(request.state, "jwt_claims", {})
    # Policy comes from the verified JWT claim, never the raw header (see pii_engine).
    industry_type = claims.get("industry_type") or request.headers.get("X-Industry-Type", "")
    org_id = claims.get("org_id", "unknown")
    request_id = getattr(request.state, "request_id", "")

    masked_text, detected, scan_error = await _safe_pii_scan(text, industry_type)

    request.state.response_pii_detected = list(set(detected))

    elapsed = (time.monotonic() - start) * 1000
    request.state.pipeline_timing["response_scanner"] = elapsed

    if scan_error:
        log.error(
            "response_pii_scan_failed_blocked",
            org_id=org_id,
            request_id=request_id,
            pipeline_step="response_scanner",
            error=scan_error,
            elapsed_ms=round(elapsed, 2),
        )
        # Return placeholder — never pass unscanned LLM output to the client
        return _SCAN_FAILURE_PLACEHOLDER

    if detected:
        log.warning(
            "response_pii_detected",
            org_id=org_id,
            request_id=request_id,
            pipeline_step="response_scanner",
            detected_types=detected,
            elapsed_ms=round(elapsed, 2),
        )
    else:
        log.info(
            "response_scan_clean",
            org_id=org_id,
            request_id=request_id,
            pipeline_step="response_scanner",
            elapsed_ms=round(elapsed, 2),
        )

    return masked_text


async def _safe_pii_scan(text: str, industry_type: str):
    """Returns (masked_text, detected_types, error_string_or_None)."""
    try:
        masked, detected = await pii_scan_response(text, industry_type)
        return masked, detected, None
    except Exception as exc:
        return text, [], str(exc)
