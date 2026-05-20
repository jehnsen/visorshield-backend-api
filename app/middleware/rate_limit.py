import time
import asyncio
from datetime import datetime, timezone
from calendar import monthrange
import structlog
from fastapi import Request, HTTPException
import redis.asyncio as aioredis
from app.config import settings

log = structlog.get_logger()

_redis_client: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def _monthly_reset_date() -> str:
    now = datetime.now(timezone.utc)
    _, last_day = monthrange(now.year, now.month)
    reset = datetime(now.year, now.month, last_day, 23, 59, 59, tzinfo=timezone.utc)
    return reset.strftime("%Y-%m-%dT%H:%M:%SZ")


async def rate_limit_middleware(request: Request) -> None:
    """Spike arrest + monthly token quota enforcement via Redis."""
    start = time.monotonic()

    claims = getattr(request.state, "jwt_claims", {})
    org_id = claims.get("org_id", "unknown")
    api_key = request.headers.get("X-API-Key", "default")
    rpm_limit = int(claims.get("rpm_limit", 60))
    monthly_budget = int(claims.get("monthly_token_budget", 1_000_000))

    redis = get_redis()
    request_id = getattr(request.state, "request_id", "")

    # --- Spike Arrest: sliding window per-minute counter ---
    rpm_key = f"visorshield:{org_id}:{api_key}:rpm"
    now_ts = int(time.time())
    window_start = now_ts - 60

    pipe = redis.pipeline()
    pipe.zremrangebyscore(rpm_key, "-inf", window_start)
    pipe.zadd(rpm_key, {f"{now_ts}:{request_id}": now_ts})
    pipe.zcard(rpm_key)
    pipe.expire(rpm_key, 120)
    results = await pipe.execute()

    current_rpm = results[2]
    if current_rpm > rpm_limit:
        log.warning(
            "rate_limit_exceeded",
            org_id=org_id,
            current_rpm=current_rpm,
            rpm_limit=rpm_limit,
            request_id=request_id,
            pipeline_step="rate_limit",
        )
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limit_exceeded", "retry_after_seconds": 60},
        )

    # --- Monthly Token Quota Check ---
    now = datetime.now(timezone.utc)
    monthly_key = f"visorshield:{org_id}:{api_key}:monthly_tokens:{now.year}:{now.month}"
    used_tokens = await redis.get(monthly_key)
    used_tokens = int(used_tokens) if used_tokens else 0

    if used_tokens >= monthly_budget:
        reset_date = _monthly_reset_date()
        log.warning(
            "quota_exceeded",
            org_id=org_id,
            used_tokens=used_tokens,
            monthly_budget=monthly_budget,
            request_id=request_id,
            pipeline_step="rate_limit",
        )
        # Fire webhook alert non-blocking (quota alerts defined in webhook_service)
        import asyncio
        from app.services.webhook_service import send_quota_alert
        asyncio.create_task(
            send_quota_alert(
                org_id=org_id,
                used_tokens=used_tokens,
                budget_tokens=monthly_budget,
                reset_date=reset_date,
            )
        )
        raise HTTPException(
            status_code=429,
            detail={"error": "quota_exceeded", "reset_date": reset_date},
        )

    # Store keys in state so audit service can increment after response
    request.state.rate_limit_keys = {
        "monthly_key": monthly_key,
        "rpm_key": rpm_key,
        "monthly_budget": monthly_budget,
    }

    elapsed = (time.monotonic() - start) * 1000
    request.state.pipeline_timing["rate_limit"] = elapsed

    log.info(
        "rate_limit_passed",
        org_id=org_id,
        current_rpm=current_rpm,
        used_tokens=used_tokens,
        monthly_budget=monthly_budget,
        request_id=request_id,
        pipeline_step="rate_limit",
        elapsed_ms=round(elapsed, 2),
    )


async def increment_token_usage(request: Request, input_tokens: int, output_tokens: int) -> None:
    """Called after LLM response to update token counters."""
    keys = getattr(request.state, "rate_limit_keys", None)
    if not keys:
        return
    redis = get_redis()
    total = input_tokens + output_tokens
    now = datetime.now(timezone.utc)
    _, last_day = monthrange(now.year, now.month)
    seconds_left = int(
        (datetime(now.year, now.month, last_day, 23, 59, 59, tzinfo=timezone.utc) - now).total_seconds()
    )
    await redis.incrby(keys["monthly_key"], total)
    # Expire at end of current month; add 1 hour buffer for clock skew
    await redis.expire(keys["monthly_key"], max(seconds_left + 3600, 3600))
