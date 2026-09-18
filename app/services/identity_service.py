"""
Resolves the ``X-VisorShield-User`` header into a tracked User row.

Best-effort by design: identity resolution is an enrichment for FinOps and
identity-aware policy ("who is using which AI service"), not a security gate.
The org/API-key active check in auth.py is the actual gate and stays
fail-closed; a DB hiccup here degrades to an unresolved identity (user_id is
None, external_user_id is still recorded) rather than blocking the request.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import text

from app.db.database import AsyncSessionLocal

log = structlog.get_logger()


async def get_or_create_user(org_id: str, external_id: str) -> Optional[dict]:
    """
    Get-or-create the User row for (org_id, external_id), touching
    last_seen_at, and return its id + department_id.

    Uses a raw upsert (INSERT ... ON CONFLICT) rather than SELECT-then-INSERT
    so two concurrent first-time requests from the same caller can't race
    into a duplicate-row IntegrityError.
    """
    try:
        org_uuid = uuid.UUID(org_id)
    except (ValueError, TypeError, AttributeError):
        return None

    try:
        async with AsyncSessionLocal() as session:
            now = datetime.now(timezone.utc)
            row = (
                await session.execute(
                    text(
                        "INSERT INTO users (id, org_id, external_id, first_seen_at, last_seen_at) "
                        "VALUES (gen_random_uuid(), :org_id, :external_id, :now, :now) "
                        "ON CONFLICT (org_id, external_id) "
                        "DO UPDATE SET last_seen_at = :now "
                        "RETURNING id, department_id"
                    ),
                    {"org_id": str(org_uuid), "external_id": external_id, "now": now},
                )
            ).one()
            await session.commit()
            return {
                "id": str(row.id),
                "department_id": str(row.department_id) if row.department_id else None,
            }
    except Exception as exc:
        log.warning(
            "identity_lookup_failed",
            error=str(exc),
            org_id=org_id,
            pipeline_step="auth",
        )
        return None
