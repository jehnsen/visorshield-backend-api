"""
Auto-discovery of the AI inventory (providers, models, calling apps, browser
installations) from observed traffic — see app/models/inventory.py for why
this is upserted rather than hand-curated.

Best-effort throughout: a failure here must never break the audit write or
the heartbeat response it rides along with.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal

log = structlog.get_logger()


async def record_provider_model_usage(provider: str, model: str) -> None:
    """Upsert the (provider, model) pair seen on a completed/attempted transaction."""
    if not provider or not model:
        return
    try:
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as session:
            provider_row = (
                await session.execute(
                    text(
                        "INSERT INTO ai_providers (id, name, first_seen_at, last_seen_at) "
                        "VALUES (gen_random_uuid(), :name, :now, :now) "
                        "ON CONFLICT (name) DO UPDATE SET last_seen_at = :now "
                        "RETURNING id"
                    ),
                    {"name": provider, "now": now},
                )
            ).one()
            await session.execute(
                text(
                    "INSERT INTO ai_models (id, provider_id, name, first_seen_at, last_seen_at) "
                    "VALUES (gen_random_uuid(), :provider_id, :name, :now, :now) "
                    "ON CONFLICT (provider_id, name) DO UPDATE SET last_seen_at = :now"
                ),
                {"provider_id": str(provider_row.id), "name": model, "now": now},
            )
            await session.commit()
    except Exception as exc:
        log.warning("inventory_model_upsert_failed", error=str(exc), provider=provider, model=model)


async def record_app_usage(org_id: str, app_source: str) -> None:
    """Upsert the calling app seen on a transaction for this org."""
    if not app_source:
        return
    try:
        org_uuid = uuid.UUID(org_id)
    except (ValueError, TypeError, AttributeError):
        return
    try:
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as session:
            await session.execute(
                text(
                    "INSERT INTO ai_apps (id, org_id, app_source, first_seen_at, last_seen_at) "
                    "VALUES (gen_random_uuid(), :org_id, :app_source, :now, :now) "
                    "ON CONFLICT (org_id, app_source) DO UPDATE SET last_seen_at = :now"
                ),
                {"org_id": str(org_uuid), "app_source": app_source, "now": now},
            )
            await session.commit()
    except Exception as exc:
        log.warning("inventory_app_upsert_failed", error=str(exc), org_id=org_id, app_source=app_source)


async def record_browser_installation(
    org_id: str, device_id: str, extension_version: Optional[str], user_id: Optional[str]
) -> None:
    """Upsert a browser-extension installation seen on a heartbeat."""
    if not device_id:
        return
    try:
        org_uuid = uuid.UUID(org_id)
    except (ValueError, TypeError, AttributeError):
        return
    try:
        user_uuid = uuid.UUID(user_id) if user_id else None
    except (ValueError, TypeError):
        user_uuid = None
    try:
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as session:
            await session.execute(
                text(
                    "INSERT INTO browser_installations "
                    "(id, org_id, device_id, user_id, extension_version, first_seen_at, last_seen_at) "
                    "VALUES (gen_random_uuid(), :org_id, :device_id, :user_id, :ext_version, :now, :now) "
                    "ON CONFLICT (org_id, device_id) DO UPDATE SET "
                    "last_seen_at = :now, user_id = COALESCE(:user_id, browser_installations.user_id), "
                    "extension_version = COALESCE(:ext_version, browser_installations.extension_version)"
                ),
                {
                    "org_id": str(org_uuid),
                    "device_id": device_id,
                    "user_id": str(user_uuid) if user_uuid else None,
                    "ext_version": extension_version,
                    "now": now,
                },
            )
            await session.commit()
    except Exception as exc:
        log.warning("inventory_device_upsert_failed", error=str(exc), org_id=org_id, device_id=device_id)
