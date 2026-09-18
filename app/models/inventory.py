"""
AI inventory: auto-discovered catalog of providers, models, calling apps, and
browser-extension installations.

There was no inventory at all before this — a governance proxy that can't
list what it's actually governing. Rows here are upserted from observed
traffic (audit_service.log_transaction for providers/models/apps, the
extension heartbeat for installations), not hand-entered, so the catalog
reflects reality (including unsanctioned "shadow AI") rather than what admins
remembered to register.
"""
import uuid
from sqlalchemy import Column, String, Boolean, TIMESTAMP, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from app.db.database import Base


class AIProvider(Base):
    __tablename__ = "ai_providers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False)
    first_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)


class AIModel(Base):
    __tablename__ = "ai_models"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider_id = Column(UUID(as_uuid=True), ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    # Governance flag, not a pricing/routing input — cost_calculator.py stays the
    # single source of truth for pricing (see CLAUDE.md). This only marks
    # whether the model is approved for use once discovered in traffic.
    is_sanctioned = Column(Boolean, default=True, nullable=False)
    first_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("provider_id", "name", name="uq_model_provider_name"),)


class AIApp(Base):
    """A calling application (JWT ``app_source``), auto-registered from traffic."""
    __tablename__ = "ai_apps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    app_source = Column(String(100), nullable=False)
    category = Column(String(50), nullable=True)
    is_sanctioned = Column(Boolean, default=True, nullable=False)
    first_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("org_id", "app_source", name="uq_app_org_source"),)


class BrowserInstallation(Base):
    """One browser-extension install, tracked via its heartbeat (device_id)."""
    __tablename__ = "browser_installations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String(255), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    extension_version = Column(String(50), nullable=True)
    first_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("org_id", "device_id", name="uq_device_org_id"),)
