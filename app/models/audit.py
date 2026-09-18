import uuid
from sqlalchemy import Column, String, Integer, BigInteger, Boolean, Numeric, TIMESTAMP, Text, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
from app.db.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    industry_type = Column(String(50), nullable=False)
    monthly_token_budget = Column(BigInteger, default=1_000_000)
    requests_per_second_limit = Column(Integer, default=10)
    allowed_models = Column(ARRAY(Text), default=["gpt-4o-mini"])
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    api_keys = relationship("APIKey", back_populates="organization")
    transactions = relationship("Transaction", back_populates="organization")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False)
    label = Column(String(100))
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="api_keys")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    app_source = Column(String(100))
    model_requested = Column(String(100))
    model_used = Column(String(100))
    provider = Column(String(50))
    prompt_hash = Column(String(64), index=True)
    pii_detected = Column(JSONB, default=list)
    response_pii_detected = Column(JSONB, default=list)
    input_tokens = Column(Integer)
    output_tokens = Column(Integer)
    cost_usd = Column(Numeric(10, 8))
    compliance_status = Column(String(20), default="pass")
    guardrail_triggered = Column(String(100))
    latency_ms = Column(Integer)
    industry_type = Column(String(50))
    routing_reason = Column(String(100))
    # Resolved User row for the caller (see app/models/identity.py). Nullable:
    # identity resolution is best-effort/fail-open, so a DB hiccup there must
    # never block or fail-close the audit write itself.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    # Raw X-VisorShield-User value, kept even if user_id resolution failed —
    # "who made this call" must survive an identity-service outage.
    external_user_id = Column(String(255), nullable=True)
    # Tamper-evident hash chain (see app/services/audit_integrity.py). Set by
    # the application at write time, never by the DB, so the hash can commit
    # to created_at deterministically before the row exists.
    chain_seq = Column(BigInteger, nullable=False)
    prev_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=False)
    # Application-generated (not server_default) so it can be included in the
    # hash committed to record_hash before the row is inserted.
    created_at = Column(TIMESTAMP(timezone=True), nullable=False)

    organization = relationship("Organization", back_populates="transactions")

    __table_args__ = (UniqueConstraint("org_id", "chain_seq", name="uq_transaction_org_chain_seq"),)


class GuardrailIncident(Base):
    __tablename__ = "guardrail_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    # Soft reference: transaction may not be committed before incident is logged (fire-and-forget)
    transaction_id = Column(UUID(as_uuid=True), nullable=True)
    policy_profile = Column(String(50))
    violation_category = Column(String(100))
    detection_layer = Column(String(20))
    prompt_hash = Column(String(64))
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)


class AuditChainState(Base):
    """
    One row per org: the tip of that org's transactions hash chain. Locked via
    ``SELECT ... FOR UPDATE`` when appending (see audit_integrity.py) so
    concurrent fire-and-forget audit writes for the same org serialize instead
    of racing on prev_hash, which would silently fork the chain.
    """
    __tablename__ = "audit_chain_state"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    last_seq = Column(BigInteger, nullable=False, default=0)
    last_hash = Column(String(64), nullable=True)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
