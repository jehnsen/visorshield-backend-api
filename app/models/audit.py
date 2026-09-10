import uuid
from sqlalchemy import Column, String, Integer, BigInteger, Boolean, Numeric, TIMESTAMP, Text, ForeignKey, func
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
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="transactions")


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
