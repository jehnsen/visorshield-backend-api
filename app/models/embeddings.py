import uuid
from sqlalchemy import Column, String, UniqueConstraint, TIMESTAMP, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from pgvector.sqlalchemy import Vector
from app.db.database import Base

VECTOR_DIMS = 384  # paraphrase-MiniLM-L6-v2 output dimension


class PolicyEmbedding(Base):
    """Per-org guardrail topic embeddings stored in pgvector for dynamic policy management."""
    __tablename__ = "policy_embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    policy_profile = Column(String(50), nullable=False)
    topic = Column(String(255), nullable=False)
    embedding = Column(Vector(VECTOR_DIMS), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "policy_profile", "topic", name="uq_org_policy_topic"),
    )
