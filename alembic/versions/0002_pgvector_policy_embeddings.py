"""Add pgvector extension and policy_embeddings table for per-org guardrail topics

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-15 00:01:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# paraphrase-MiniLM-L6-v2 output dimension
VECTOR_DIMS = 384


def upgrade() -> None:
    # Enable pgvector — requires pgvector installed in PostgreSQL
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "policy_embeddings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_profile", sa.String(50), nullable=False),
        sa.Column("topic", sa.String(255), nullable=False),
        # vector(384) — stored as pgvector type
        sa.Column("embedding", sa.Text(), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()")),
        sa.UniqueConstraint("org_id", "policy_profile", "topic", name="uq_org_policy_topic"),
    )

    # Rewrite the embedding column to the actual vector type using raw DDL
    op.execute(f"ALTER TABLE policy_embeddings ALTER COLUMN embedding TYPE vector({VECTOR_DIMS}) USING embedding::vector({VECTOR_DIMS})")

    op.create_index("idx_policy_embeddings_org_policy", "policy_embeddings", ["org_id", "policy_profile"])

    # IVFFlat index for fast approximate nearest-neighbour cosine search
    op.execute(
        "CREATE INDEX idx_policy_embeddings_ivfflat "
        "ON policy_embeddings USING ivfflat (embedding vector_cosine_ops) "
        "WITH (lists = 10)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_policy_embeddings_ivfflat")
    op.drop_index("idx_policy_embeddings_org_policy", table_name="policy_embeddings")
    op.drop_table("policy_embeddings")
    op.execute("DROP EXTENSION IF EXISTS vector")
