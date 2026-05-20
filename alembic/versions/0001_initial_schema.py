"""Initial schema — organizations, api_keys, transactions, guardrail_incidents

Revision ID: 0001
Revises:
Create Date: 2026-05-15 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("industry_type", sa.String(50), nullable=False),
        sa.Column("monthly_token_budget", sa.BigInteger(), server_default="1000000"),
        sa.Column("requests_per_second_limit", sa.Integer(), server_default="10"),
        sa.Column("allowed_models", postgresql.ARRAY(sa.Text()), server_default=sa.text("ARRAY['gpt-4o-mini']::text[]")),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE")),
        sa.Column("key_hash", sa.String(255), unique=True, nullable=False),
        sa.Column("label", sa.String(100)),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "transactions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("app_source", sa.String(100)),
        sa.Column("model_requested", sa.String(100)),
        sa.Column("model_used", sa.String(100)),
        sa.Column("provider", sa.String(50)),
        sa.Column("prompt_hash", sa.String(64)),
        sa.Column("pii_detected", postgresql.JSONB(), server_default="'[]'"),
        sa.Column("response_pii_detected", postgresql.JSONB(), server_default="'[]'"),
        sa.Column("input_tokens", sa.Integer()),
        sa.Column("output_tokens", sa.Integer()),
        sa.Column("cost_usd", sa.Numeric(10, 8)),
        sa.Column("compliance_status", sa.String(20), server_default="'pass'"),
        sa.Column("guardrail_triggered", sa.String(100)),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("industry_type", sa.String(50)),
        sa.Column("routing_reason", sa.String(100)),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "guardrail_incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("transaction_id", postgresql.UUID(as_uuid=True)),
        sa.Column("policy_profile", sa.String(50)),
        sa.Column("violation_category", sa.String(100)),
        sa.Column("detection_layer", sa.String(20)),
        sa.Column("prompt_hash", sa.String(64)),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_index("idx_transactions_org_id", "transactions", ["org_id"])
    op.create_index("idx_transactions_created_at", "transactions", ["created_at"])
    op.create_index("idx_transactions_compliance_status", "transactions", ["compliance_status"])
    op.create_index("idx_transactions_prompt_hash", "transactions", ["prompt_hash"])
    op.create_index("idx_guardrail_org_id", "guardrail_incidents", ["org_id"])


def downgrade() -> None:
    op.drop_index("idx_guardrail_org_id", table_name="guardrail_incidents")
    op.drop_index("idx_transactions_prompt_hash", table_name="transactions")
    op.drop_index("idx_transactions_compliance_status", table_name="transactions")
    op.drop_index("idx_transactions_created_at", table_name="transactions")
    op.drop_index("idx_transactions_org_id", table_name="transactions")
    op.drop_table("guardrail_incidents")
    op.drop_table("transactions")
    op.drop_table("api_keys")
    op.drop_table("organizations")
