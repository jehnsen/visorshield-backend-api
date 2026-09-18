"""Add identity model (users/departments/groups), AI inventory
(providers/models/apps/browser installations), and audit hash-chain +
append-only enforcement on transactions/guardrail_incidents.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-16 00:00:00.000000

"""
import hashlib
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Frozen copy of the hashing rules in app/services/audit_integrity.py, used
# only to backfill chain links for rows that predate this migration.
# Migrations must not depend on application code that can change shape later.
def _canon_cost(cost_usd) -> str:
    if cost_usd is None:
        return "0.00000000"
    return f"{float(cost_usd):.8f}"


def _hash_link(prev_hash, fields) -> str:
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256((prev_hash or "genesis").encode() + b"|" + payload).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()

    # ── Identity: departments, groups, users, memberships ──────────────────
    op.create_table(
        "departments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_department_org_name"),
    )

    op.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_group_org_name"),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255)),
        sa.Column("display_name", sa.String(255)),
        sa.Column("department_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("departments.id", ondelete="SET NULL")),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("org_id", "external_id", name="uq_user_org_external_id"),
    )
    op.create_index("idx_users_org_id", "users", ["org_id"])

    op.create_table(
        "user_group_memberships",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("group_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )

    # ── AI inventory: providers, models, apps, browser installations ───────
    op.create_table(
        "ai_providers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(50), nullable=False, unique=True),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )

    op.create_table(
        "ai_models",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("provider_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("is_sanctioned", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("provider_id", "name", name="uq_model_provider_name"),
    )

    op.create_table(
        "ai_apps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("app_source", sa.String(100), nullable=False),
        sa.Column("category", sa.String(50)),
        sa.Column("is_sanctioned", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("org_id", "app_source", name="uq_app_org_source"),
    )

    op.create_table(
        "browser_installations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("extension_version", sa.String(50)),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("org_id", "device_id", name="uq_device_org_id"),
    )

    # ── Audit chain tip (one row per org) ───────────────────────────────────
    op.create_table(
        "audit_chain_state",
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("last_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_hash", sa.String(64)),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )

    # ── transactions: identity + hash-chain columns ────────────────────────
    op.add_column("transactions", sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True))
    op.add_column("transactions", sa.Column("external_user_id", sa.String(255), nullable=True))
    op.add_column("transactions", sa.Column("chain_seq", sa.BigInteger(), nullable=True))
    op.add_column("transactions", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("transactions", sa.Column("record_hash", sa.String(64), nullable=True))
    op.create_index("idx_transactions_user_id", "transactions", ["user_id"])

    # created_at becomes application-generated (see Transaction model) so it
    # can be committed to record_hash before the row exists. Drop the DB-level
    # default so a future INSERT that forgets to set it fails loudly (NOT
    # NULL) instead of silently taking NOW() and mismatching its own hash.
    op.alter_column("transactions", "created_at", server_default=None)

    # ── Backfill: chain any transactions that predate this migration ───────
    rows = bind.execute(
        text(
            "SELECT id, org_id, app_source, model_requested, model_used, provider, "
            "prompt_hash, pii_detected, response_pii_detected, input_tokens, output_tokens, "
            "cost_usd, compliance_status, guardrail_triggered, latency_ms, industry_type, "
            "routing_reason, created_at FROM transactions ORDER BY org_id, created_at, id"
        )
    ).fetchall()

    chain_state: dict = {}  # org_id (str) -> (last_seq, last_hash)
    for row in rows:
        org_id = str(row.org_id)
        seq, prev_hash = chain_state.get(org_id, (0, None))
        seq += 1
        fields = {
            "id": str(row.id),
            "org_id": org_id,
            "app_source": row.app_source or "",
            "model_requested": row.model_requested or "",
            "model_used": row.model_used or "",
            "provider": row.provider or "",
            "prompt_hash": row.prompt_hash or "",
            "pii_detected": sorted(row.pii_detected or []),
            "response_pii_detected": sorted(row.response_pii_detected or []),
            "input_tokens": int(row.input_tokens or 0),
            "output_tokens": int(row.output_tokens or 0),
            "cost_usd": _canon_cost(row.cost_usd),
            "compliance_status": row.compliance_status or "",
            "guardrail_triggered": row.guardrail_triggered or "",
            "latency_ms": int(row.latency_ms or 0),
            "industry_type": row.industry_type or "",
            "routing_reason": row.routing_reason or "",
            "user_id": "",
            "external_user_id": "",
            "created_at": row.created_at.isoformat() if row.created_at else "",
        }
        record_hash = _hash_link(prev_hash, fields)
        bind.execute(
            text("UPDATE transactions SET chain_seq = :seq, prev_hash = :prev, record_hash = :hash WHERE id = :id"),
            {"seq": seq, "prev": prev_hash, "hash": record_hash, "id": row.id},
        )
        chain_state[org_id] = (seq, record_hash)

    for org_id, (seq, last_hash) in chain_state.items():
        bind.execute(
            text(
                "INSERT INTO audit_chain_state (org_id, last_seq, last_hash) VALUES (:org_id, :seq, :hash) "
                "ON CONFLICT (org_id) DO UPDATE SET last_seq = :seq, last_hash = :hash"
            ),
            {"org_id": org_id, "seq": seq, "hash": last_hash},
        )

    op.alter_column("transactions", "chain_seq", nullable=False)
    op.alter_column("transactions", "record_hash", nullable=False)
    op.create_unique_constraint("uq_transaction_org_chain_seq", "transactions", ["org_id", "chain_seq"])

    # ── Append-only (WORM) enforcement ──────────────────────────────────────
    # DB-level, not just application convention: a trigger fires regardless of
    # which role/credential issues the UPDATE/DELETE. This does not survive a
    # superuser dropping the trigger — the same boundary standard Postgres
    # audit-trigger extensions accept — but it does close the actual gap
    # (routine admin access, or a compromised app credential, editing history).
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit records are append-only and cannot be % (table: %)', TG_OP, TG_TABLE_NAME;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER trg_transactions_append_only "
        "BEFORE UPDATE OR DELETE ON transactions "
        "FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation()"
    )
    op.execute(
        "CREATE TRIGGER trg_guardrail_incidents_append_only "
        "BEFORE UPDATE OR DELETE ON guardrail_incidents "
        "FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_guardrail_incidents_append_only ON guardrail_incidents")
    op.execute("DROP TRIGGER IF EXISTS trg_transactions_append_only ON transactions")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_mutation()")

    op.drop_constraint("uq_transaction_org_chain_seq", "transactions", type_="unique")
    op.drop_index("idx_transactions_user_id", table_name="transactions")
    op.drop_column("transactions", "record_hash")
    op.drop_column("transactions", "prev_hash")
    op.drop_column("transactions", "chain_seq")
    op.drop_column("transactions", "external_user_id")
    op.drop_column("transactions", "user_id")
    op.alter_column("transactions", "created_at", server_default=sa.text("NOW()"))

    op.drop_table("audit_chain_state")
    op.drop_table("browser_installations")
    op.drop_table("ai_apps")
    op.drop_table("ai_models")
    op.drop_table("ai_providers")

    op.drop_table("user_group_memberships")
    op.drop_index("idx_users_org_id", table_name="users")
    op.drop_table("users")
    op.drop_table("groups")
    op.drop_table("departments")
