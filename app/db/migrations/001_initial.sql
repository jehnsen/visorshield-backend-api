-- Legacy schema snapshot — alembic/versions/ is authoritative for actual
-- migrations (see CLAUDE.md). This file is a consolidated, manually-applied
-- reference equivalent to `alembic upgrade head` (currently 0001 + 0002
-- pgvector_policy_embeddings + 0003 identity_inventory_audit_integrity),
-- kept for anyone bootstrapping a database without Alembic. If you add a
-- migration, update this file to match or it stops being a snapshot.
--
-- Requires the pgvector extension in the Postgres image (the
-- pgvector/pgvector:pg16 image used in docker-compose.yml has it
-- preinstalled).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- ── Core: organizations, api_keys ───────────────────────────────────────────

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    industry_type VARCHAR(50) NOT NULL,
    monthly_token_budget BIGINT DEFAULT 1000000,
    requests_per_second_limit INTEGER DEFAULT 10,
    allowed_models TEXT[] DEFAULT ARRAY['gpt-4o-mini'],
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    label VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Identity: departments, groups, users, memberships ───────────────────────
-- See CLAUDE.md "Identity Model". Users are auto-provisioned from
-- X-VisorShield-User, never hand-created; departments/groups are admin-curated.

CREATE TABLE departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_department_org_name UNIQUE (org_id, name)
);

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_group_org_name UNIQUE (org_id, name)
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    display_name VARCHAR(255),
    department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_org_external_id UNIQUE (org_id, external_id)
);

CREATE TABLE user_group_memberships (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- ── AI inventory: providers, models, apps, browser installations ───────────
-- All rows here are auto-discovered from observed traffic (see
-- app/services/inventory_service.py) — is_sanctioned is a governance flag
-- only, never a pricing or access-control source (see CLAUDE.md).

CREATE TABLE ai_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    is_sanctioned BOOLEAN NOT NULL DEFAULT true,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_model_provider_name UNIQUE (provider_id, name)
);

CREATE TABLE ai_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    app_source VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    is_sanctioned BOOLEAN NOT NULL DEFAULT true,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_app_org_source UNIQUE (org_id, app_source)
);

CREATE TABLE browser_installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    extension_version VARCHAR(50),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_device_org_id UNIQUE (org_id, device_id)
);

-- ── Guardrails Layer 3: per-org pgvector guardrail topics ──────────────────
-- See CLAUDE.md "Guardrails: Three-Layer Detection". Falls back to the
-- in-process default topics for a policy profile when an org has none here.

CREATE TABLE policy_embeddings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_profile VARCHAR(50) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    embedding VECTOR(384) NOT NULL, -- paraphrase-MiniLM-L6-v2 output dimension
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_org_policy_topic UNIQUE (org_id, policy_profile, topic)
);

-- ── Audit: transactions, guardrail_incidents, hash-chain tip ───────────────
-- See CLAUDE.md "Audit Integrity". created_at is application-generated (no
-- server default) so it can be committed to record_hash before the row
-- exists — the app always sets it explicitly (audit_service.log_transaction).

CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    app_source VARCHAR(100),
    model_requested VARCHAR(100),
    model_used VARCHAR(100),
    provider VARCHAR(50),
    prompt_hash VARCHAR(64),
    pii_detected JSONB DEFAULT '[]',
    response_pii_detected JSONB DEFAULT '[]',
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd NUMERIC(10, 8),
    compliance_status VARCHAR(20) DEFAULT 'pass',
    guardrail_triggered VARCHAR(100),
    latency_ms INTEGER,
    industry_type VARCHAR(50),
    routing_reason VARCHAR(100),
    -- Identity (see app/models/identity.py) — user_id is nullable because
    -- identity resolution fails open; external_user_id is the raw header
    -- value and survives even when user_id resolution failed.
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    external_user_id VARCHAR(255),
    -- Tamper-evident hash chain (see app/services/audit_integrity.py).
    chain_seq BIGINT NOT NULL,
    prev_hash VARCHAR(64),
    record_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_transaction_org_chain_seq UNIQUE (org_id, chain_seq)
);

CREATE TABLE guardrail_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    transaction_id UUID,
    policy_profile VARCHAR(50),
    violation_category VARCHAR(100),
    detection_layer VARCHAR(20),
    prompt_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE audit_chain_state (
    org_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    last_seq BIGINT NOT NULL DEFAULT 0,
    last_hash VARCHAR(64),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Indexes ──────────────────────────────────────────────────────────────

CREATE INDEX idx_transactions_org_id ON transactions(org_id);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_transactions_compliance_status ON transactions(compliance_status);
CREATE INDEX idx_transactions_prompt_hash ON transactions(prompt_hash);
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_guardrail_org_id ON guardrail_incidents(org_id);
CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_policy_embeddings_org_policy ON policy_embeddings(org_id, policy_profile);

-- ivfflat cosine index for the per-org guardrail ANN search (Layer 3).
-- `lists = 10` matches alembic/versions/0002_pgvector_policy_embeddings.py —
-- tune for larger topic sets per pgvector's own sizing guidance.
CREATE INDEX idx_policy_embeddings_ivfflat
    ON policy_embeddings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

-- ── Append-only (WORM) enforcement on audit tables ──────────────────────────
-- DB-level, not just application convention — fires regardless of which
-- role/credential issues the statement. See CLAUDE.md "Audit Integrity" for
-- the accepted boundary (does not survive a superuser dropping the trigger).

CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit records are append-only and cannot be % (table: %)', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_transactions_append_only
    BEFORE UPDATE OR DELETE ON transactions
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

CREATE TRIGGER trg_guardrail_incidents_append_only
    BEFORE UPDATE OR DELETE ON guardrail_incidents
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
