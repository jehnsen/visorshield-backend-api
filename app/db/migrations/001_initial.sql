CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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

CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
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
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE guardrail_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    transaction_id UUID,
    policy_profile VARCHAR(50),
    violation_category VARCHAR(100),
    detection_layer VARCHAR(20),
    prompt_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_transactions_org_id ON transactions(org_id);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_transactions_compliance_status ON transactions(compliance_status);
CREATE INDEX idx_guardrail_org_id ON guardrail_incidents(org_id);
