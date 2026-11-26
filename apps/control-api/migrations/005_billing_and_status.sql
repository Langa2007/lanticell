-- Lanticell Phase 5 Billing Plans, Usage Metering & Status Page Schema

CREATE TABLE IF NOT EXISTS tenant_plans (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    plan_tier TEXT NOT NULL DEFAULT 'pilot' CHECK (plan_tier IN ('pilot', 'growth', 'enterprise')),
    monthly_request_limit BIGINT NOT NULL DEFAULT 5000000,
    max_sites INTEGER NOT NULL DEFAULT 3,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS usage_records (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_month TEXT NOT NULL, -- YYYY-MM
    inspected_requests BIGINT NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,
    bytes_inspected BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, period_month)
);

CREATE TABLE IF NOT EXISTS status_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('minor', 'major', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
    summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
