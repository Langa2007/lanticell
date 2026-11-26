-- Lanticell Phase 4 API Security & Adaptive Policies Schema

CREATE TABLE IF NOT EXISTS route_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    path_pattern TEXT NOT NULL,
    methods TEXT[] NOT NULL DEFAULT ARRAY['GET', 'POST']::TEXT[],
    route_type TEXT NOT NULL DEFAULT 'api' CHECK (route_type IN ('public', 'login', 'auth_otp', 'checkout', 'search', 'api', 'webhook')),
    rate_limit_rps INTEGER NOT NULL DEFAULT 30,
    action_override TEXT NOT NULL DEFAULT 'inherit' CHECK (action_override IN ('inherit', 'allow', 'observe', 'rate_limit', 'block')),
    service_allowlist_cidrs TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    webhook_sig_header TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    endpoints_json JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, version)
);

CREATE TABLE IF NOT EXISTS api_inventory (
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    normalized_path TEXT NOT NULL,
    documented BOOLEAN NOT NULL DEFAULT FALSE,
    hit_count BIGINT NOT NULL DEFAULT 1,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (site_id, method, normalized_path)
);

CREATE INDEX IF NOT EXISTS idx_route_policies_site ON route_policies(site_id);
CREATE INDEX IF NOT EXISTS idx_api_inventory_site_undoc ON api_inventory(site_id, documented);
