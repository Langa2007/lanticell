-- Lanticell Phase 2 WAF & Security Events Schema

CREATE TABLE IF NOT EXISTS waf_policies (
    site_id UUID PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'monitor' CHECK (mode IN ('off', 'monitor', 'block')),
    crs_version TEXT NOT NULL DEFAULT '4.10.0',
    max_inspect_body_bytes BIGINT NOT NULL DEFAULT 131072,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_exclusions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    route_prefix TEXT NOT NULL DEFAULT '/',
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_version TEXT NOT NULL DEFAULT '1.0',
    correlation_id TEXT NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    route TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    crs_version TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('allow', 'observe', 'block')),
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_exclusions_site ON waf_exclusions(site_id);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_created ON security_events(tenant_id, created_at DESC);
