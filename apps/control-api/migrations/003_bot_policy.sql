-- Lanticell Phase 3 Bot Detection Policy Schema

CREATE TABLE IF NOT EXISTS bot_policies (
    site_id UUID PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'observe' CHECK (mode IN ('off', 'observe', 'enforce')),
    challenge_difficulty INTEGER NOT NULL DEFAULT 3 CHECK (challenge_difficulty BETWEEN 1 AND 6),
    allowlisted_bots TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
