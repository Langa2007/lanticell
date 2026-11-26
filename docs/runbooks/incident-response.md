# Incident Response & On-Call Runbook

## 1. Severity Levels
- **SEV-1 (Critical):** Gateway outage, cross-tenant data exposure, or widespread false-positive blocking across multiple tenants. Acknowledge in 15 minutes.
- **SEV-2 (High):** Control-plane outage (data-plane gateways continue serving last-known-good config), `botd` outage, or single-tenant misrouting.
- **SEV-3 (Medium):** Delayed telemetry/events or degraded dashboard latency.

## 2. Immediate Containment
1. If a bad policy/WAF/schema rollout causes false positives, roll back the site's WAF mode to `monitor` or Bot mode to `observe`, or roll back the OpenAPI schema version.
2. If `control-api` is unreachable, verify gateways retain `/var/lib/lanticell/last-good/bundle.json` and do **not** restart NGINX with an empty `conf.d`.
3. Post an update to the customer status endpoint (`POST /api/v1/operator/incidents`) within 30 minutes for SEV-1/SEV-2.

## 3. Backup & Restore Drill Checklist
- Run `scripts/ops/backup-postgres.sh` daily with encrypted off-host storage.
- Run monthly restore verification (`scripts/ops/restore-postgres.sh`) into an isolated staging database and verify row counts and tenant isolation tests pass.
