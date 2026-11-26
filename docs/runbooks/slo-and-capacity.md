# SLOs, Capacity Limits & Pre-Launch Pentest Gate

## Service Level Objectives (Pilot Targets)
- **Gateway Data-Plane Availability:** 99.9% monthly uptime (multi-zone deployment).
- **Gateway Added Latency (`botd` + proxy overhead):** p95 <= 15 ms (fail-open to `observe` on `botd` timeout).
- **Config Propagation Time:** <= 15 s from publish to gateway reload.
- **Security Event Delivery:** <= 30 s under normal load; bounded async drops under saturation.

## Pre-Launch Security & Pentest Checklist
- [ ] Independent penetration test covering tenant isolation, RBAC, origin secret handling, and WAF/bot bypasses.
- [ ] All `CRITICAL` and `HIGH` findings from `govulncheck` and `trivy` resolved.
- [ ] Restore, config rollback, and control-plane-outage drills completed and signed off.
- [ ] On-call rotation and support escalation contacts staffed.
