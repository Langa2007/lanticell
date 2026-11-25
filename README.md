# Lanticell

**An API-first web and application security platform built for African businesses and designed for global scale.**

Lanticell is a security gateway and control platform that helps protect websites, web applications, and APIs against malicious traffic, common web exploits, automated abuse, and evolving attack patterns.

The platform combines proven open-source infrastructure with a product-owned control plane, security policy system, telemetry pipeline, and **behavior-based bot and API abuse detection**.

> **Security and scope statement:** Lanticell is a defense-in-depth platform, not a guarantee that an application is invulnerable. Protection depends on deployment topology, upstream network capacity, origin lockdown, correct configuration, and ongoing operations. Network-layer volumetric DDoS mitigation requires capable transit, peering, or scrubbing partners; an application gateway alone cannot absorb traffic that saturates its upstream link.

## Vision

Make dependable application security accessible to African developers and businesses, then expand globally through a reliable, developer-friendly protection network.

## Product principles

- **Bot detection is a core differentiator:** detect behavior and abuse context, not only static IP lists or user-agent strings.
- **Secure by default, observable always:** begin in monitor mode where appropriate; explain decisions and support safe policy rollout.
- **Modular detection:** versioned rules and detector plugins allow new attack classes to be added without redesigning the platform.
- **Fail safely and deliberately:** define behavior for gateway, policy, control-plane, and telemetry failures.
- **Privacy-aware intelligence:** minimize collected data, define retention, protect tenant isolation, and avoid sharing raw customer data by default.
- **Open-source foundations, owned product:** use maintained components while owning onboarding, policy orchestration, analytics, bot intelligence, customer experience, and operations.
- **No unsupported claims:** publish tested limits and clear coverage boundaries.

## Initial threat coverage

| Threat | Initial defense |
|---|---|
| SQL injection | WAF rules, request normalization, application secure-coding guidance |
| Cross-site scripting (XSS) | WAF rules, output-encoding guidance, CSP support |
| Path traversal and common protocol attacks | WAF rules and normalization |
| HTTP floods / abusive request rates | Rate limits, behavior-based detection, upstream capacity |
| Credential stuffing / account abuse | API and session behavior signals, endpoint-specific policies |
| Scraping and automated abuse | Bot scoring, challenge/deny/allow policies |
| API misuse | Schema/endpoint policies, quotas, authentication-aware signals where integrated |
| Volumetric L3/L4 DDoS | Partner-assisted mitigation and network architecture; not solved by the MVP gateway alone |

WAF protection is not a substitute for parameterized SQL queries, output encoding, secure authentication, authorization, patching, or application-level validation.

## Architecture overview

```text
Clients / browsers / mobile apps / API consumers
                    |
             DNS / edge routing
                    |
     Network / DDoS partner (as deployed)
                    |
          Lanticell gateway fleet
       + TLS + reverse proxy + WAF
       + rate limits + bot decision engine
                    |
             Protected origin
                    |
      Events / metrics / security decisions
                    |
       Telemetry pipeline -> analytics store
                    |
    Control plane -> policy/config distribution
                    |
      Customer dashboard / API / alerts
```

### Control plane and data plane

- **Control plane:** tenants, sites, policies, onboarding, billing integration, configuration publishing, analytics queries, and dashboard.
- **Data plane:** gateways that inspect and route requests. Gateways should continue enforcing their last known valid configuration if the control plane is temporarily unavailable.
- **Telemetry plane:** bounded, asynchronous event delivery. Telemetry failure should not cause unbounded memory growth or unnecessarily stop request processing.

## Technology baseline

| Area | Initial choice |
|---|---|
| Gateway / reverse proxy | NGINX initially; evaluate Envoy when requirements justify it |
| WAF | Coraza |
| WAF rules | OWASP Core Rule Set (CRS) |
| Control-plane API | Go |
| Bot detection | Go modular detector pipeline; rules first, statistical scoring next |
| Control-plane database | PostgreSQL |
| Hot-path bot state | In-memory bounded counters (single-node MVP); Redis / Valkey (multi-node) |
| L3/L4/DDoS baseline | NGINX connection/rate limits + CrowdSec + `nftables` (`eBPF/XDP` later) |
| Dashboard | Vue 3 + Vite + JavaScript |
| Telemetry / metrics | Prometheus + Grafana; structured logs |
| Event analytics | Begin with PostgreSQL or a bounded log pipeline; add ClickHouse when volume warrants |
| Deployment | Docker Compose for development; hardened Linux hosts / orchestrated deployment later |
| Testing | Go tests, integration tests, replay corpus, load tests, security regression tests |

Choose one gateway for the MVP. Do not operate NGINX and Envoy in parallel unless there is a clear requirement.

## Repository documentation

- [`phases.md`](phases.md) — phased product and engineering roadmap
- [`structure.md`](structure.md) — proposed monorepo layout and languages
- [`technical.md`](technical.md) — detailed architecture, detection, policy, security, and operations

## MVP success criteria

The MVP is ready for controlled pilot use when:

1. A customer can onboard a domain and configure an origin securely.
2. TLS and reverse proxying work reliably.
3. Coraza + CRS detect known test attacks with documented false-positive handling.
4. Monitor and block modes are available and auditable.
5. Rate limits and basic bot scoring are enforced consistently.
6. A gateway uses its last valid configuration during control-plane outages.
7. Tenant data and policy boundaries are tested.
8. The origin can be restricted to gateway traffic.
9. Logs, metrics, alerts, backups, and incident procedures exist.
10. Load and failure testing establish honest capacity limits.

## Development status

This document describes the proposed architecture and roadmap. It does not claim that the platform is already implemented, audited, production-ready, or capable of mitigating attacks beyond its tested deployment capacity.

## Security

Please report vulnerabilities through the project's private security contact or security policy once configured. Do not publish exploit details for an unpatched production deployment.

## License

Select and publish a project license before public release. Review the licenses of every dependency and any bundled rules or data separately.
