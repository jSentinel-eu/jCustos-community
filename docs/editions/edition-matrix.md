# jCustos editions

jCustos is open core. Everything a developer needs to secure an application is
free software; the operations and forensics layer is commercial.

**Build & secure is free. Operate & prove is commercial.**

## Community Edition — EUPL 1.2

`eu.jsentinel:jCustos-*` · https://repo.jsentinel.eu/releases (every release, on the day it is
made) and Maven Central (at most once a month); see
[release verification](../security/release-verification.md#resolving-from-repojsentineleu)

Complete and production-ready on its own. Nothing here is time-limited,
feature-gated or nagware.

| Area | Modules |
|---|---|
| Core & decisions | `jCustos-core` |
| Adapters | `jCustos-vaadin`, `jCustos-rest`, `jCustos-standalone` |
| Developer experience | `jCustos-dx`, `jCustos-dx-vaadin`, `jCustos-dx-rest`, `jCustos-dx-standalone`, `jCustos-vaadin-starter` |
| Compile-time tooling | `jCustos-processor`, `jCustos-autoservice-annotations`, `jCustos-autoservice-processor` |
| Credentials & crypto | `jCustos-crypto-bc` (Argon2id, bcrypt, scrypt), `jCustos-credentials-hibp` |
| Persistence | `jCustos-persistence-eclipsestore`, `jCustos-persistence-testkit` |
| Security event bus | `jCustos-events`, `jCustos-events-testkit` |
| Identity | `jCustos-jwt`, `jCustos-oauth2` (+ `-vaadin`, `-rest`), `jCustos-identity-oidc` (+ `-vaadin`, `-rest`), six `jCustos-identity-vendor-*` profiles, `jCustos-dpop` |
| Token propagation | `jCustos-propagation`, `jCustos-propagation-processor`, `jCustos-propagation-oidc` |
| Test support | `jCustos-test`, `jCustos-test-oidc` |
| BOM | `jCustos-bom` |

Signed event envelopes, replay protection, Argon2id hashing and the full OIDC
relying-party stack are security primitives, and security primitives stay free.

## Enterprise Edition — commercial

`eu.jsentinel.jcustos.enterprise:jCustos-*` · https://repo.jsentinel.eu/sensitive
(access is part of the licence)

For teams that must **prove** what their security layer did — auditors,
regulators, a SOC.

| Module | What it gives you |
|---|---|
| `jCustos-monitoring` | Metrics SPI with a `security.*` name catalogue, event-bus bridge, health indicators, saturation warnings |
| `jCustos-audit-integrity` | Tamper-evident audit chain `H(prev‖entry)`, verifier with five distinct break reasons, signed batches, NDJSON export that re-verifies from text plus public keys |
| `jCustos-audit-integrity-persistence-eclipsestore` | Restart-safe chain storage |
| `jCustos-audit-integrity-testkit` | Contract tests for your own chain store |
| `jCustos-events-webhook` | Signed envelopes over HTTPS, bounded queue, retry with backoff and jitter |
| `jCustos-events-siem` | CEF, LEEF 2.0 and NDJSON formatters, vendor-neutral |
| `jCustos-events-opentelemetry` | Export through the OpenTelemetry logs bridge |
| `jCustos-events-rest` | REST/SSE bridge for signed envelopes |
| `jCustos-events-persistence-eclipsestore` | Durable event and replay storage |

Every one of them plugs into community SPIs. The community edition never
references them — a test enforces that.

## Which do I need?

Take the Community Edition if you are securing an application: authentication,
authorisation, OIDC login, password hardening, sessions, audit events.

Add the Enterprise Edition when someone external will ask what happened: an
audit chain that survives scrutiny, exports a SIEM ingests, metrics and health
for the operators.
