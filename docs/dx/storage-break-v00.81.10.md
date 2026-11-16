# V00.81.10 storage break — fresh storage only

The jCustos rebranding (V00.81.10) renamed every persisted class:
packages moved from `com.svenruppert.jsentinel` to `eu.jsentinel.jcustos`
and the `JSentinel*` types became `JCustos*`. Eclipse Store persists fully
qualified class names in its type dictionary, so **storages written by
jSentinel V00.81.00 or earlier cannot be opened by jCustos** — Eclipse
Store fails at `openAt(...)` with unresolvable legacy types.

This is a **deliberate decision** (concept review gate, 2026-08-31):
no legacy type mappings ship. jCustos starts with fresh storages.

## What this affects

Every Eclipse-Store-backed store, in all three persistence modules:

| Module | Stores |
|---|---|
| `jCustos-persistence-eclipsestore` | framework storage (`jcustos-store`: sessions, audit ring, bootstrap state, …), user-directory storage (`…/users`) |
| `jCustos-events-persistence-eclipsestore` | envelope / replay / sequence / dead-letter stores |
| `jCustos-audit-integrity-persistence-eclipsestore` | audit hash-chain storage |

Note the default framework storage subdirectory also changed its NAME:
`jsentinel-store` → `jcustos-store`. Even a same-path deployment will
therefore not accidentally pick up an old storage tree.

## Migration paths for existing data

- **Audit chain (forensics):** export under V00.81.00 with
  `AuditExportService` (NDJSON + `SignedAuditBatch`). The export stays
  verifiable forever with public key material only — the wire/hash
  protocol strings (`jsentinel-audit-chain/v1`, …) were deliberately NOT
  renamed, so old exports stay verifiable under jCustos. Since 00.84.00 an
  export verifies only when its signing key is bound to the producer id
  `jcustos-audit-export`, and an export written before 00.84.00 verifies as
  `Unanchored(LEGACY_EXPORT)` (JS-SEC-103).
- **Signed event envelopes:** the wire format is FQCN-free and unchanged;
  exported/streamed envelopes remain valid. The Eclipse-Store envelope
  store itself starts fresh.
- **Users / sessions / everything else:** re-create under jCustos
  (first-admin bootstrap flow), or keep the old application on V00.81.00
  until its data has aged out. Sessions are ephemeral by design
  (`SweepingSessionStore` retention, V00.81.00).

## Verification

The Eclipse-Store restart/contract tests (e.g.
`EclipseStoreAuditChainRestartTest`) run against the new type names and
prove close → reopen → a verifying chain for jCustos-written storages
(`Anchored` since 00.84.00; the verifier no longer returns `Valid`).
