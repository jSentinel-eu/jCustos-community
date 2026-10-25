# jCustos V00.81.10 — the jSentinel → jCustos rebranding

**Theme:** a feature-free, behavior-free release that renames the entire
framework: **jSentinel is now jCustos**. New Maven coordinates
(`eu.jsentinel:jCustos-*`), new package root (`eu.jsentinel.jcustos`), new
type names (`JCustos*`), new operator-visible names (`jcustos.*`). Wire
formats and every signed byte stay identical.

## Themes

1. **Full rename** — 112 package trees, 172 types, 61 modules, 62 poms,
   ~2,000 files rewritten; every step landed with a green full reactor.
2. **Hard operator-name cut** — config keys, OTel attributes, logger names,
   webhook headers, the OAuth2 binding cookie: all on the jCustos brand,
   no aliases (mapping table below).
3. **Fresh-storage break** — Eclipse-Store storages written by jSentinel do
   not open under jCustos; no legacy type mappings ship (deliberate).
4. **Guided transition** — 47 relocation POMs under the old coordinates,
   the `jcustos-migration` skill for consumers, and the 12 integration
   skills re-released under `jcustos-*` names.
5. **Wire/hash invariants preserved** — old signed envelopes and audit-chain
   exports verify unchanged.

## Statement of additivity

**None — this is the breaking release the rebrand announced.** Every
consumer touchpoint renames. The complete cut:

| Surface | jSentinel (≤ 00.81.00) | jCustos (00.81.10+) |
|---|---|---|
| Maven groupId | `com.svenruppert.jsentinel` | `eu.jsentinel` |
| Maven artifactIds | `jSentinel-<module>` | `jCustos-<module>` |
| Package root | `com.svenruppert.jsentinel` | `eu.jsentinel.jcustos` |
| Types (172) | `JSentinel*` (`JSentinelEnforcer`, `@JSentinelAutoService`, `@ExperimentalJSentinelApi`, …) | `JCustos*` |
| System properties | `jsentinel.dev`, `jsentinel.events.bus.enabled` | `jcustos.dev`, `jcustos.events.bus.enabled` |
| OTel attributes (14) | `jsentinel.envelope.id`, … | `jcustos.envelope.id`, … |
| Named loggers | `com.svenruppert.jsentinel.events` / `….alerts` | `eu.jsentinel.jcustos.events` / `….alerts` |
| Webhook headers | `X-JSentinel-Event-Type` / `X-JSentinel-Envelope-Id` | `X-JCustos-Event-Type` / `X-JCustos-Envelope-Id` |
| OAuth2 binding cookie | `__Host-JSentinelOAuth2State` | `__Host-JCustosOAuth2State` |
| Wrapper index | `META-INF/jsentinel/generated-wrappers.idx` | `META-INF/jcustos/generated-wrappers.idx` |
| Framework storage subdir | `jsentinel-store` | `jcustos-store` |
| Integration skills | `jsentinel-vaadin`, `jsentinel-rest`, … | `jcustos-vaadin`, `jcustos-rest`, … |

## What deliberately did NOT change

- **Wire formats**: signed event envelopes, the envelope wire JSON,
  `EventType` values, the metric-name catalog (`security.*` — brand-free
  by design since V00.80.00).
- **Protocol domain strings** (hash/signature bases):
  `jsentinel-audit-chain/v1`, `jsentinel-audit-chain:genesis`,
  `jsentinel-audit-batch/v1`, `jsentinel-audit-event/v1`,
  `jsentinel-event/canonical-json/v1`. Old signed data and NDJSON audit
  exports verify byte-identically under jCustos; the golden-value hash
  pins in the test suite ran green throughout the rename.
- The `jsentinel.eu` domain (docs, Maven-namespace verification, the
  default Auth0 claim namespace `https://jsentinel.eu/roles`).
- History: release notes, docs archives, snapshots and audit reports keep
  their original wording.

## Breaking: Eclipse-Store fresh start

Storages written by jSentinel (≤ 00.81.00) cannot be opened by jCustos —
Eclipse Store persists FQCNs in its type dictionary and **no legacy
mappings ship** (concept gate decision). Export what you need under
V00.81.00 first (the NDJSON audit export stays verifiable forever), then
start jCustos with fresh storage directories. The default framework
storage subdirectory also renamed (`jsentinel-store` → `jcustos-store`),
so a same-path deployment cannot accidentally open an old tree.
Detail: `docs/dx/storage-break-v00.81.10.md`.

## Migration

Mechanical, ordered, ~minutes per project — use the **`jcustos-migration`
skill** (`docs/skills/claude/jcustos-migration/`): GAV swap → package/type
rename → META-INF/services (names AND contents — extensionless!) →
operator names → verify grep-clean. The old coordinates carry
**relocation POMs at 00.81.10**: Maven prints the relocation message and
redirects, so stale builds keep working while telling you to move.

## Delivery mechanics (this release)

- `scripts/clean-bundle-for-central.sh` now stages `eu/jsentinel` with the
  47 `jCustos-*` modules; `scripts/build-relocation-bundle.sh` produces
  the one-time signed relocation bundle for the old coordinates.
- Deploy gate: the Sonatype Central namespace `eu.jsentinel` must be
  verified (DNS TXT on jsentinel.eu).

## Verification

- Full reactor green with tests after EVERY rename wave (P001–P007 +
  review fixes); golden-value hash pins green throughout.
- Static-analysis gate green on the library-module sample after the
  exit-review RF-1 fix (SpotBugs exclude regexes with escaped dots had
  silently stopped matching — the kind of breakage only the gate shows).
- Exit review focused on silent breakage: extensionless
  META-INF/services contents (fixed in-cycle), regex-escaped FQCNs
  (RF-1), residual lowercase brand tokens in demos (RF-2). SHIP.

## Roadmap

Next: **V00.82.00 — hardening rest (T3) & CSRF**, the first feature
release under the jCustos name. The project itself moves to
`Workspaces/jSentinel/jCustos` (post-deploy step P008).

---

Concept: `Konzept-V00.81.10.md` (archived in the project umbrella under `docs/v00.81.10/`) · Plan: ClickUp parent `86cbb2aqw` ·
Predecessor: `RELEASE-NOTES-00.81.00.md` (the last jSentinel release)
