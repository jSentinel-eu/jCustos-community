# jCustos V00.83.00 — saying what is stable

**Theme:** two credibility gaps. Large parts of the public surface still carried
`@ExperimentalJCustosApi` after running unchanged for six releases — including
types whose own Javadoc promised promotion "in V00.76". And
`RestJCustosBootstrap.decisionMapper(...)` accepted configuration that never
reached the enforcement path, which the bootstrap documented about itself.

No new security features, no new modules. What changes is what the project
tells you it will stand behind.

## Stable-API promotion

Forty-three types and eleven methods lose the experimental marker. The
procedure is the one V00.79 established (Konzept-V00.79 §13.1) — form
stability, real test coverage, a litmus test through an actual integration,
and at least three minor releases of soak — applied rather than reinvented.

| Module | Promoted | Since |
|---|---|---|
| `jCustos-core` — `credential/propagation` | 14 types | 00.74 |
| `jCustos-core` — `@PropagateToken` | 1 | 00.74 |
| `jCustos-core` — `JCustosServiceResolver` | 7 methods | 00.74/00.76 |
| `jCustos-propagation` | `PropagatingProxy` | 00.74 |
| `jCustos-propagation-oidc` | 6 types | 00.74 |
| `jCustos-jwt` | `HttpJwksClient`, `NimbusJwtValidator`, `NimbusJwtSigner` | 00.76/00.77 |
| `jCustos-oauth2` | 5 types (code flow, token endpoint, refresh rotation, state store) | 00.77 |
| `jCustos-dx` | `Health`, `HealthFinding`, `HealthStatus`, `PropagationBootstrap` | 00.74 |
| `jCustos-dx` — `JCustosRuntime` | 4 methods (`summary`, `toMap`, `toJson`, `healthCheck`) | 00.74.10 |
| `jCustos-dx-rest` | `RestCorsConfiguration(+Builder)`, `RestOpenApiMetadata(+Builder)` | 00.74 |
| `jCustos-dx-standalone` | `InteractiveLogin*`, `ThreadPropagation*` (5) | 00.74 |

`JCustosServiceResolver` now carries no experimental marker at all. It is a
stable class that marked individual methods, and leaving its propagation and
JWT accessors marked would have kept those surfaces experimental through the
back door.

Promotion removes an annotation and changes no behaviour, so it cannot break a
compiling caller and the affected modules keep their PIT baselines.

### The promise that had a condition attached

The propagation types read *"stable promotion staged for V00.76"*, and the
package Javadoc named the condition: **after at least one real demo adoption**.

That adoption had never happened. `@PropagateToken` appeared only inside the
library modules and their own tests. The demo that would have shown it off
concatenated `"Bearer " + token` by hand, and a second demo configured
`.propagation(p -> p.passThrough())` without ever invoking a `@PropagateToken`
path — the strategy was decoration.

So the adoption came first: `demo-jcustos-vaadin-rest-client` now calls its
backend through a `@PropagateToken` interface with no token parameter and no
`Authorization` literal at any call site. It forced no signature change, which
is what made the promotion defensible rather than merely overdue.

### SemVer commitments

For every promoted type:

- **Interfaces grow only through `default` methods.**
- **Records and enums grow only additively.** A new record component means a
  successor type and a deprecation cycle, not a changed signature.
- **Annotations grow only through elements with default values.**
- **No signature, record component or enum constant is removed** without a
  major version.

Re-marking a promoted type is a SemVer regression. `StableApiPromotionGuardTest`
fails when it happens, naming the type.

### Kept experimental, and why

The marker means two different things, and this table separates them.

| Kept | Reason |
|---|---|
| `jCustos-events` (135) + `jCustos-events-testkit` (11) | The surface deserves an audit as a whole, including the testkit contract suites — a different size of job than per-type promotion |
| `jCustos-core` remainder (111) | Heterogeneous: V00.70 persistence-store SPIs, account lifecycle, rate limiting. Each group needs its own audit |
| V00.79.20 hardening group — mutual TLS, PAR, JAR, JWE (6 across jwt/oauth2) | **Not** soak time, which has passed. This group has not had its own audit yet |
| `jCustos-dpop` (9), `jCustos-identity-oidc` (3) | Deferred in V00.79 for their own soak; audit scheduled with the group above |
| `jCustos-oauth2-rest` `CallbackStateBinding` (1) | `@since 00.81.00` — genuinely still soaking |
| `jCustos-vaadin` (9), `jCustos-rest` (7), `jCustos-persistence-eclipsestore` (5), `jCustos-standalone` (1) | Adapter-side V00.70/V00.74 surfaces, not part of this release's scope |
| Permission API (`PermissionName`, `HasPermissions`, `PermissionBasedAccessEvaluator`, …) | **A design position, not a soak status.** Role-based access is the recommended path for production; the marker says so in its own text and stays |
| `jCustos-dx` — `OidcBootstrap.vendor(VendorProfile)` (1 method) | The leak rule: a stable interface exposing a still-soaking type marks that one method, rather than holding the whole interface back |
| Enterprise repo (56) | V00.80 operations stack, two minors old |

Community drops from 343 marked files to 299.

## A configured REST decision mapper now reaches enforcement (JS-SEC-026)

`RestJCustosBootstrap.decisionMapper(...)` and `.errorBodies(...)` took
configuration and dropped it: both were recorded as diagnostic entries while
`RestAuthorizationFilter` hard-wired its own `HttpStatusDecisionMapper`. An API
that accepts configuration and ignores it is worse than one that never offered
it.

`.errorBodies(...)` was in a worse state still — **nothing** consumed it. Even
`DefaultRestDecisionMapper` never called the strategy; the two defaults simply
happened to produce the same strings.

The module dependency runs `core → rest → dx-rest` and had to keep running that
way, so the seam went into `jCustos-rest`: `RestDecisionMapping` and
`RestErrorBodies`, which the existing DX interfaces now extend. Existing lambdas
and implementations compile unchanged. `HttpStatusDecisionMapper` renders its
bodies through the strategy, giving `RestErrorBodyStrategy` its first consumer,
and `RestDecisionContext` carries the configured mapper from `install()` to the
filter.

Two details worth naming:

- **The filter resolves per request, not at construction.** Applications build
  their filter before bootstrapping — `DemoHttpRouter` holds it in a constructor
  field — so a snapshot would have missed the configuration published moments
  later. Explicit constructor argument wins, then the published mapper, then the
  conservative default.
- **The session-expiry path joins the other two.** It wrote status and body
  directly, so a `problem+json` strategy would have rendered two of three denials
  and left expiry as plain text.

Nothing changes for an application that never calls `.decisionMapper(...)`.

## Also in this release

- `docs/dx/5-minute-setup-propagation.md` — the missing page in that series.
- `ExperimentalJCustosApi`'s own Javadoc described the permission API as the
  only experimental surface, accurate for V00.60. It now explains both meanings
  of the marker and where to tell them apart.
- The README's stable/experimental section and FEATURES.md's legend follow.
- Two Javadoc promises corrected rather than deleted: the propagation package
  records that its condition was met; the events package's V00.76/V00.77 target
  is named as predating the surface itself (V00.75) and not a commitment.

## Verification

Full reactor green: **6632 tests**, up from 6610 in V00.82.

> **Correction (00.84.00):** both totals counted every test twice; they summed every
> `Tests run:` line of the Maven log, class lines and module summaries alike. Measured again
> from the tags: 3316 tests (00.82.00: 3305), and 237 in the enterprise edition, no failures.

Each behavioural change was verified by removing it:

| Change | Disabled | Result |
|---|---|---|
| Demo adoption | `@PropagateToken` removed from `BackendGateway` | 2 of 4 tests fail |
| Propagation promotion | `TokenCredentialStore` re-marked | Guard fails, names the type |
| DX promotion | `JCustosRuntime.summary()` re-marked | Guard fails, names the method |
| Decision-mapper wiring | Context lookup reverted | 3 of 5 tests fail |

`RestDecisionMappingWiringTest` asserts against the response rather than
`runtime.services()`. That distinction is why JS-SEC-026 went unnoticed: the
existing bootstrap tests only checked registration, never the wire.

The pre-existing filter, mapper and session-lifetime tests pass unchanged,
which is what demonstrates backwards compatibility.

## Upgrade

Drop-in. No API was broken and no default changed.

Two things to know:

1. If you implemented `RestDecisionMapper` or `RestErrorBodyStrategy`, they now
   extend the new `jCustos-rest` interfaces. Source-compatible; recompile.
2. If you called `.decisionMapper(...)` or `.errorBodies(...)` and worked around
   them having no effect, **remove the workaround** — the configuration now
   applies, and applying it twice may double-render a body.
