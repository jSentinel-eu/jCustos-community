# Decision table — V00.73 DX

| Situation | Recommended path |
|---|---|
| Interface available, want runtime proxy | `SecuredProxy.wrap(...)` |
| Concrete class without interface | `@Secured` + generated `<Type>Secured` wrapper (jCustos-processor) |
| Vaadin button / link / menu | `SecuredUi.button(...) / .link() / .menuItem(...)` |
| Vaadin policy-guarded button / link / menu | `SecuredUi.button(...).requiresPolicy("...")` (V00.73 real evaluation) |
| ServiceLoader configuration | `@JCustosAutoService` |
| Bootstrap-side wiring | `VaadinSecurity.bootstrap()` / `RestSecurity.bootstrap()` / `StandaloneSecurity.bootstrap()` |
| Real audit / session / policy / role / credential config | V00.73 sub-builders `.audit(...)` / `.sessions(...)` / `.policies(...)` / `.roles(...)` / `.credentials(...)` |
| Production setup | Adapter facade + `productionDefaults()` profile + `JCustosDiagnostics.inspect()` for sanity |
| Catch unknown `@SecureRoute(policy = ...)` at boot | `.discoverSecureRoutes(true)` + `mode(STRICT)` |
| Programmatic health / monitoring / `/health` endpoint | `runtime.healthCheck()` + `runtime.toJson()` (V00.74.10) |
| CLI boot banner | `runtime.summary()` (V00.74.10) |
| App + framework persistence in one parent dir | `JCustosStorageFactory.openAt(parent)` returns a `JCustosStoragePair` with linked-lifecycle two-phase close (V00.74.20) |

## When to use

- **`SecuredProxy`** — small interface, dynamic-proxy is fine; runtime
  cost is negligible. Test fixtures love this.
- **`@Secured` + `<Type>Secured`** — production hot path, no interface,
  zero per-call reflection. Catches `final` / `private` / `static`
  guarded methods at compile time. V00.73 also writes the wrapper-index
  at `META-INF/jcustos/generated-wrappers.idx`, surfaced
  through `JCustosDiagnostics.inspect()`.
- **`SecuredUi.*`** — declarative Vaadin UI. Hides / disables on a
  denied subject without imperative `if`-trees. V00.73 makes
  `.requiresPolicy(...)` real (lookup through `PolicyRegistry`).
- **`@JCustosAutoService`** — drops the burden of hand-written
  `META-INF/services` files for every SPI implementation.
- **Adapter facades** — typed fluent bootstrap; same `CommonJCustosBootstrap<B>`
  contract across Vaadin, REST and Standalone.
- **Sub-builders** — `.audit(...)` composes the existing
  `LoggingAuditSink` / `RingBufferAuditSink` / `StoreBackedJCustosAuditService`;
  `.policies(...)` registers into `PolicyRegistry`; `.credentials(...)`
  keeps the legacy `PasswordHasher` resolver path and the V00.71
  `PasswordHashingService` pipeline path separate.
- **Runtime tooling (V00.74.10)** — `runtime.summary()` for a single-
  line banner; `runtime.healthCheck()` for a structured `HealthStatus`
  with `Health.HEALTHY/DEGRADED/FAILED` classification; `runtime.toMap()`
  for a deterministically-ordered immutable map; `runtime.toJson()` for
  RFC 8259 output via the internal encoder. Maven Enforcer on
  `jCustos-dx` blocks Jackson, Gson and `org.json` on compile/runtime
  scope so no JSON library leaks onto the DX classpath.

## When NOT to use

- Don't use `SecuredProxy` if you can use `@Secured`: the compile-time
  path is always faster and clearer.
- Don't use `@JCustosAutoService` for SPIs you intentionally want to
  *not* register globally (e.g. test doubles).
- Don't put `PasswordHashingService` through
  `JCustosServiceResolver.setPasswordHashingService(...)` — that
  setter is for the legacy `PasswordHasher`. Use
  `.credentials(c -> c.hashing(svc))` instead; since 00.84.00 it lands in
  `JCustosServiceResolver.credentialHashingService()` (JS-SEC-073).
- Don't expect `.pepper(...)`, `.credentialStore(...)`,
  `.passwordChange(...)` or `.passwordReset(...)` to activate anything —
  the bootstrap records them and reports
  `dx/credential-<entry>-recorded-not-wired` (WARNING; STRICT → ERROR).
  Compose the pepper into the hashing service and wire the rest yourself.
- Don't call `.roles(r -> r.mapping(...))` — `RolePermissionMapping` is
  deliberately not part of the V00.73 fluent surface (Konzept §9).
  Register it directly through `JCustosServiceResolver` if needed.
- Don't expect `.sessions(s -> s.storeBacked(...))` on REST or
  Standalone to register anything globally — there is no global
  `setSessionStore(...)` resolver setter. REST records
  `rest/session-store-unused` INFO; Standalone records
  `standalone/sessions-not-applicable` INFO.
