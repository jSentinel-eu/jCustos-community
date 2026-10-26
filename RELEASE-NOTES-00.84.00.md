# jCustos V00.84.00 — own your security decisions

**Theme:** (to be written at release close — the window combines the requirements R1–R9
from aligning the Vaadin Create 2026 talk with the source, the credential-hardening
backlog, and the findings of the first full entry review over both editions.)

This file grows with the window; every change cites its JS-SEC identifier and CWE where
one applies, and its tracker reference (R<n> for the requirements, ER<nn> for the
entry-review findings).

## Vaadin platform 25.3.3 (R6, release hygiene)

The reactor moves from Vaadin 25.1.1 to 25.3.3. `vaadin-core` 25.3.3 pulls
`flow-server` 25.3.4, and the platform BOM now manages Jackson 3 at 3.2.0 and the
Jackson 2 annotations at 2.22.

Two consequences for the demos:

- The six Vaadin demos no longer pin `tools.jackson.core` 3.1.4 and
  `jackson-annotations` 2.21. Those pins dated from V00.76.10, when they lifted
  Vaadin's transitive Jackson above a vulnerable version; with 25.3.3 the BOM is ahead
  of them, and a pin would now *downgrade* `jackson-databind` to 3.1.4 next to a 3.2.0
  `jackson-core`. Removing them also closes the 50 Dependabot alerts the GitHub mirror
  had accumulated — all of them Jackson in demo or test scope, none in a published
  module.
- The Jackson-2-annotations workaround for `vaadin-maven-plugin:prepare-frontend`
  (a `NoClassDefFoundError` on `JsonSerializeAs` under 25.1.1) is obsolete: the demos
  package without it.

The two remaining test-scope pins in published modules follow the same move:
`jCustos-dx` tests use `jackson-databind` 2.22.4, `jCustos-vaadin` tests use
`jackson-annotations` 2.22. Neither reaches a consumer's classpath.

Deprecations surfaced by the upgrade: none in the jCustos sources — `javac` with
`-Xlint:deprecation` over all 66 reactor projects reports no use of a deprecated Vaadin
API. The 25.3 deprecations (`VaadinService.addRpcInvocationListener`,
`addSessionLockListener`, `fireUIInitListeners`) are not called anywhere.

One test needed adapting, not the library: the browserless testkit that comes with
25.3 (`browserless-test` 25.3.2, managed by the BOM, previously 1.0.0) flushes
server-initiated focus after a tester click and reaches into the UI's session for it.
`demo-vaadin`'s sign-out test clicks a button whose handler invalidates the HTTP
session, so the flush found no session (a real browser never notices). The test now
asserts usability through the tester and fires the click server-side.

`SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem`, `SessionManagementView` and
`LoginView` are covered by the existing browserless tests, which pass unchanged on
25.3.3. `VaadinService.reinitializeSession` is deprecated only from Flow 25.4 and is
handled by R1.

## The session-management route was reachable without logging in (ER01, JS-SEC-068, CWE-306)

`jCustos-dx-vaadin` ships `SessionManagementRoute` at `/session-management`, and Vaadin
registers every `@Route` class it finds on the classpath. The route carried no security
annotation, `AuthorizationListener` exempted `SessionManagementView` subclasses from
deny-by-default by type, and the STRICT route discovery excluded them for the same
reason. Once an application had called `.sessionManagementView()` with a store-backed
session configuration, any visitor could open the inventory of live sessions — tenant,
subject id, session id — and press Revoke, whose handler ran on the server without a
check of its own. A hidden button is not a security boundary; this one was not even
hidden.

The route is now protected like any consumer route, and the requirement is explicit:

- `SessionManagementRoute` carries `@ProtectedBy(SessionManagementAccess.class)`. The
  evaluator reads the requirement the bootstrap published and returns `Forbidden` when
  none was published, `Unauthenticated` without a subject, and `Granted` only for a
  subject holding every required role and permission.
- `VaadinJCustosBootstrap.sessionManagementView(SecuredVisibility.Requirement)` names
  that requirement. The parameterless overload is deprecated: it leaves the route closed
  to everyone and reports `session-management-view-without-requirement`, an error in
  PRODUCTION and STRICT and a warning in DEVELOPMENT. Secure by default, loud about it.
- `SessionManagementView` gained a three-argument constructor taking the requirement.
  Its Revoke handler re-checks the current subject before it touches the store and
  audits a refused attempt as `AccessDenied`; the two-argument constructor keeps the
  requirement empty for subclasses that carry their own annotation, as the demos do.
- The type-based exemptions in `AuthorizationListener.isDenyByDefaultExempt` and in
  `VaadinRouterSecureRouteDiscovery` are gone. Error views remain exempt.

Verified by removing it: without `@ProtectedBy` the new browserless test lets an
anonymous visitor onto the view. With it, the visitor is forwarded to the login route and
the refusal is audited; a subject without the permission is refused with
`session-management:requirement-not-met`; an administrator reaches the view and revokes
exactly one session through the grid's Revoke button. The evaluator and the bootstrap
finding have their own tests.

## `sameTenant` compared a request attribute with itself (ER02, JS-SEC-069, CWE-863)

`JCustosPolicies.sameTenant(name, subjectKey, resourceKey)` read both tenants from the
same attribute map of the `AccessContext`, and the one-argument variant passed the key
`tenantId` for both sides. Any request carrying *some* `tenantId` attribute was admitted;
neither `ResourceRef.tenant()` nor the `ResourceResolver` was consulted, although the
Javadoc promised exactly that. The existing test cemented the behaviour as the success
case. An application relying on this policy for tenant isolation had none.

The policy now compares two genuinely different sources:

- the resource tenant is `ResourceRef.tenant()` when the context carries a `ResourceRef`,
  otherwise the `resourceTenantKey` attribute (resolved resource attributes first, then
  access attributes);
- the subject tenant is the `subjectTenantKey` access attribute when the adapter or
  application set one, otherwise the tenant of the current subject through the registered
  `SubjectIdResolver.tenantFor(...)`;
- the policy denies when either side is unknown, and the constructor rejects equal keys.

`sameTenant(name)` uses `subjectTenantId` and `resourceTenantId`. Attribute values may be
`TenantId` or `String`. This changes what the one-argument variant admits — from
everything to only matching tenants — which is the point.

## A class-level restriction did not reach a Method-wired REST handler (ER03, JS-SEC-070, CWE-862)

`RestAuthorizationFilter` receives the secured element as a `Method` in the usual wiring
(the demo router and every test fixture), and `JCustosAnnotationScanner` looked only at the
method's own annotations: a `@RequiresRole` or `@RequiresPermission` on the handler *class*
yielded an empty scan. Under allow-by-omission the handler then ran unguarded; under
deny-by-default every caller was refused. Meanwhile `isPublicRoute`, the start-up check in
`ClassScanningRestHandlerDiscovery` and the OpenAPI metadata all treated the class level
as applying to every method — so the start-up check reported such a handler as protected
while the filter did not protect it. The JS-SEC-040 superclass walk covered classes, not
the method-to-class step.

The scanner now falls back from a method without a restriction of its own to the
restriction declared on (or inherited by) its declaring class; an explicit `@PublicRoute`
on the method remains the opt-out and wins over the class default. Every caller of the
scanner — the REST filter, `JCustosEnforcer`, the discovery check, the OpenAPI generator —
sees the same answer. Scanner tests cover the fallback and the opt-out; the REST filter
tests wire a class-annotated handler by `Method` and show 403 without the permission, the
handler running with it, and a `@PublicRoute` method of the protected class staying public.

## Session lifetime is enforced by default (R4, JS-SEC-065, CWE-1188)

`SessionLifetimeListener` is registered for every Vaadin application and advertises idle
and absolute-lifetime enforcement, but the resolver default behind it was
`NoopSessionPolicy`: nothing was enforced unless the application registered a policy.
00.79.40 added a warning (JS-SEC-035), 00.81.00 a bootstrap finding; the default itself
stayed inert.

`JCustosServiceResolver.sessionPolicy()` now falls back to
`TimeoutSessionPolicy.secureDefault(...)`: 30 minutes idle, 12 hours absolute lifetime,
rotation after login, login route from the resolver. `findSessionPolicy()` still reports
the default as "not configured" so diagnostics can tell a default from a registration.
`NoopSessionPolicy` remains available as the explicit opt-out, and the listener now says so
in its one-time warning. The bootstrap finding `sessions/no-timeout-policy` is an INFO in
every mode — an unconfigured lifetime is no longer a silent no-op and no longer gates
STRICT — and the policy the DX bootstrap builds takes its login route from the resolver
too.

Migration: applications that registered a `TimeoutSessionPolicy` themselves see no change.
Applications that registered nothing now end idle sessions after 30 minutes and every
session after 12 hours; configure `.sessions(s -> s.timeout(...).absoluteLifetime(...))`
or register a policy to choose other limits, or register `NoopSessionPolicy` to opt out.
Verified: with no registered policy, a navigation 31 minutes after the last activity
clears the subject, forwards to the login view and audits `SessionExpired(IdleTimeout)`.


## Client address behind a reverse proxy (R2, JS-SEC-061, CWE-348)

`LoginView` took the client address from `VaadinRequest.getRemoteAddr()`, and the demos'
authentication services did the same. Behind a reverse proxy on loopback that address is
the proxy, so every client shared one brute-force bucket; with Jetty's
`ForwardedRequestCustomizer` installed, Jetty also honoured RFC 7239 `Forwarded`,
`X-Forwarded-Server`, `X-Forwarded-Port` and `X-Proxied-Https`, none of which a plain Caddy
set-up rewrites, so an Internet client could forge the address that keys the throttle. The
REST adapter recorded no client address at all.

New in `jCustos-core`, package `eu.jsentinel.jcustos.net` (all `@ExperimentalJCustosApi`):

- `ClientAddressResolver` — SPI deciding which address identifies the client, resolved
  through `JCustosServiceResolver.clientAddressResolver()` / `findClientAddressResolver()` /
  `setClientAddressResolver(...)`, SPI-discoverable via `META-INF/services`.
- `DefaultClientAddressResolver` — the default: the connection peer, no header consulted.
- `TrustedProxyClientAddressResolver` (`ClientAddressResolver.trustedProxies(...)`) — honours
  `X-Forwarded-For` only when the peer is a configured trusted proxy (addresses or CIDR
  ranges, IPv4 and IPv6); reads the header from the right, skips trusted hops, ignores
  `Forwarded`, `X-Real-IP` and friends, falls back to the peer with a one-time `WARN` for
  untrusted peers or malformed entries. IP literals are parsed without name resolution.
- `ClientRequestView` — the transport-neutral request view the resolver works on.

Adapters: `VaadinClientAddress.current()` replaces `getRemoteAddr()` in `LoginView` and in all
Vaadin demos; `RestRequest.remoteAddress()` (default `null`, so existing implementations
keep compiling) exposes the peer, `RestClientAddress.resolve(request)` resolves it and
`RestAccessContextFactory` records it as attribute `clientAddress` (scrubbed). The REST demos
and the enterprise `HttpExchangeRestRequest` expose their peer; `demo-rest` drops its
`X-Demo-Remote-Addr` header hack. DX: `.clientAddress(ClientAddressResolver)` on every
bootstrap registers the resolver at `install()`.

Documentation: `docs/security/deployment/reverse-proxy.md` describes both supported
topologies — the jCustos resolver with trusted peers, or Jetty's customizer with the
`Forwarded`, `X-Proxied-Https`, `X-Forwarded-Server` and `X-Forwarded-Port` headers stripped
at the proxy (Caddy fragment included) — and what not to combine.

Migration: nothing changes for direct connections. Behind a reverse proxy call
`.clientAddress(ClientAddressResolver.trustedProxies("127.0.0.1", "::1"))` (or register the
resolver programmatically) so throttling keys on the real client again. Verified: forged
`X-Forwarded-For` and `Forwarded` from an untrusted peer leave the resolved address at the
peer; the same header from a trusted peer yields the appended client address, in core,
REST and a browserless Vaadin request alike.

## Session-id rotation without `reinitializeSession`, audited with the surviving id (R1, JS-SEC-060, CWE-384)

`LoginView` rotated the HTTP session id after login through
`VaadinService.reinitializeSession(VaadinRequest)`, which Flow deprecates for removal from
25.4 in favour of `HttpServletRequest.changeSessionId()`. The audit trail also told the story
backwards: the `SessionContext` was built before the rotation, so `TimeoutSessionPolicy.onLogin`
published `SessionCreated` with the id that was about to be retired, and `SessionInvalidated`
followed for the same id — the id that actually lived on was never recorded as created.
Applications that wrote a `SessionStore` record inside `checkCredentials()` persisted that
retired id too, so revocation by id missed the live session.

`LoginView.notifyOnLogin` now rotates first, through `changeSessionId()` on the current
`VaadinServletRequest` (the servlet session object and with it the `VaadinSession`, the bound
subject and the `JCustosVersion` snapshot stay in place; only the id changes), falls back to
`reinitializeSession` only for non-servlet transports, and only then calls
`SessionPolicy.onLogin` with a context that names the new id. `SessionCreated` therefore
carries the surviving id; `SessionInvalidated` follows for the retired id with the policy's
reason. No new audit variant was added — `AuditEvent` stays sealed at 31 permits, so exhaustive
switches in `LoggingAuditSink`, `AuditQuery` and external consumers keep compiling.

New hook `LoginView.onSessionRotated(previousSessionId, currentSessionId)` (no-op by default)
runs once per login after the rotation was audited; applications create or re-key
session-keyed state there. `SessionRecord.withSessionId(...)` and the default method
`SessionStore.rekey(from, to)` (find, save under the new id, delete the old; covered by the
`SessionStoreContract` in `jCustos-persistence-testkit`) support the re-key. The four Vaadin
demos record their inventory row from the hook instead of from `checkCredentials()`.

Migration: nothing to change for applications that do not key state by session id. If a
login view records sessions itself, move that call into `onSessionRotated(...)` or re-key with
`SessionStore.rekey(previousSessionId, currentSessionId)`. Verified under browserless Vaadin
with a real `MockRequest`: the wrapped-session id differs after login, the subject bound before
the rotation is still bound afterwards, `SessionCreated.sessionId()` equals the new id and
`SessionInvalidated.sessionId()` the old one.

## Refresh-token rotation claims before it issues; replays revoke the family (ER04, JS-SEC-071, CWE-367, CWE-294)

`TokenService.rotate` persisted the successor pair through `issue(...)` and only then marked
the old token replaced. When that compare-and-set lost against a concurrent rotation of the
same refresh token, the already persisted pair was returned anyway, so two callers presenting
one stolen token both received valid pairs, and a replay of a consumed token was refused
without any audit trace.

`rotate` now claims the old token first — `RefreshTokenStore.markReplaced` is the atomic
step — and persists the successor only after the claim succeeded; nothing is written when the
claim fails, so two concurrent rotations yield exactly one pair and exactly one successor
record. A consumed token presented again, sequentially or by losing the race, is a replay:
every still-active successor reachable through `replacedByHash` is revoked (RFC 9700 token
family revocation, so the legitimate holder signs in again) and a `CredentialVerificationFailed`
with the new classification `InternalAuditEventType.REFRESH_TOKEN_REPLAY` is emitted; the
`username` carries the subject id of the family. No new `AuditEvent` variant. The revocation
instant is clamped to the successor's `createdAt`, because the losing rotation's clock reading
can predate the winner's, and the record invariant would otherwise reject it. Operators who
prefer the broader response keep `revokeAll(subjectId)`.

Verified with two threads on a real `InMemoryRefreshTokenStore` behind a read barrier, so both
read the token as active before either claims it: exactly one `Optional` is present, the
store holds the initial record and one successor, one `TokenRotated` and one replay event are
published, and the successor is revoked.

## Legacy PBKDF2 hasher: 600 000 iterations by default, stored parameters validated (ER05, JS-SEC-072, CWE-916, CWE-400, CWE-248)

Two PBKDF2 implementations ship with two wire formats. The modern pipeline
(`Pbkdf2PasswordHashProvider`, `Pbkdf2Defaults`) uses 600 000 iterations and validates its
parameters; the legacy `Pbkdf2PasswordHasher` — still the resolver fallback behind
`JCustosServiceResolver.passwordHashingService()` and the DX `.pbkdf2Defaults()` — hashed with
120 000 iterations and took iteration count and salt from the stored hash unchecked. A stored
`pbkdf2$0$…` or an empty salt made `PBEKeySpec` throw out of `verify`, and a stored
`pbkdf2$2000000000$…` pinned a CPU core per login attempt.

`Pbkdf2PasswordHasher` now defaults to `Pbkdf2Defaults.DEFAULT_ITERATIONS` (600 000), so hashes
written with the historical default report `needsRehash` and are upgraded on the next successful
login. `verify` refuses an iteration count outside `1..Pbkdf2Defaults.MAX_ITERATIONS`, a salt
outside `MIN_SALT_LENGTH..MAX_SALT_LENGTH` bytes and an empty hash segment before any derivation
runs, and a failing derivation yields `false` rather than an exception. The constructor rejects
an iteration count outside the same range and a `null` salt source. Hashes written by the old
default (16-byte salt, 120 000 iterations) still verify.

Not changed here: the resolver fallback is still this class. Switching the default to the
modern `PasswordHashingServices.defaults()` and deprecating the legacy hasher for removal is
the follow-up the review proposed for a later release; ER06 covers the DX pipeline wiring.
Verified: `verify(x, "pbkdf2$0$<salt>$<hash>")` and `verify(x, "pbkdf2$1000$$AAAA")` return
`false` without an exception, an excessive iteration count is refused in under 50 ms, and
`new Pbkdf2PasswordHasher().hash(…)` carries 600 000 iterations.

## DX credential pipeline: `.hashing(...)` and `.modern()` are wired, inert entries are reported (ER06, JS-SEC-073, CWE-684)

The `.credentials(...)` sub-builder recorded the V00.71 pipeline — `.hashing(...)`, `.modern()`,
`.pepper(...)`, `.credentialStore(...)`, `.passwordChange(...)`, `.passwordReset(...)` — in the
bootstrap state and listed every entry in `JCustosRuntime.services()` as `bootstrap-explicit`,
the same position JS-SEC-055 corrected for `.rateLimit(...)`: no module read the state, so after
`.modern()` the application still resolved the PBKDF2 fallback while the diagnostics claimed an
active Argon2id pipeline.

`JCustosServiceResolver` gains a slot for the pipeline: `credentialHashingService()` (falls back
to `PasswordHashingServices.defaults()`), `findCredentialHashingService()` (empty for the
fallback) and `setCredentialHashingService(...)`, cleared by `resetAll()`. It is distinct from
the legacy `passwordHashingService()` accessor, which keeps returning the `PasswordHasher`. The
DX bootstrap wires `.hashing(...)`, `.modern()` and `.pbkdf2Defaults()` through that slot, so
`.modern()` really activates Argon2id for everything that resolves the pipeline. The four
entries without a consumer — pepper, credential store, password change, password reset — are
no longer listed as services; they surface as `dx/credential-<entry>-recorded-not-wired`
(WARNING, a boot failure in STRICT), each with the remedy: compose the pepper into
`.hashing(PasswordHashingServices.defaults(policy, limiter, pepper))`, hand the rest to the
application's own wiring or drop the call.

Migration: applications that read their pipeline from their own wiring keep working; those
that want the configured pipeline call `JCustosServiceResolver.credentialHashingService()`.
A STRICT application that passes `.pepper(...)`, `.credentialStore(...)`,
`.passwordChange(...)` or `.passwordReset(...)` fails to boot until the inert call is composed
or removed. Verified: `.credentials(c -> c.modern()).mode(STRICT).install()` wires a pipeline
whose fresh hash reports algorithm `Argon2id` and provider `argon2id-bc`; with the wiring
removed that test and the `.hashing(...)` / `.pbkdf2Defaults()` tests fail.

## Single-use tokens: siblings retire, stores are bounded, every reset is audited (ER07, JS-SEC-074, CWE-640, CWE-770, CWE-778)

Three single-use-token services — the account-lifecycle `PasswordResetService` and
`EmailVerificationService`, and the credential-pipeline `credential.reset.PasswordResetService`
— wrote a new record on every request and never retired the earlier ones; `consume` marked only
the token presented. An older link intercepted before the user asked again therefore reset the
password a second time after the newer link had already been used. Their in-memory stores grew
without limit over the unauthenticated forgot-password path, and the credential-pipeline
service published no audit event at all.

- **Only the newest link works.** `request`/`issue` retires every open token of the subject
  before the new one is persisted; `consume` retires the remaining siblings after the single-use
  marker is set (the consumed record itself stays as the marker). The account-lifecycle
  services use `deleteBySubject`; the credential-pipeline service uses the new
  `ResetTokenStore.findByUsername(...)` and marks siblings `EXPIRED`. Implementers of
  `ResetTokenStore` must add `findByUsername`; the in-memory store is the only one shipped.
- **Bounded in-memory stores.** `InMemoryPasswordResetTokenStore`,
  `InMemoryEmailVerificationTokenStore` and `InMemoryResetTokenStore` take a capacity
  (default `CapacityBound.DEFAULT_MAX_ENTRIES`, 100 000). A full store purges consumed and
  expired records and otherwise refuses with
  `<namespace>-capacity-exceeded`, the pattern the nonce and login-attempt stores already
  follow. The stores index tokens by subject and track the earliest expiry, so sibling
  retirement is proportional to the subject's own tokens and a full store refuses in constant
  time — the first version of this change scanned 100 000 records per request and turned the
  forgot-password path into an O(n) CPU cost, which the mass-request test exposed.
- **Audit for the credential pipeline.** `credential.reset.PasswordResetService` now publishes
  `PasswordResetRequested` and `PasswordResetCompleted`, carrying the public selector, never the
  verifier; a constructor overload takes an explicit `JCustosAuditService`, the existing one
  resolves the sink per event.

Not done here: the structural consolidation into a shared `SingleUseTokenService` /
`SingleUseTokenStore` core is a design decision recorded as a question subtask under the
V00.84.00 plan; the three services keep their shapes until Sven decides.

Behaviour change to note: `revokeAll(subject)` after two requests now removes one record, not
two, because the second request already retired the first. Verified: two requests for the same
subject, consume of the second succeeds and the first validates empty; 150 000 requests keep
the in-memory store at its bound and refuse the surplus in under a second; the audit sink sees
one `PasswordResetRequested` per issue and one `PasswordResetCompleted` per consume.

## Test hygiene: Vaadin sessions in unit tests are strongly referenced

`CurrentInstance` holds the current `VaadinSession` through a `WeakReference`. Four Vaadin
test classes bound an in-memory session and dropped their own reference to it, so a GC pause
between binding and the assertion made `VaadinSession.getCurrent()` return `null` and the
test fail intermittently. The test classes now keep the bound session in a field. No
production code changed.
