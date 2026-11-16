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

## Session registry: a reused session id no longer inherits another subject's record (ER08, JS-SEC-075, CWE-613, CWE-384)

`StoreBackedSubjectSessionRegistry.register(subject, sessionId)` refreshed any record it found
under the id, regardless of the subject or status stored in it. When a container reused a
session id, or a login landed on an id whose record was already `EXPIRED` or `REVOKED`, the
record stayed bound to the previous subject with the previous version snapshot: `clearAll(A)`
ended B's session, `sessionsOf(B)` did not know it, and drift detection compared B against A's
`JCustosVersion`.

`register` now refreshes only a record that is still the same subject's `ACTIVE` session.
Anything else — another subject, or a record that is `EXPIRED` or `REVOKED` — is replaced by a
fresh `ACTIVE` record for the registering subject with its own version snapshot. Verified:
after `register(A, sid)` and `register(B, sid)`, `sessionsOf(B)` lists the id, `sessionsOf(A)`
does not, the record carries B's version and `clearAll(A)` leaves B's session alone; a record
saved as `EXPIRED` or `REVOKED` is `ACTIVE` and listed again after the next `register`.

## A compromised credential cannot return to ACTIVE without a new secret (ER09, JS-SEC-076, CWE-284)

The credential state machine allowed `COMPROMISED → ACTIVE` and nothing else that would
rotate the secret: no transition to `MUST_CHANGE` or `RESET_PENDING`, and
`credential.reset.PasswordResetService.issue` refused a `COMPROMISED` credential as `Blocked`.
The only way back into service re-accepted the compromised hash unchanged.

`CredentialLifecycleService` now allows `COMPROMISED → MUST_CHANGE`, `RESET_PENDING` and
`DISABLED`, and no longer `ACTIVE`; `ACTIVE` is reachable again only after the rotation. The
reset service lets a `COMPROMISED` credential start a reset — the reset is the rotation — and
the subsequent `consume` writes the new hash and moves the credential to `ACTIVE`; `DISABLED`
stays blocked because re-enabling is an administrative decision. `DISABLED` additionally gains
`MUST_CHANGE` and `RESET_PENDING` as the safer re-enable paths while `DISABLED → ACTIVE` stays
available to administrators. The incident-response bulk path (`MassCredentialStatusChange`)
writes statuses directly and is unaffected.

Verified: `isAllowed(COMPROMISED, ACTIVE)` is `false`, `isAllowed(COMPROMISED, MUST_CHANGE)` and
`isAllowed(COMPROMISED, RESET_PENDING)` are `true`; issuing a reset for a `COMPROMISED`
credential yields `Created`, consuming it ends in `ACTIVE` with a different hash; a reset for
`MUST_CHANGE` stays `Created`, for `DISABLED` stays `Blocked`.

## Emergency status change survives a failing audit sink (ER10, JS-SEC-077, CWE-703)

`MassCredentialStatusChange.forceAllToStatus` was the one place in the credential area where
`audit.publish` was not shielded against a `RuntimeException`. If the sink failed during a
pepper-compromise run, the loop ended after the first successful update, the remaining accounts
stayed `ACTIVE`, and the operator received an exception instead of the report — fail-open on an
incident path.

The publish is now guarded: a failing sink is counted in the new `Report.auditFailures`, logged
as a `WARN` through `HasLogger`, and the loop continues. `Report` gains the fifth component; the
previous four-argument constructor remains, and `total()` still sums the four outcome buckets.
Verified: with a sink that throws on every publish and three accounts, `forceAllToStatus`
returns `changed == 3` without an exception, every account is at the target status and the
report shows three audit failures.

## Five in-memory structures bounded; rate limiting checks and records atomically (ER11, JS-SEC-078, CWE-770, CWE-367)

Five in-memory structures are filled with keys an attacker chooses — client address, username,
refresh-token family id, RP session id, OAuth2 state — and were never bounded or cleaned:
`InMemoryRateLimitStore` kept every admitted event for ever (`purgeOlderThan` is called by no
shipped module) and `InMemoryRateLimitPolicy.tryAcquire` counted and recorded in two steps, so
N parallel requests at `limit - 1` all passed; `AbusePatternMonitor` emptied its deques but never
dropped a key; `InMemoryRefreshTokenFamilyStore` remembered families and revoked ids for ever;
`InMemorySessionRegistry` had no `unregister`; `VaadinSessionStateStore` kept expired entries.
JS-SEC-030, -048 and -015 had bounded their sister classes.

- **Rate limiting.** `RateLimitStore` gains `tryAdmit(key, at, since, limit)` with an
  `Admission` result — check and record as one step. The default is the old two-step sequence
  for stores that cannot do better; `InMemoryRateLimitStore` performs it atomically per key
  under `ConcurrentHashMap.compute` and drops events older than `since` on the way, so buckets
  no longer grow beyond the window. The store is bounded (`CapacityBound.DEFAULT_MAX_ENTRIES`,
  constructor overload) and evicts the key seen first in constant amortised time.
  `InMemoryRateLimitPolicy.tryAcquire` uses `tryAdmit`.
- **Abuse monitor.** Each of the three pattern maps is bounded (constructor overload with
  `maxTrackedKeys`, default `DEFAULT_MAX_ENTRIES`), the key seen first is evicted at the bound,
  and `purgeIdle(now)` removes keys whose observations all lie outside their window.
- **Refresh-token families.** `InMemoryRefreshTokenFamilyStore` is bounded for current and
  revoked families alike and forgets a revoked id after a retention (default seven days);
  constructor overload with capacity, retention and clock.
- **OIDC session registry.** `SessionRegistry` gains `unregister(sessionId)`; the in-memory
  registry implements it, is bounded, and forgets the session registered first at the bound.
  `terminate` now drops the terminated ids from the registry entirely. The new
  `VaadinSessionRegistryCleanup` (`jCustos-identity-oidc-vaadin`) is a `SessionDestroyListener`
  that unregisters the RP session when Vaadin destroys it — register it once per service.
  Implementers of `SessionRegistry` must add `unregister`; the in-memory registry is the only
  one shipped.
- **OAuth2 state in the Vaadin session.** `VaadinSessionStateStore` drops expired entries on
  every `bind` and caps pending states per session (default 32; constructor overload); at the
  cap the state expiring soonest goes first. `pendingCount()` reports the current size.

Verified: 200 000 distinct keys keep each store within its bound; 50 threads against a limit of
10 admit exactly 10; the registry is empty after every session is unregistered; with the atomic
admission and the bound removed, the new tests fail.

## Audit lines carry a session reference, not the live session id (ER12, JS-SEC-079, CWE-532)

The Vaadin adapter fills `SessionContext.sessionId` with the value of the servlet session cookie,
`TimeoutSessionPolicy` passes it into `SessionCreated`, and `LoggingAuditSink` wrote it as
`session=…` into the INFO line — likewise for `LoginSucceeded`, `LogoutPerformed`,
`SessionExpired`, `SessionInvalidated` and `SessionStale`. Anyone who reads the audit log — log
shipping, SIEM, support — could take over a running session. Tokens and API keys already
followed the hash convention.

`LoggingAuditSink` now writes `sessionRef=`, the marker `sref-` followed by the first 16 hex
characters of the SHA-256 of the session id (`SessionRef`, JS-SEC-117): stable for correlating
events of one session, useless for hijacking. The change is
confined to the sink; the audit events still carry the id for stores and consumers that need
it, and `LoggingAuditSink.sessionRef(String)` is public so dashboards and tests can compute the
same reference. Verified with a real recording SLF4J logger: a `SessionCreated` with session id
`ABCDEF0123456789` produces a line without that substring but with a deterministic `sessionRef=`,
and two events with the same id share the reference.

## A missing audit service is announced, not silently swallowed (ER13, JS-SEC-080, CWE-778)

`JCustosServiceResolver.securityAuditService()` fell back to `NoopJCustosAuditService.INSTANCE`
without a word when no `JCustosAuditService` was registered: every `publish` succeeded and nothing
was recorded. The resolver recognised the fallback by identity only, so a
`new NoopJCustosAuditService()` — which the DX bootstrap constructs for the session policy — read
as a configured audit service. The DX bootstrap reported an empty `.audit(a -> {})` but said
nothing when `.audit(...)` was never called at all.

The first fallback now logs one WARN `audit/noop-fallback` per JVM through the shared logger;
`findJCustosAuditService()` treats any `NoopJCustosAuditService` — the shared instance or a fresh
one — as "nothing configured"; and the DX bootstrap adds `audit/noop-fallback` when neither
`.audit(...)` nor a registered service exists: an ERROR in STRICT, a WARNING in every other mode. The Noop fallback is no longer cached: a
negative `ServiceLoader` result on a thread with the wrong context class loader no longer cements
itself, and a service that becomes visible later is picked up by the next lookup.
**STRICT consumers:** a STRICT bootstrap that never configured audit now fails at `install()` —
call `.audit(a -> a.logging())` (or `.ringBuffer(n)`, `.storeBacked(...)`) or register a
`JCustosAuditService` via `META-INF/services`. Verified with isolated contexts and the real DX
adapter: no SPI yields the Noop plus exactly one warning, a repeated fallback does not warn again, a service
set afterwards wins, and
an explicitly set Noop no longer reads as configured.

## Restrictions on super-interfaces are inherited; `SecuredProxy` honours deny-by-default (ER14, JS-SEC-081, CWE-862)

`JCustosAnnotationScanner` walked only the superclass chain. An interface has no superclass, so a
sub-interface that redeclared or added methods shed the `@RequiresRole` or `@RequiresPermission`
declared on its super-interface — and `SecuredProxy.wrap(...)` guards exactly such interface
types. `JCustosEnforcer.enforce(...)` returned silently whenever no restriction was found, even
with `JCustosServiceResolver.setDenyByDefault(true)`, which the REST filter and the Vaadin
navigation listener already honoured: a proxied service was allow-by-omission while the rest of
the application was deny-by-default.

The scanner now walks the implemented interfaces after the superclass chain, in declaration
order, with the most-derived restriction still winning. Under deny-by-default the enforcer denies an
element without a restriction unless it, or its class, carries `@PublicRoute` — the same opt-out
the other adapters use. Verified through the real dynamic proxy: a method redeclared on a
sub-interface and a method declared only there are both denied without the role of the
super-interface and pass with it; with deny-by-default an unannotated method throws
`AccessDeniedException`, a `@PublicRoute` method passes, and allow-by-omission is unchanged.

## Session lifetime and version drift are enforced on every RPC, not only on navigation (ER15, JS-SEC-082, CWE-613)

`SessionLifetimeListener` and `JCustosVersionEnforcerListener` were pure `BeforeEnterListener`s.
Vaadin RPC — button clicks, grid paging, `@ClientCallable` — travels through the UIDL handler and
never reaches `beforeEnter`, so a session past its absolute lifetime or with revoked roles kept
working inside the current view for as long as the user stayed there. The reverse was true as
well: only navigations advanced the last-activity marker, so a user working in one view was
logged out as idle on the next route change.

Both listeners now also implement Vaadin's `RequestHandler`. `SessionLifetimeListener` registers
itself through `ServiceInitEvent.addRequestHandler` and evaluates the policy on every UIDL
request ahead of the framework handlers; on idle timeout or absolute lifetime it drops the
subject, audits `SessionExpired`, sends the browser to the login route (the registered
`LoginListener`'s view, otherwise the resolver's login route, with the context path) and closes
the session. The request itself is never consumed. `JCustosVersionEnforcerListener` does the same
on drift — subject dropped, snapshot cleared, `SessionStale` audited, redirect to the reroute
target, session closed; applications register the same instance via
`ServiceInitEvent.addRequestHandler(listener)` (the two demos show it). Vaadin's
`VaadinSession.getLastRequestTimestamp()`, stamped by `ServerRpcHandler` on every serviced UIDL
request, now counts as activity next to the listener's own attribute; heartbeats do not.
Verified with browserless tests that drive the handlers with the UIDL mock request the servlet
would hand over: after the absolute lifetime an RPC drops the subject, audits
`AbsoluteLifetimeExceeded` and closes the session; before expiry it keeps the subject and records
the activity; a heartbeat changes nothing; a drifted version snapshot is enforced on the RPC. A
unit test shows that a 40-minute-old RPC stamp keeps a 45-minute-old session alive under the
30-minute idle default, and that the same navigation is an idle timeout without the stamp.
Browserless component events bypass the request pipeline, which is why the tests call the
handler directly instead of clicking.

## Navigation and action audit events carry the resolver's subject id, never an identity hash or `toString()` (ER16, JS-SEC-083, CWE-778, CWE-532)

`VaadinAccessContextFactory` built the `JCustosSubject` of every navigation decision from
`subject.getClass().getSimpleName() + "@" + identityHashCode` and used `subject.toString()` as the
display name, and `StaticActionAuthorizationService` audited `ActionDenied` with the same identity
handle. `AccessGranted`, `AccessDenied`, `StepUpChallenged` and `ActionDenied` therefore carried a
value such as `DemoUser@3f2a1b` that changes per object instance and cannot be correlated with
`LoginSucceeded` or `SessionExpired`, which already go through the `SubjectIdResolver`
(JS-SEC-004). Worse, `toString()` — the PII source R019 closed elsewhere — flowed into the
`AccessContext` of every evaluator as the display name.

Both paths now derive the subject id from the registered `SubjectIdResolver`; the display name is
the same value. Without a resolver (or with a blank result) the non-PII identity handle remains —
`toString()` is never used. `StaticActionAuthorizationService` gained a third constructor argument
for an explicit `SubjectIdResolver<U>`; the two-argument constructor keeps using the registered one.
Verified with a registered resolver and a subject whose `toString()` carries a credential: the
navigation context and the `AccessGranted` event carry the resolver value without an `@` suffix, no
audit field contains the credential, and `ActionDenied.subjectId()` equals
`resolver.resolve(user).value()` for both the explicit and the registered resolver. A shared facade
for the four places that derive subject ids (session policy, lifetime listener, context factory,
action service) is the subject of ER30.

## The Vaadin bootstrap's login route is honoured; logout defaults follow it and carries the session id (ER17, JS-SEC-084, CWE-684)

`VaadinJCustosBootstrap.loginRoute(...)` was recorded and then discarded at `install()`:
`JCustosServiceResolver.setLoginRouteName` had no caller outside core, so an application with
`.loginRoute("signin")` was still sent to `login` on an unauthenticated navigation and ended in
`RouteNotFoundError`. `.subjectType(...)` and `.securedComponents()` were equally inert. The
convenience constructor of `VaadinLogoutService` redirected to a hard-coded `/login`, and the
`SessionPolicy.onLogout` notification carried `sessionId == null` although the wrapped session id
was at hand — the logout audit could not be correlated with the login.

`install()` now publishes the login route to the resolver (and lists it as
`bootstrap-login-route=…` among the registered services), so `AuthorizationListener`, the
session-lifetime listener and the logout default all send users to the configured route.
`.subjectType(...)` has a consumer: it is checked against the authentication service's subject type
and a mismatch is reported as `bootstrap/subject-type-mismatch`. `.securedComponents()` is
deprecated for removal — the secured components never needed the opt-in. `VaadinLogoutService` gained
a constructor `(SubjectStore, Class<U>, VaadinLogoutGateway)` that redirects to
`"/" + loginRouteName()` resolved at logout time; the two-argument constructor uses it with the
default gateway. `VaadinLogoutGateway` gained the default method `currentSessionId()` (the default
gateway returns the wrapped session id), and the logout service passes it into the
`SessionContext` given to `SessionPolicy.onLogout`, so `SessionInvalidated` names the session that
`SessionCreated` named. Verified: a bootstrap with `.loginRoute("signin")` yields
`loginRouteName() == "signin"` and an anonymous browserless navigation to a `@RequiresRole` route
ends on the signin view; logout through the new constructor calls `gateway.redirectTo("/signin")`;
the `SessionContext.sessionId()` handed to the policy equals the gateway's session id, which for the
default gateway is the wrapped session id.

## `denyByDefault(boolean)` on every bootstrap; STRICT and PRODUCTION report allow-by-omission (ER18, JS-SEC-085, CWE-1188)

No bootstrap builder offered a deny-by-default switch, although the resolver's Javadoc asked
production applications to turn it on at bootstrap. With the flag off the adapters' startup
cross-checks returned without a finding — in STRICT too — so a `.mode(STRICT)` application with
handler discovery booted green while every unannotated handler was public.

`CommonJCustosBootstrap` gained `denyByDefault(boolean)`; `install()` publishes the value through
`JCustosServiceResolver.setDenyByDefault` before the adapter cross-checks run and lists it as
`bootstrap-deny-by-default=…` among the registered services. When the flag is off at install time,
the bootstrap reports `authorization/allow-by-omission` — an ERROR in STRICT (the install fails), a
WARNING in PRODUCTION, nothing in the development modes. **STRICT consumers:** a STRICT bootstrap
now has to call `.denyByDefault(true)` (and mark public entry points with `@PublicRoute`) to boot.
Verified with the real REST adapter: STRICT without the switch throws with the finding, STRICT with
`.denyByDefault(true)` and fully annotated handlers boots, PRODUCTION records the warning and boots,
DEVELOPMENT stays silent.

## Every REST filter renders its 401 through the configured mapper, with a challenge and an audit event (ER19, JS-SEC-086, CWE-778)

`RestAuthenticationFilter` and `RestJCustosVersionFilter` wrote status and body themselves. A
bootstrap configured with `.errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)` or
`.decisionMapper(...)` therefore changed the answers of `RestAuthorizationFilter` only: the other
two filters kept replying with the plain text `Unauthorized`, the authentication filter sent its
401 without a `WWW-Authenticate` challenge, and an anonymous request it turned away left no audit
event at all.

All three filters now render through the mapper published to `RestDecisionContext`, falling back
to `HttpStatusDecisionMapper`. That mapper adds `WWW-Authenticate: Bearer` to every
`Unauthenticated` 401 (RFC 7235 §3.1, new constant `HttpStatusDecisionMapper.BEARER_CHALLENGE`);
the version filter replaces it with its more specific `SessionStale` challenge.
`RestAuthenticationFilter` publishes an `AccessDenied` with reason `Unauthenticated:no-subject`
for a request without a subject; an expired session keeps its `SessionExpired` event. The mapper
renders a refusal and does not decide it: neither filter runs the handler, whatever the mapper
returns. **Consumers:** clients and tests that expected a 401 without a `WWW-Authenticate` header
now see `Bearer`, and audit trails gain one `AccessDenied` per anonymous request stopped by the
authentication filter. The mapper sets the problem+json body, not the `Content-Type` header — that
remains the job of the application's response adapter. Verified with the real REST bootstrap and
the three real filters: each answers a 401 with
`{"type":"about:blank","title":"Unauthorized","status":401}`, and the audit trail holds the
`AccessDenied` and the `SessionStale` event.

## `X-Forwarded-For` on several header lines no longer lets the client choose its address (SA13, JS-SEC-113, CWE-348, CWE-290)

`TrustedProxyClientAddressResolver` reads `X-Forwarded-For` from the right, but the REST path handed
it a single-valued header map, and every shipped adapter kept only the first of several lines. A
proxy that adds its own line instead of merging — HAProxy with `option forwardfor` — was thereby
dropped, and the line the client had sent decided the address: throttle buckets, audit lines and
`ipAllowList` policies followed a forged value.

`RestRequest` gains `headerValues(String)`, `RestClientAddress` resolves through it, and the
contract of `RestRequest.headers()` now states that repeated list headers are joined with `", "`
(RFC 9110 §5.3) while a repeated `Authorization`, `X-Api-Key` or `Cookie` is rejected with `400`;
the new `RestHeaderLines` implements both for an adapter. `ClientRequestView.of(String, Map)` is
deprecated in favour of the multi-valued factory, and `BearerTokenExtractor` yields no token when
`Authorization` arrives twice. **Consumers:** an adapter that reduces headers to their first line
must be changed — override `headerValues` or build `headers()` with `RestHeaderLines.joined(...)`;
as an immediate measure let HAProxy replace the header with `http-request set-header X-Forwarded-For
%[src]` (see `docs/security/deployment/reverse-proxy.md`). Verified over a real socket against a JDK
`HttpServer`: two lines, the client's first, resolve to the proxy's value, and an `ipAllowList`
policy denies.

## Policy paths require an authenticated subject (SA57, JS-SEC-157, CWE-306, CWE-684)

`JCustosEnforcer.requirePolicy` promised an `AccessDeniedException` when no subject is bound, but
evaluated the policy with an empty subject, and `RequiresPolicyEvaluator` did the same. A policy
that looks at no subject — `JCustosPolicies.timeWindow`, `ipAllowList` — therefore admitted
anonymous callers: a route carrying only `@RequiresPolicy("business-hours")` was open to everybody
during business hours.

Both paths now answer a request without a subject as unauthenticated before the policy is consulted:
`RequiresPolicyEvaluator` returns `Unauthenticated("no-subject")`, `requirePolicy` throws. A policy
that is meant to decide anonymous requests says so explicitly, with `PolicyBuilder.allowAnonymous()`
or `JCustosPolicies.anonymous(policy)`; `Policy.allowsAnonymous()` and
`PolicyRegistry.allowsAnonymous(name)` expose the opt-in. **Consumers:** an anonymous request to a
policy-protected REST route now receives `401` with a `Bearer` challenge instead of `403`, and
deployments that relied on a subject-free policy as a public gate must opt that policy in. A custom
`PolicyRegistry` whose `find` does not return its policies overrides `allowsAnonymous(String)` to
opt in. With a subject nothing changes.

## The REST version filter records a session reference, never the bearer token (SA17, JS-SEC-117, CWE-532, CWE-522)

`RestJCustosVersionContext.sessionId` was documented as an "opaque session identifier (token,
session id, …)", and the reference resolver filled it with the raw bearer token.
`RestJCustosVersionFilter` passed it on to `JCustosVersionEnforcer`, which stores it verbatim in the
`SessionStale` event; only `LoggingAuditSink` reduced it to a reference (ER12), while the ring
buffer, store-backed audit and the integrity chain kept a credential that remains valid in the token
store after the drift.

The filter now hashes at the producer: the event carries
`RestJCustosVersionFilter.sessionReference(sessionId)`, the marker `sref-` followed by the first 16
hex characters of the SHA-256 — the value `LoggingAuditSink.sessionRef` computes. The Javadoc of `RestJCustosVersionContext`,
`JCustosVersionEnforcer` and `SessionStale` now says that the identifier must be non-secret, never
the token itself. **Consumers:** `SessionStale.sessionId` of REST events is a reference from
00.84.00 on; anything that compared it with its own session id must compute the same reference.
Verified with the real filter and the real composite audit service: after a version drift no field
of the event contains the token, and two events of one token share the reference.

## `PostLogoutRedirectValidator.allowOnly` compares the host in every case (SA19, JS-SEC-119, CWE-601, CWE-20)

`allowOnly` promised an exact comparison of scheme, host, port and path, but fell back to an empty
host when `URI.getHost()` returned `null`. That happens for names Java does not accept as a server
authority — an underscore as in `my_app.example.com` is enough — and an allow-list with such an
entry matched every other unparsable host with the same scheme and path, for instance
`https://evil_site.attacker.test/bye`.

An `http`/`https` entry without a parsable host is now refused with an `IllegalArgumentException`
when the validator is built, and a candidate without one is never allowed. URIs with user
information (`https://anything@app.example.com/bye`) are refused on both sides, and the default port
is normalised, so `https://app.example.com:443/bye` matches the entry without a port. Non-web
schemes with an unparsable host compare on the raw authority, opaque URIs on their scheme-specific
part. **Consumers:** an allow-list containing an underscore host or user information now fails at
start-up; use a name `java.net.URI` parses. The default validator `permitAll()` is unchanged.

## The OAuth2 REST callback is bound to the browser by default, and the binding cannot be weakened (SA20, JS-SEC-120, CWE-352, CWE-565)

The two-argument constructor of `OAuth2CallbackHandler` installed `CallbackStateBinding.unbound()`
and merely logged a warning: any caller presenting a still-open `state` completed the login, which
is the login CSRF the binding of 00.81.00 was introduced to stop. That constructor now binds with
`CallbackStateBinding.hostCookie()`; a callback without the `__Host-JCustosOAuth2State` cookie is
answered with a generic `400` and the single-use `state` stays unconsumed. An integration that binds
`state` itself says so by name with `OAuth2CallbackHandler.withoutUserAgentBinding(flow, sink)`, and
every handler built without a binding logs `oauth2/state-unbound`.

The cookie binding itself is tightened: `hostCookie(String)` and `hostCookieHeader(String, String)`
reject names without the `__Host-` prefix — without it the browser guarantees neither the host
binding nor `Path=/` — and a callback carrying the binding cookie twice, or several `Cookie` header
lines, does not match. **Consumers:** code that used the two-argument constructor must emit
`CallbackStateBinding.hostCookieHeader(state)` when it starts the flow, or switch to the explicitly
unbound factory; custom cookie names need the `__Host-` prefix.

## A reset request no longer locks the account (SA21, JS-SEC-121, CWE-645, CWE-640, CWE-799)

`credential.reset.PasswordResetService.issue` moved an `ACTIVE` credential to `RESET_PENDING`, and
nothing ever moved it back: anyone who knew a username could close the password login of its owner,
and every further request retired the link the owner had just received. A reset request is
unauthenticated, so it now leaves the status of a usable credential alone; the reset runs alongside
the password login until `consume` replaces the password. Only a `COMPROMISED` credential still
enters `RESET_PENDING` (JS-SEC-076), and it returns to `COMPROMISED` when its last open link lapses
— adapters trigger that check with `releaseLapsedReset(username)`.

The service gained a throttle seam, `withAbuseDetection(...)`: a request the throttle refuses issues
no token and retires no link, while an accepted request still makes the older links worthless. The
per-username counter for `RESET_REQUEST` in `InMemoryAbuseDetectionService` now counts accepted
requests instead of being cleared by them, so the documented limit (delay from the fourth, block
from the seventh request per hour) applies to existing accounts for the first time. **Consumers:**
integrations that read `RESET_PENDING` as "reset outstanding" for ordinary accounts no longer see
it; accounts that an earlier version left in `RESET_PENDING` leave it through a completed reset.
`ResetTokenStore` gained default methods a third-party store may override.

## Token-bearing records no longer print their token (SA27, JS-SEC-127, and ER21, JS-SEC-088, CWE-532)

Seven records relied on the compiler-generated `toString()` and with it printed a reusable secret
into any log line or exception message that stringified them: `HeaderValue`,
`TokenService.TokenPair`, the three `IssuedToken` records of the remember-me, password-reset and
email-verification services, `JCustosNotification` with its `tokenPlain` attribute, and
`CreateInitialAdminCommand`. All of them now mask the secret and keep the other components readable.
Which notification attributes count as secret is decided in one place,
`JCustosNotification.isSensitiveAttribute`, used by the record and by `LoggingNotificationSender`
alike. A structural test walks every record of `jCustos-core` and fails when one with a
secret-bearing component keeps the generated `toString()`, so the next record of this kind cannot
slip through.

## Password change and reset invalidate what the old password issued (SA28, JS-SEC-128, CWE-613, CWE-640, CWE-367)

A reset link issued before a password change stayed valid after it, neither flow revoked sessions or
tokens, and `consume` wrote the new hash before it claimed the token, so two requests with one link
could both write a password. `PasswordChangeService.withResetTokenStore(...)` now retires the open
links of the account after a change, and `consume` claims the token first and writes only when the
claim succeeded; a token whose claim succeeded stays spent. Both services accept an optional
`CredentialChangeListener`; the shipped `RevokingCredentialChangeListener` raises the subject's
security version and revokes its remember-me and refresh tokens.

`StoreBackedRememberMeService.rotate` exchanges a remember-me token on every use, and a token that
was already exchanged revokes all remember-me tokens of the subject when it is presented again —
with a store that records rotated tokens, which both shipped stores do (the Eclipse-Store store
since the addition further down). All of this is
additive: an application that does not configure the new collaborators behaves as before, except
that a reset token whose claim succeeded is spent even when the hash write then fails.

## A revocation during refresh-token rotation is no longer lost (SA29, JS-SEC-129, CWE-367, CWE-613)

`TokenService.rotate` checked a token, claimed it and stored its successor in three separate store
calls; a logout between check and claim was ignored, and a `revokeAll` between claim and save left
the successor alive. `RefreshTokenStore` gained an atomic `rotate(oldHash, successor, now)` that
claims only a record which is neither replaced nor revoked nor expired and stores the successor in
the same step, and `revokeAll` now leaves an "invalid before" mark that refuses tokens from
operations that started earlier. The in-memory and the Eclipse-Store implementation provide both; a
third-party store inherits default methods that keep the earlier behaviour and should override them
— the testkit contract checks the new operations (`implementsAtomicRotation()` opts out).

Revoking a token that was already rotated now also revokes its successors, and the family walk after
a replay re-reads each record after revoking it. **Consumers:** `TokenService.issue` throws an
`IllegalStateException` (`authentication/refresh-token-superseded`) in the rare case that a
`revokeAll` for the same subject overtook it; `EclipseStoreJCustosRoot` gained the field
`refreshTokenInvalidBefore`, which roots stored before 00.84.00 receive on first use.

## A planted bootstrap token file is not adopted (SA30, JS-SEC-130, CWE-345, CWE-732, CWE-613)

In `PERSISTENT_FILE` mode start-up reused whatever token file it found, and a creation instant in
the future never expired — a local user with write access to the token path could plant a token and
create the first administrator with it. `FileBootstrapTokenStore.load()` now adopts a file only when
it can have been written by the store itself: on POSIX a regular file owned by the process user with
no access for group or others, and on every platform a token in the generator's format. A rejected
file is reported with a warning and treated as absent, so start-up generates a fresh token and
replaces the file; a creation instant more than five minutes ahead counts as expired. On filesystems
without POSIX attributes owner and permissions still cannot be checked (JS-SEC-016). **Consumers:**
token files that were written by hand or provisioned with wider permissions are no longer accepted;
on a read-only mount start-up then fails when it tries to replace the file.

## The `@Secured` processor guards every restriction annotation and honours deny-by-default (SA56, JS-SEC-156, CWE-862, CWE-1068)

`SecuredAnnotationProcessor` lowered five annotations and nothing else. `@ProtectedBy` on a method
and every consumer-defined annotation that is meta-annotated with `@JCustosAnnotation` produced a
plain `super` call without a compiler message, an annotated `protected` or package-private method
was left out of the wrapper altogether, and deny-by-default had no effect, because the wrapper
called the explicit enforcer API instead of `JCustosEnforcer.enforce` — while `SecuredProxy`
enforced all of it at run time. The wrapper now routes every restriction it does not lower natively,
every restriction inherited from a superclass or an interface, and every method without a
restriction through `JCustosEnforcer.enforce(Method, Class)`; the `Method` is resolved once in a
static field, and a wrapper that cannot resolve it fails its class initialisation instead of running
unguarded.

A restriction annotation on a method the wrapper does not override — `final`, `static`, `private`,
`protected`, package-private, an `Object` method, or one excluded through `@SkipProxy` or
`excludeMethodNames` — is the compile error `processing/unenforceable-security-annotation`, and a
native and a custom restriction on one element fail with `processing/multiple-security-annotations`.
**Consumers:** builds that relied on such an annotation being ignored fail until the method is made
public or the annotation is removed; with deny-by-default switched on, un-annotated methods of a
generated wrapper are denied unless they carry `@PublicRoute`. A restriction on an interface or
superclass method that the `@Secured` class overrides without repeating it is still not enforced by
the wrapper — repeat the annotation on the overriding method. Verified by compiling, loading and
calling generated wrappers: 432 decisions over seven fixture classes are identical on the
`SecuredProxy` path and in the wrapper.

## bcrypt hashes are NUL-terminated; legacy hashes keep verifying and are rehashed (SA33, JS-SEC-133, CWE-327, CWE-521)

`BcryptPasswordHashProvider` handed the raw UTF-8 bytes of the password to Bouncy Castle's low-level
`BCrypt.generate`, without the terminating NUL byte of standard bcrypt. Blowfish repeats its key
cyclically, so `abc`, `abcabc` and `abcabcabcabc` derived the same hash: a periodic password
verified with its shortest period. New hashes append the terminator and record it in the envelope as
`term=1`; their derived bytes equal OpenBSD bcrypt (`$2a$`/`$2b$`/`$2y$`) for the same password,
salt and cost, proven against Bouncy Castle's `OpenBSDBCrypt` and published test vectors. An
envelope without `term` is a legacy hash: it still verifies in the old framing, so nobody is locked
out, and `needsRehash` reports `PARAMETERS_OUTDATED` for it under every policy whose bcrypt defaults
come from `BcryptDefaults.defaultParameters()`. `hash` now accepts at most 71 UTF-8 bytes (the
terminator takes the 72nd) and rejects the empty password and any password containing U+0000 with
dedicated exceptions; a candidate containing U+0000 never matches a new hash.

**Operators:** the weakness of an existing bcrypt hash ends only when it is rehashed, on the user's
next successful login. A policy that assembles its bcrypt default parameters by hand must add
`term=1` (`BcryptParameterNames.TERMINATOR`) to them to obtain the rehash signal. Rehash code must
expect `BcryptInputTooLongException` for a legacy password of exactly 72 bytes, and
`BcryptNulCharacterException` for one containing U+0000, and ask for a new password. Hashes written
by this release cannot be verified by an earlier one, so a rollback after users have logged in locks
those users out.

## `SecuredUi.component(...)` hides a denied component without `HasEnabled` (SA53, JS-SEC-153, CWE-636, CWE-200)

In the default HIDE mode `SecuredVisibility.apply` called `setVisible(false)` and then
`setEnabled(true)`, and for a component without `HasEnabled` the builder mapped "enabled" to
`setVisible(true)`. A denied `Composite`, custom `@Tag` component or `Icon` therefore stayed visible
to every visitor, with its content and server-side listeners. Enabling such a component is now a
no-op and disabling hides it, and the HIDE branch calls `setVisible(false)` last. Verified for a
`Composite`, a custom `@Tag` component and an `Icon`: hidden for anonymous visitors and subjects
without the role in every mode, visible for an authorised subject.

## An empty role or permission list no longer means "everyone" (SA35, JS-SEC-135, CWE-636, CWE-863)

`SecuredUi.requiresRole()` and `requiresPermission()` accepted an empty array — typically read from
configuration — and produced an empty requirement, which `SecuredVisibility` admitted for every
visitor, anonymous ones included. Both methods now reject an empty array with
`IllegalArgumentException`, and `SecuredVisibility.apply` denies every requirement when no subject
is bound. An empty `Requirement` passed directly to a secured component still admits any
authenticated subject. **Consumers:** an affordance meant for everyone needs no secured component;
code that passed an empty array now fails when the component is built instead of silently opening
it.

## A denial whose reroute target is not registered no longer renders the protected view (SA52, JS-SEC-152, CWE-636, CWE-285)

`AuthorizationListener` answered `Unauthenticated` and `StepUpRequired` with
`event.rerouteTo(route)`. Vaadin treats a reroute to an unregistered route as a no-op, so without a
view under the login route (and no `LoginListener`) or under the step-up route, the protected view
was instantiated and rendered while the audit trail recorded `AccessDenied`. Both decision mappers
now resolve the target first, and the listener enforces a post-condition: every denial that leaves
the event without a reroute or forward target ends in the error view for `SecurityException`. An
application whose login view is registered under another name keeps working, because an anonymous
visitor is forwarded to the login view of the registered `LoginListener`.

The bootstrap reports `vaadin/login-route-unresolved` and `vaadin/step-up-route-unresolved` where
the route registry is readable — a WARNING, and an ERROR in STRICT and PRODUCTION for the login
route and for an explicitly configured step-up route; the default step-up route without a view stays
a WARNING in every mode. **Consumers:** register a view under the step-up route before using step-up
policies, and publish a non-default login route with `.loginRoute(...)`. A `Reroute` marked as
forward to a route that is not a server-side route no longer becomes a client-side forward; it ends
in the error view.

## Restrictions on router layouts and composed annotations are enforced (SA54, JS-SEC-154, CWE-862)

The navigation listener scanned only the navigation target, and the scanner recognised only
annotations carrying `@JCustosAnnotation` directly. `@RequiresRole("ADMIN")` on a parent layout, or
on an annotation type such as `@AdminOnly`, compiled and protected nothing. The listener now
evaluates the restriction of every layout in the chain together with that of the target, and all of
them must grant; the scanner resolves a restriction declared on an annotation type one level deep,
with the "one restriction per element" rule unchanged. `@PublicRoute` on a view does not lift the
restriction of its layout — a public view, the login view and the step-up view have to live outside
a restricted layout.

The start-up discovery uses the same `RouteRestrictionResolver` as the listener, so a route
protected through its layout is no longer reported as un-annotated and policies referenced from
layouts are cross-checked. Composed annotations take effect in the REST and standalone adapters as
well.

## The logout-token validator enforces issuer, audience and the replay window itself (ER20, JS-SEC-087, CWE-287, CWE-294)

`DefaultLogoutTokenValidator` relied on the composed `JwtValidator` for `iss` and `aud`, while the
bootstrap permits a validator without either expectation. Whoever reused such a validator accepted
the logout token of every tenant sharing the signing keys and terminated sessions on a stranger's
request. The validator now takes the expected issuer and client id in its constructor and checks
both itself, as `DefaultIdTokenValidator` has done since JS-SEC-007; a mismatch is reported as
`JwtInvalid` with `claims/iss-mismatch` or `claims/aud-mismatch`. It also requires `exp` and `iat`,
rejects a token issued more than ten minutes ago, and remembers a `jti` until the token itself can
no longer be accepted instead of for a fixed ten minutes. **Consumers:** the constructors without
issuer and client id are deprecated and reject every token — back-channel logout stops working until
the call site moves to `new DefaultLogoutTokenValidator(jwtValidator, issuer, clientId[,
jtiStore])`; a warning `logout-token/no-expectations-configured` is logged at construction. Logout
tokens without `exp` or `iat` are no longer accepted.

## DPoP: bounded proof and `jti`, and the key binding is part of the validation (SA48, JS-SEC-148, CWE-770, CWE-345)

The DPoP proof parser was the one JOSE parser without a size limit, and a sender-chosen `jti` of any
length was kept in clear text in the `JtiStore`, whose capacity counts entries, not bytes.
`NimbusDpopProofValidator` now applies the shared 100 kB limit before parsing — the constants moved
to the new `eu.jsentinel.jcustos.jwt.api.JoseLimits` — and rejects a `jti` longer than 128
characters; `InMemoryJtiStore` records the SHA-256 of a `jti`, never the value. The validation also
covers the key binding: `DpopValidationRequest.boundTo(proof, method, uri, accessToken,
expectedJkt)` names the `cnf.jkt` of the access token, and a proof signed with any other key fails
with the new `KeyBindingMismatch` before its `jti` is recorded. Before, `boundTo` checked `ath`
only, so a thief of a DPoP-bound token could sign a proof with a key of his own. **Consumers:** the
four-argument `boundTo` is deprecated and fails closed; an exhaustive `switch` over
`DpopValidationError` needs a branch for `KeyBindingMismatch`; implementations of `JtiStore` must
keep entries of bounded size.

## JWKS: bounded trust in stale keys, key hygiene, and a `Result` for every signed token (SA49, JS-SEC-149, CWE-672, CWE-326, CWE-476)

`HttpJwksClient` kept serving the keys it held for as long as refreshes failed, so a key the issuer
had withdrawn stayed trusted while the endpoint answered with an error. It now remembers the last
successful fetch and drops the key set after 24 hours without one (configurable through a new
constructor); validation then reports `jwt/unknown-kid` and `jwks/stale-keys-dropped` is logged
once. Keys are taken from the document only if they may verify signatures: a key with a `use` other
than `sig`, with `key_ops` lacking `verify`, or an RSA key below 2048 bit is skipped, and a key that
declares an `alg` verifies only tokens of that algorithm. `NimbusJwtValidator` refuses an RSA key
below 2048 bit from any `JwksClient`, drops JSON `null` claims instead of throwing a
`NullPointerException`, and turns any late `RuntimeException` into `MalformedJwt`. **Consumers:** an
issuer that publishes only weak or encryption keys no longer validates.

## GitHub subjects are keyed on the numeric account id only; pass-through honours the declared audience (SA51, JS-SEC-151, CWE-290, CWE-441)

`GitHubProfile` promised to key a principal on GitHub's immutable numeric account id, yet accepted
any non-blank `sub` — even with the numeric `id` present. An integrator's adapter that put the
`login` into `sub` therefore produced `github#<login>`, a name that can change hands. The profile
now reads the numeric `id` first, accepts a `sub` only if it consists of digits, and throws
otherwise. `PassThroughStrategy`, the default of `@PropagateToken`, ignored the declared audience
and forwarded the caller's token unchanged to any downstream service; with a declared audience it
now forwards the token only when it is known to be issued for that audience and logs
`propagation/audience-mismatch` otherwise. A call without a declared audience keeps forwarding and
is reported once as `propagation/pass-through-without-audience`. **Consumers:**
`@PropagateToken(audience = …)` with pass-through needs an inbound credential whose audience is
known (for example `OidcAccessToken.fromValidated`) — the stock `RestTokenCredentialFilter` binds
one when a `JwtValidator` is configured, see the addition further down; use the `exchange` strategy
for a service outside the token's audience. Subjects stored as `github#<login>` no longer map.

## The authorisation-code flow binds the response to its issuer; a full state store no longer blocks every login (SA50, JS-SEC-150, CWE-346, CWE-770)

The callback of the authorisation-code flow did not know which authorisation server had answered: a
relying party that reaches several issuers through one redirect URI could be led to send the code
and the PKCE verifier of an honest server to the token endpoint of a malicious one.
`OAuth2ClientConfig` now carries an expected issuer (`withExpectedIssuer(issuer, required)`),
`CallbackParams` the `iss` parameter of the response (RFC 9207), and `OidcProviderMetadata` the
discovery flag `authorization_response_iss_parameter_supported`. `HttpAuthorizationCodeFlow` rejects
a response that names another issuer — or none, when the issuer announces the parameter — before it
consumes the state or contacts the token endpoint; the REST `OAuth2CallbackHandler` and the Vaadin
`AbstractOAuth2CallbackView` pass the parameter through, and the view refuses a response that names
several issuers.

`JdkInMemoryStateStore` and `InMemoryNonceStore` used to throw once they were full, so an anonymous
script calling the login start could make every login fail; they now evict the entry that expires
earliest and reclaim expired entries incrementally. **Consumers:** the binding is opt-in through the
configuration — with discovery metadata, `config.withExpectedIssuer(metadata.issuer(),
metadata.authorizationResponseIssParameterSupported())`; a custom callback adapter has to pass `iss`
into `CallbackParams`, and a persistent `StateStore` has to keep `StateEntry.extra`. Code that
relied on the `…-capacity-exceeded` exception no longer sees it.

## Login lockouts survive capacity pressure; the bound is hard (SA22, JS-SEC-122, CWE-307, CWE-770)

`InMemoryLoginAttemptStore` evicted the entry with the oldest failure without knowing whether it was
a live lockout, so a spray of new user names pushed a victim's lockout out of the store and
`StoreBackedLoginAttemptPolicy` let the account be guessed again. `InMemoryLoginAttemptPolicy`
spared locked entries but then had no bound at all once only locked entries remained. Both now sit
on one bounded table: a key that is locked or has an attempt in flight is never evicted, expired
state is removed through an expiry index on the next call, and the number of tracked keys never
exceeds `maxEntries`. When the table is full of live lockouts, an attempt on a further key is denied
with `LockedOut` until the first lockout ends, and `bruteforce/capacity-exhausted` is logged.
`LoginAttemptStore` gained four atomic attempt operations as `default` methods; the in-memory store
and the Eclipse-Store adapter implement them, the latter without a change to the stored format.
**Behaviour:** the store-backed policy now forgets a counter after a full `window()` without
failures, and the in-memory policy forgets a lockout level one `maxLockout` after the lockout ended.

## The login lockout is one atomic step; one key per account (SA23, JS-SEC-123, CWE-367, CWE-307, CWE-178)

`beforeAttempt` only read the counter and the failure was counted after the credential check, so
fifty parallel guesses at a threshold of five were all evaluated, and a late `recordSuccess` removed
a lockout that had set in meanwhile. The shipped policies now reserve the attempt when they allow
it: at most `failureThreshold` attempts are in flight per key, the report releases the reservation,
and one that is never reported lapses after 30 seconds. `LoginAttemptPolicy` gained `confirmSuccess`
(answers `LockedOut` instead of lifting a live lockout), `abandonAttempt` (no verdict, nothing
counted) and `peek` (look without reserving), all as `default` methods. The new
`SubjectKeyCanonicalizer` (NFKC, lower-case, trimmed by default) is used by both login policies and
by `InMemoryCredentialStore`, so `alice` and `ALICE` can no longer be two accounts sharing one
failure counter. **Migration:** every allowed `beforeAttempt` must be followed by exactly one of
`confirmSuccess`/`recordSuccess`, `recordFailure` or `abandonAttempt`; code that used
`beforeAttempt` merely to display a lockout switches to `peek`; `InMemoryCredentialStore` rejects a
second registration that differs only in spelling unless it is built with
`SubjectKeyCanonicalizer.exact()`.

## Login throttling is on by default; switching it off is announced (SA24, JS-SEC-124, CWE-1188, CWE-307)

**Behaviour change for every application that registered no `LoginAttemptPolicy`:**
`JCustosServiceResolver.loginAttemptPolicy()` no longer falls back to `NoopLoginAttemptPolicy` but
to an `InMemoryLoginAttemptPolicy` with the default thresholds — five failures within fifteen
minutes lock the key for fifteen minutes, doubling up to four hours. Until now such an application
ran without any limit on password guessing and without a line in the log. `findLoginAttemptPolicy()`
still reports the default as "not configured". Consumers who relied on no throttling must register
`NoopLoginAttemptPolicy` explicitly; doing so logs one WARN `bruteforce/noop-policy` and makes the
DX bootstrap report `bruteforce/noop-policy` — a WARNING, an ERROR in PRODUCTION and STRICT. The
`NoopLogoutService` fallback is announced once as `logout/noop-fallback` and is no longer cached,
and the bootstrap reports `logout/missing-service` with the same severities. **STRICT consumers:** a
STRICT bootstrap without `.logout(...)` or a registered `LogoutService` now fails at `install()`.

## "Could not verify" is no longer "wrong" (SA26, JS-SEC-126, CWE-703, CWE-645, CWE-636)

When the KDF limiter shed a verification, `DefaultPasswordHashingService` reported
`INVALID_CREDENTIALS`: a flood of anonymous requests that kept the permits busy made correct logins
count as failed attempts and locked the accounts behind them. Shed verifications now return
`TEMPORARILY_UNAVAILABLE`, which the type had reserved for exactly this and never produced.
`CredentialVerificationResult.temporarilyUnavailable()` and
`CredentialVerificationUnavailableException` carry the outcome through boolean contracts;
`StandaloneLoginFlow` gives the attempt back to the policy, records no failure, writes no
`LoginFailed` and lets the exception reach the caller, who answers "try again later".
`PasswordHistoryService` counted every result that was not `Verified` as "not reused", so a
saturated limiter or a retired algorithm switched the history off; the new `check(...)` returns
`Indeterminate` for such entries and `evaluate(...)` rejects the change instead of allowing it.
**Migration:** callers of `verify(...)` that record a failed attempt for every non-`Verified` result
must exclude `temporarilyUnavailable()`; after an algorithm or pepper migration a history entry that
can no longer be verified blocks a password change through `evaluate(...)` until it is resolved —
`check(...)` exposes the reason.

## The per-request session checks take the session lock, consume the request, ignore polls and cover WebSocket messages (SA55, JS-SEC-155, CWE-667, CWE-362, CWE-613)

The fix for JS-SEC-082 was itself defective. Vaadin calls a plain `RequestHandler` without the
session lock, so `SessionLifetimeListener` and `JCustosVersionEnforcerListener` read and wrote
session state unsynchronised, and with `sessionLockCheckStrategy=throw` — which Vaadin applies
outside production mode — every UIDL request ended in "Internal error". Both listeners now take the
lock for their check and, on expiry or drift, consume the request: the identity is cleared, the
Vaadin session closed, the HTTP session invalidated, and the client receives Vaadin's
session-expired message instead of having its RPC executed. Activity is tracked in the listener's
own attribute; an automatic poll (`UI.setPollInterval`) restores the previous value, so a polling
view no longer keeps an unattended session alive, and `getLastRequestTimestamp()` is no longer
consulted.

Both listeners are also `VaadinRequestInterceptor`s, which is the only hook Vaadin calls for
messages sent over a WebSocket-only push channel;
`JCustosVersionEnforcerListener.register(ServiceInitEvent)` wires all three entry points, and a
start-up warning points out that `Transport.WEBSOCKET` cannot rotate a session id. The tests drive
`VaadinService.handleRequest` from a thread without the session lock and with the strict lock check;
the WebSocket path is verified at the service level, not with a live Atmosphere connection.
**Consumers:** the server no longer calls `Page.setLocation(login)` on expiry — the client reloads
on the session-expired message, and `SystemMessages.sessionExpiredURL` can redirect; a listener
registered by hand needs `event.addVaadinRequestInterceptor(listener)` or the new `register(event)`.

## "Revoke" ends the session (SA31, JS-SEC-131, CWE-613, CWE-684)

Pressing Revoke in the session management only removed a record from the `SessionStore`; nothing on
the request path read it, so the revoked user kept working until a timeout, and the wiring the
Javadoc recommended logged out the administrator who clicked. The new `VaadinSessionRevocation` ends
the live session on the same node at once — subject, security-version snapshot and token credential
cleared, `SessionInvalidated` audited with the reason `Revoked`, Vaadin session closed, HTTP session
invalidated — and `SessionLifetimeListener` checks the record of the current session on every client
message and navigation, so a session revoked on another node is refused on its next request.
`SessionManagementContext.publish` registers the store for that check and makes the real termination
the default revoke of `SessionManagementRoute`. A record with the status `EXPIRED` does not end a
session: that status is derived from the lifetime policy, which the listener evaluates against the
live session itself. A store failure during the check is logged and the request proceeds.
**Consumers:** applications that pass their own revoke callback or store must call
`VaadinSessionRevocation.revoke` / `terminate` or register the store with `useSessionStore`. The
REST adapter has its own check, described in the next section but one.

## The federated login rotates the session id (SA46, JS-SEC-146, CWE-384)

`AbstractOAuth2CallbackView` bound the tokens into the session the browser had arrived with and
forwarded; only `LoginView` rotated the session id, in private code. An attacker able to plant a
session cookie in the victim's browser was therefore logged in as the victim after an OAuth2 or OIDC
login. The post-login sequence — id rotation, `SessionPolicy.onLogin`, rotation audit,
`onSessionRotated` hook, security-version snapshot — now lives in the public
`LoginSessionRotation.afterLogin(...)`, which `LoginView` and the callback view both call. The
callback view fails closed: if the id cannot be rotated, the login is undone, `SessionInvalidated`
is audited with the reason `RotationAfterLoginFailed`, the session is ended and the view forwards to
its error target. `LoginView` keeps its "warn and continue" behaviour, with one correction: a
rotation that leaves the id unchanged is no longer reported and audited as a rotation.
**Consumers:** callback views that do not extend the base class must call
`LoginSessionRotation.afterLogin()` themselves.

## OIDC logout reaches the provider, always ends the local session and needs proof of intent (SA47, JS-SEC-147, CWE-613, CWE-460, CWE-352)

`AbstractOidcLogoutView` requested its redirect through `getUI()`, which is empty while a view is
being entered, so the browser never reached the provider's end-session endpoint; locally it removed
the subject only, and not even that when `endSessionEndpoint()`, `logoutRequest()` or
`onBeforeLogout()` threw. The view now redirects through the navigation event's UI and performs the
complete local teardown in a `finally` block: session policy notified, subject, token credential and
security-version snapshot cleared, `LogoutPerformed` audited, Vaadin session closed and HTTP session
invalidated. When the provider URL cannot be computed, the user is logged out locally and sent to
`localLogoutTarget()` (default: the login route) with a warning in the log.

Navigating to the route no longer logs anybody out: the logout runs only with a single-use token
bound to the session, minted by `AbstractOidcLogoutView.logoutLocation(...)`, and otherwise the view
shows a confirmation button. The REST `OidcLogoutHandler` accepts `POST` only (405 with `Allow:
POST` otherwise) and refuses a foreign `Origin` with 403; `withAllowedOrigins(...)` names the public
origins behind a proxy. **Consumers:** existing sign-out links have to be built with
`logoutLocation(...)`; the REST route has to be mapped as `POST`; `onBeforeLogout()` now runs after
the subject has been cleared, as its Javadoc always stated.

## `jCustos-bom` manages the jCustos modules and nothing else (SA39, JS-SEC-139, CWE-1104, CWE-1395)

`jCustos-bom` was a child of the community parent, so importing it also imported that parent's
complete dependency management: the Vaadin BOM and some eighty third-party pins together with their
scopes, 259 entries besides the 37 jCustos modules. An application that imported the BOM could have
its own libraries moved to older, vulnerable versions (Jackson 3.2.0 and 2.22.0, httpclient5 5.6.1)
or have a scope changed without notice. The BOM is now a stand-alone POM without a parent and
manages the 37 library and testkit modules only. **Consumers:** if your build relied on
`jCustos-bom` for the version of Vaadin, SLF4J, Log4j, JUnit or any other third-party library,
declare that version yourself or import the vendor's BOM (for Vaadin: `com.vaadin:vaadin-bom`). A
dependency without a version that the BOM used to cover now fails with "version is missing", which
names exactly the entries to add. The jCustos coordinates and versions are unchanged.

## Jackson is pinned to patched releases and the build rejects vulnerable ones (SA38, JS-SEC-138, CWE-1395, CWE-400)

The inherited parent POM managed Jackson 3 at 3.2.0. That entry took precedence over the version
Vaadin Flow asks for, so every Vaadin-facing module resolved `jackson-core` and `jackson-databind`
3.2.0, which carry nine published advisories between them, three of them rated high. The community
parent now manages both artefacts at 3.2.4, and the Jackson 2 line used in test scope at 2.22.4. A
new enforcer rule fails the build of any module in which a Jackson 3 release below 3.2.4, or a
`jackson-core` or `jackson-databind` 2.x release below 2.22.3, is resolved in any scope.
**Consumers:** applications that depend on `jCustos-vaadin` and build with Maven 4 now receive
Jackson 3.2.4 instead of 3.2.0; with Maven 3 the version declared by Vaadin Flow applies as before.
If you pin Jackson yourself, keep it at 3.1.7 or later on the 3.1 line, or 3.2.3 or later on the 3.2
line.

## Bouncy Castle 1.86 and Jetty Maven plugin 12.1.15 (SA40, JS-SEC-140, CWE-295, CWE-674, CWE-400)

`jCustos-crypto-bc` shipped Bouncy Castle 1.84, which is affected by CVE-2026-8763 (name constraints
bypassed by a trailing dot, rated critical) and CVE-2026-13506 (the ASN.1 nesting guard is reset,
rated high). jCustos itself only calls the Argon2id, bcrypt and scrypt primitives, but the jar is on
the class path of every application that uses the module. It is now 1.86. The Jetty Maven plugin
that runs the demo applications moves from 12.1.8 to 12.1.15, which removes two moderate advisories
from the build. **Consumers:** applications using `jCustos-crypto-bc` receive `bcprov-jdk18on` 1.86;
if you pin Bouncy Castle yourself, do not go below 1.85. Stored password hashes are unaffected.

## The build resolves from Maven Central only, and annotation-only artefacts no longer reach consumers (SA41, JS-SEC-141, CWE-829, CWE-494, CWE-1357, CWE-1104)

Four things are corrected. Both annotation processors depended on `proxybuilder-annotations`
00.11.00, a version that was never published, so the released processors could only be resolved on a
machine that had it installed locally; they now use 00.11.01, which is on Maven Central. The
community parent POM declared three third-party repositories, two of them with snapshots enabled,
and used one plugin without a version; every consumer resolving that POM inherited the repositories.
It now declares Maven Central only, the build no longer forces update checks, and an enforcer rule
fails the build when a repository other than Maven Central and the project's own registry or an
unversioned plugin appears. `spotbugs-annotations`, and with it `jsr305`, was a compile dependency
of every module and therefore of every consumer; it is now provided and optional. The demo
applications no longer package Dropwizard Metrics 4.1.0 and JavaPoet, which arrived through the
annotations artefact.

**Consumers:** `jsr305` and `spotbugs-annotations` disappear from your class path; add them yourself
if your own code uses them. If you wire `jCustos-processor` or `jCustos-propagation-processor` and
declare `proxybuilder-annotations`, use 00.11.01 and exclude `io.dropwizard.metrics` and
`com.squareup:javapoet` from it. Builds that relied on the Vaadin pre-release or add-on repositories
being inherited from the jCustos parent must declare them themselves.

## A trusted key now signs only for the producer it is bound to (SA01, JS-SEC-101, CWE-290, CWE-863)

The consume pipeline resolved the verification key by key id and then applied the producer policy to
the `producerId` the signer had written into the envelope itself. Any trusted key could therefore
sign in the name of any producer and any tenant: a UI process holding only its own key could publish
as the REST service. `JCustosEventVerificationKeyResolver` now has `mayVerify(keyId, producerId,
tenantId)`, and `ConsumePipeline` asks it directly after the signature verified; an envelope whose
key is not bound to the claimed producer is rejected as `KeyNotAuthorizedForProducer` without
touching replay or sequence state. `JdkKeyStoreKeyManagement` binds a key to the producer named like
its alias, or to the producers given with `withProducerBinding`; `InMemoryKeyManagement` can be
confined with a new constructor. **Consumers:** name keystore aliases after the producer id or
declare the binding explicitly. A custom key resolver inherits the default "key id equals producer
id" and rejects everything else until it overrides `mayVerify`. Code that switches exhaustively over
`JCustosEventVerificationResult` has to handle the new variant.

## Rejections of unauthenticated envelopes no longer adopt the envelope's claims and are throttled (SA04, JS-SEC-104, CWE-345, CWE-770, CWE-778)

A rejection that needs no key at all — unknown key, invalid signature, payload hash mismatch —
raised an ERROR event under the tenant the envelope claimed and with its full envelope id, once per
request. Anyone allowed to submit envelopes could fill alert channels and audit stores in a foreign
tenant's name. Such events are now raised under the system tenant, carry the claimed id as
`unverified:` plus at most 64 characters, and are limited to 20 per minute by
`ConsumeFailureHandler`, with the remainder counted in `suppressedUnauthenticatedCount()`.
`EnvelopeWireCodec` rejects textual fields longer than 256 characters. Rejections of authenticated
envelopes are reported as before. **Consumers:** dashboards that group rejection events by tenant
will see pre-authentication rejections under the system tenant. Use
`SelfObservabilityEvents.isUnauthenticatedRejection(event)` to treat them separately, and `new
EnvelopeWireCodec(n)` if your identifiers exceed 256 characters.

## A fresh sequence scope accepts only the first sequence, and verification no longer fails on a stored maximum (SA05, JS-SEC-105, CWE-190, CWE-755)

Without stored state every sequence was accepted as the baseline. One validly signed envelope with
`Long.MAX_VALUE` made the scope unusable for good, and every later `verify()` threw an
`ArithmeticException` although it is documented as total. `SequenceValidator` now accepts a fresh
scope only up to `maxInitialSequence` (default 1), compares without overflow, and `ConsumePipeline`
always returns a result. `JCustosEventSequenceStore.resetSequence` gives operators a way to restart
a scope. **Consumers:** a consumer that joins a running producer with an empty sequence store — for
instance an in-memory store after a restart — must seed the scope with `updateSequence` or configure
`new SequenceValidator(maxInitialSequence, maxTolerableGap)`; until then it rejects with
`SequenceViolation`.

## The payload must describe the event its signed envelope announces (SA07, JS-SEC-107, CWE-345, CWE-863)

The canonical payload repeats event type, event id, tenant, subject and time, but only its hash was
checked. A producer allowed to publish one harmless event type could wrap a payload saying
`RoleAssigned` for another tenant, and a consumer acting on the payload would process it.
`ConsumePipeline` now decodes the payload with the codec of its content type and compares these
fields with the envelope; a deviation, an undecodable payload or an unknown content type is rejected
as `PayloadMetadataMismatch`. `Valid` carries the checked payload. The signature base is unchanged.
**Consumers:** read the event from `Valid.payload()` instead of decoding `canonicalPayload`
yourself. Register additional codecs through the new constructor; envelopes with a content type that
has no codec are rejected. Exhaustive switches need the new variant.

## A failed publish no longer leaves a hole in the sequence, and gaps can be healed (SA08, JS-SEC-108, CWE-754, CWE-400)

The publish pipeline reserved the sequence number before canonicalisation and signing, so every
exception afterwards burnt a number; a strict consumer then rejected everything behind the hole,
permanently. The reservation now happens after canonicalisation, hashing and key access, and is
handed back (`releaseReservation`) if building or signing fails. On the consumer,
`SequenceValidator` can tolerate a bounded gap (`maxTolerableGap`, default 0); an envelope accepted
across a gap is logged as `events/sequence-anomaly-accepted` and counted. Operators can
re-synchronise a scope with `updateSequence` or `resetSequence`. **Consumers:** nothing changes by
default. Configure a tolerance if your transport can drop envelopes, and monitor
`acceptedSequenceAnomalyCount()`. Custom sequence stores should override `releaseReservation`
atomically.

## Dead-letter stores deduplicate identical rejections and bound open records (SA09, JS-SEC-109, CWE-770)

Every rejection stored the complete envelope under a new id, so one captured, expired envelope
submitted repeatedly grew the store without limit — no key required.
`JCustosEventDeadLetterStore.storeOrMerge` now folds a rejection with the same reason and identical
envelope content into the open record, and `DeadLetterRecorder` announces it once.
`InMemoryDeadLetterStore` counts repeats (`occurrences`), holds at most 1000 open records by default
and evicts the oldest (`evictedCount`, WARN `events/dead-letter-evicted`). **Consumers:** resolve
dead letters before the capacity is reached or raise it through the constructor. Custom stores
inherit a scanning default of `storeOrMerge` and should replace it with an indexed one and add their
own bound.

## Log and wire output can no longer be split by Unicode separators (SA10, JS-SEC-110, CWE-117, CWE-93)

`LogFieldScrubber` replaced ISO control characters and the ASCII space only. U+2028, U+2029 and the
non-ASCII spaces passed through, so a user name could add a line or a `key=value` field for any
processor that splits on Unicode line terminators or white space. The scrubber now also replaces
every Unicode white-space and separator character, format characters and unpaired surrogates;
`scrubMessage` does the same for free text while keeping the plain space, and `isLineUnsafe` exposes
the rule. The envelope wire JSON writes U+007F–U+009F, U+2028 and U+2029 as `\uXXXX` escapes.
**Consumers:** scrubbed log fields show `?` for more characters than before. The wire JSON of an
envelope that contains one of the listed characters differs textually but decodes to the same value
in every version, and its signature is unaffected.

## Envelope text must be well-formed; a signed `?` can no longer be swapped for a lone surrogate (SA11, JS-SEC-111, CWE-176, CWE-347)

The signature base encoded strings with `String.getBytes`, which writes `?` for an unpaired
surrogate. `a?b` and `a` + U+D800 + `b` therefore shared one signature, and an attacker on the
transport could alter a signed field containing `?` without detection. Envelopes now reject any
textual field that is not well-formed UTF-16, the wire decoder refuses such strings, and the
signature base encodes strictly; the bytes for well-formed text are unchanged. On publish, an event
whose id, type, tenant or subject is malformed is refused with `EventPublishException` (reason
`malformed-text`) and reported as `EnvelopeRejected`. **Consumers:** validate or replace unpaired
surrogates in user-supplied identifiers before building events; otherwise those events are rejected
at publish and appear as `EnvelopeRejected` with reason `malformed-text`.

## Log line and audit event show the same session reference (SA17, JS-SEC-117, CWE-532, CWE-522)

The REST version filter reduces the session identifier to a reference before the event is built, and
`LoggingAuditSink` reduced whatever it found in the event: for a REST `SessionStale` it hashed the
reference a second time, so the `sessionRef=` of the log line matched no event. The new `SessionRef`
gives a reference a recognisable form — `sref-` followed by the first 16 hex characters of the
SHA-256 — and `SessionRef.of` returns a value of that form unchanged. The sink,
`LoggingAuditSink.sessionRef`, `RestJCustosVersionFilter.sessionReference` and the REST revocation
check all use it; the event records keep their `String` component. **Consumers:** a reference is 21
characters with the `sref-` marker, in the log line and in `SessionStale.sessionId` of REST events
alike; dashboards call `SessionRef.of` to compute it. An identifier of 16 hex characters without the
marker is still hashed.

## The stock REST credential filter binds a token with a known audience (addition to SA51, JS-SEC-151, CWE-441)

Since pass-through honours the declared audience, `@PropagateToken(audience = ...)` forwarded
nothing behind `RestTokenCredentialFilter`, which bound every bearer token as a `BearerToken` of
unknown audience. The filter now keeps a credential that is already bound for the token of the
request, and otherwise validates the token through a `JwtValidator` — the one passed to the new
constructor `RestTokenCredentialFilter(store, validator)`, or the one a `.jwt(...)` bootstrap
installed — and binds `OidcAccessToken.fromValidated(...)`, whose audience is the validated `aud`
claim. Without a validator, or for a token the validator does not accept, it binds a `BearerToken`
of unknown audience as before. `PassThroughStrategy` is unchanged: a token issued for another
audience, or of unknown audience, is not forwarded to a declared one. **Consumers:** applications
with `.jwt(...)` and the stock filter get the known audience without a change, at the cost of one
more validation per request; a resolver that binds the validated token itself avoids it.

## A handler method that is inherited or overridden keeps its restriction (SA14, JS-SEC-114, CWE-862, CWE-863)

`RestAuthorizationFilter` receives a handler as a `Method`, and a `Method` names the class that
declares it. For `@RequiresRole("ADMIN") class AdminHandlers extends CrudHandlers`,
`AdminHandlers.class.getMethod("deleteAll")` is `CrudHandlers#deleteAll`: the scanner looked at the
base class, found nothing, and under allow-by-omission the endpoint was served to everybody, while
`ClassScanningRestHandlerDiscovery` reported the handler class as protected. A method that overrode
a restricted method without repeating the annotation lost the restriction in the same way. The
filter now has overloads that take the handler class, `authorizeAndHandle(request, response,
handler, method, handlerClass)`, and `JCustosAnnotationScanner.scan(Method, Class)` resolves the
method as it runs on that class: the restriction on the method, otherwise the restriction of the
handler class, otherwise the restriction on a declaration the method overrides or implements.
`@PublicRoute` remains the opt-out and is not inherited by an override.

The discovery walks every public method a handler class has, inherited ones included, and asks the
filter's own `isOpenByOmission` for the verdict, so start-up and run time decide with the same code.
**Consumers:** wire handler methods with the handler-class overload — the overloads without it
cannot see the handler class of an inherited method. An un-annotated override of a restricted method
is now restricted in every adapter, `SecuredProxy` and `@Secured` wrappers included; a restriction
on the handler class takes precedence over one on an overridden declaration. Under deny-by-default
the discovery also reports unprotected public methods a handler class inherits.

## A revoked session stops working over REST (SA31, JS-SEC-131, CWE-613)

Nothing on the REST request path read the `SessionStore`: a session whose record an administrator
had revoked was served until its token expired. With a store registered — `.sessions(s ->
s.storeBacked(...))` on `RestSecurity.bootstrap()`, or `RestSessionRevocation.useSessionStore(...)`
— and a resolver that implements the new `RestSubjectResolver.resolveSessionId`,
`RestAuthenticationFilter` and `RestAuthorizationFilter` look up the record before the handler runs.
A record with the status `REVOKED`, or a record that was seen on an earlier request and is gone,
ends the session: the request is answered as unauthenticated through the configured decision mapper
(401, `WWW-Authenticate`, problem JSON where configured), `SessionInvalidated` with the reason
`Revoked` is audited, and the handler does not run. As in the Vaadin adapter, `EXPIRED` alone does
not end a session, a store failure is logged and the request proceeds, and the check never writes
the store.

**Consumers:** nothing changes without a store or without `resolveSessionId`. Record sessions under
a non-secret key such as `SessionRef.of(token)`, never under the token. The memory of seen records
is per node and holds 10 000 sessions; deployments with several nodes revoke by status or switch on
`RestSessionRevocation.requireRecord(true)`, which refuses every session id without a record.
`.storeBacked(...)` on a REST bootstrap is no longer reported as `rest/session-store-unused`.

## The Vaadin `LoginView` consults the login-attempt policy itself (addition to SA24, JS-SEC-124, CWE-307, CWE-1188)

The throttling default of 00.84.00 did not reach an application that used the library `LoginView`
with a plain `AuthenticationService`: the view called `checkCredentials()` directly, and a limit on
password guessing existed only where the service implemented it. The view now runs the complete
protocol around `checkCredentials()` — `beforeAttempt`, then exactly one of `confirmSuccess`,
`recordFailure` or `abandonAttempt` — keyed on the typed user name and on the address of the
registered `ClientAddressResolver`. A locked-out attempt does not reach the credential check; a
`CredentialVerificationUnavailableException` gives the attempt back and counts nothing; a login the
policy refuses after the check (the key was locked meanwhile) is undone: `LoginFailed` is audited
and the session ended with the reason `LoginNotConfirmed`. New hooks: `reactOnLockedOut(lockout)`
and `reactOnVerificationUnavailable()`, both defaulting to `reactOnFailedLogin()`. **Consumers:** an
`AuthenticationService` that calls the `LoginAttemptPolicy` itself now counts every attempt twice
behind this view — remove those calls, as the in-repo demos did, or override
`throttleLoginAttempts()` to return `false` when the service must keep them.

## Abuse detection, password reset and password change act on the account, not on the spelling (addition to SA23, JS-SEC-123, CWE-178)

`InMemoryAbuseDetectionService` keyed its per-username budgets on the raw spelling, so `alice`,
`ALICE` and ` Alice ` each had a reset-request budget of their own. It now applies a
`SubjectKeyCanonicalizer` (new constructor; `defaults()` otherwise), like the login policies. The
reset and change services key what they keep for an account on the name of the record the
`CredentialStore` returned: a link requested as `ALICE` retires the link requested as `alice`, and a
password change requested as `ALICE` retires the reset links and revokes the tokens of the account
`alice` — before, both protections of JS-SEC-074 and JS-SEC-128 could be sidestepped by changing the
case of the name. **Consumers:** reset tokens and the reset audit events carry the account's
registered name; a deployment with case-sensitive names passes `SubjectKeyCanonicalizer.exact()` to
the abuse detection as it does to its store and login policy.

## A shed verification of the current password is "try again later" (addition to SA26, JS-SEC-126, CWE-703, CWE-645)

`PasswordChangeService` reported every result that was not `Verified` as `CurrentPasswordRejected`,
including a verification the KDF limiter had shed. Under load a user who typed the correct current
password was told it was wrong, and an adapter counting failed attempts locked the account. The
service now returns the new `PasswordChangeResult.VerificationUnavailable`; nothing is written, no
reset link is retired and no listener is called. **Consumers:** an exhaustive `switch` over
`PasswordChangeResult` needs a branch for the new variant; answer it with 503 or 429, count no
failure and audit no rejected password.

## A replayed remember-me token is audited (addition to SA28, JS-SEC-128, CWE-778, CWE-294)

When an already exchanged remember-me token was presented again, `StoreBackedRememberMeService`
revoked the subject's tokens and wrote a log line only. It now also publishes `SessionInvalidated`
with the reason `RememberMeTokenReplay` and no session id — the event stands for every remembered
login of the subject. The event goes to the audit service handed to the new constructor, otherwise
to the one registered with `JCustosServiceResolver`; a failing sink is logged and does not undo the
revocation. **Consumers:** nothing to change; alerting on this reason is recommended.

## Store-backed sessions are revocable without the session-management view (addition to SA31, JS-SEC-131, CWE-613)

The Vaadin bootstrap registered the `SessionStore` for the per-request revocation check only
together with `.sessionManagementView(...)`. An application that kept a session inventory but built
its own administration ran without the check, so a record revoked by another node or a tool was not
honoured. `install()` now registers the store whenever `.sessions(s -> s.storeBacked(...))` is
configured and lists it as `bootstrap-session-revocation`. **Consumers:** a record with the status
`REVOKED`, or one that was seen and then removed, now ends the session on its next request in every
such application.

## The route checks run when the bootstrap is called from `serviceInit` (addition to SA52, JS-SEC-152, CWE-636)

The documentation of `RouteNameCheck` and of `vaadin/route-check-unavailable` stated that the route
registry cannot be read during `VaadinServiceInitListener.serviceInit`. That is not so: Vaadin runs
its init listeners with the service as current instance, and a test that starts a real
`VaadinServletService` now shows the login-route check and the deny-by-default discovery working
from inside `serviceInit`. The registry is unavailable only outside a service — a
`ServletContextListener`, a `main` method. Documentation and the suggested fix were corrected; no
behaviour changed. **Consumers:** call `install()` from a `VaadinServiceInitListener` to have both
checks at start-up.

## `LoginListener` recognises a route protected through its layout (addition to SA54, JS-SEC-154)

`LoginListener` still looked at the navigation target only, so `notARestrictedTarget(...)` was
called for a route whose restriction sits on a router layout. It now uses the same
`RouteRestrictionResolver` as the authorisation listener; an anonymous visitor to such a route is
forwarded to the login view by this listener already. No security effect — the authorisation
listener denied the navigation before as well.

## `JCustosEnforcer` checks an inherited method on the class that serves the call (addition to SA14, JS-SEC-114, CWE-862)

`JCustosEnforcer.enforce(Method, Class)` — the call behind `SecuredProxy` and the generated
`@Secured` wrappers — scanned a method on the class that declares it and fell back to the class
passed in only when that found nothing. For a method the class inherits, the restriction of the base
class therefore won over the restriction of the class the call is served by. The enforcer now scans
such a method with `JCustosAnnotationScanner.scan(Method, Class)` as it runs on the class passed in,
and keeps the fallback to that class. `@PublicRoute` on a method still does not lift a class-level
restriction on this path; this differs from the REST filter, where it does, and is unchanged.
**Consumers:** a call on a subclass with a restriction of its own is decided by that restriction,
not by the base class's.

## Rate limiting admits exactly `limit` requests: atomic in the Eclipse-Store store, and equal instants count separately (SA18, JS-SEC-118, CWE-367, CWE-799, CWE-770, CWE-401)

`EclipseStoreRateLimitStore` inherited the two-step default of `tryAdmit` — count under the read
lock, record under the write lock — so parallel requests all read the counter before the first one
wrote; in the analysis 15 to 50 of 50 callers passed a limit of 10. It also kept the events of a key
in a set, which dropped every further event with the same instant: with a clock that ticks coarsely
a limit of 3 admitted 20 of 20 calls. The adapter now counts, prunes and records in one step under
the write lock and keeps the events as an ordered list. `InMemoryRateLimitStore` was rebuilt on one
lock and one map: its separate queue of keys grew with every key that was purged or reset and seen
again, a stale queue entry could evict the bucket a key had just been given anew, parallel inserts
could push the map past its bound, and events that arrived out of order were miscounted. Both stores
evict the key used least recently at the bound, so a key that is being throttled is the last
candidate instead of the first, and hold at most 10 000 events per key
(`InMemoryRateLimitStore.DEFAULT_MAX_EVENTS_PER_KEY`); at that bound `tryAdmit` refuses. The default
of `RateLimitStore.tryAdmit` now serialises its callers on the store instance.

**Consumers:** a third-party `RateLimitStore` should override `tryAdmit` with an operation that is
atomic in its backing store; `RateLimitStoreContract` gained tests for equal instants, out-of-order
events and — with real threads — atomic admission (`admitsAtomically()` opts a store out of the last
one). The eviction order of `InMemoryRateLimitStore` changed from first seen to least recently used,
and all its operations now share one lock.

## Eclipse-Store adapters write the changed entry instead of the whole store, and every request-keyed store is bounded (SA25, JS-SEC-125, CWE-770, CWE-400, CWE-407)

Each adapter kept its data in one `java.util` map and stored that map after every mutation, under
the write lock all security stores share. The n-th failed login with a new user name therefore wrote
n entries: 2 000 of them put 32 MB on the disk, 10 000 more than 1 GB, and a full disk fails every
store, revocation and lockout included. The data now lives in segmented tables (the audit events in
a chunked log): a new key writes one of 1 024 segments, a changed value its own slot, and one
operation is one transaction. The same 2 000 failed logins write under 1 MB, 10 000 about 4 MB.

The stores that are filled by requests are bounded to 100 000 entries each
(`EclipseStoreJCustosStorage.DEFAULT_MAX_ENTRIES_PER_STORE`, configurable through `openAt(Path,
int)` and `JCustosStorageFactory.openAt(Path, StorageLayout, int)`): sessions, remember-me tokens
and refresh tokens drop expired entries first and then the entry stored first; password-reset and
email-verification tokens drop consumed and expired records and then refuse `save` with
`…-token-store-capacity-exceeded`, like their in-memory counterparts; rate-limit keys drop buckets
that left every window applied to them and then the key used least recently. Not bounded, by intent:
audit events (retention stays `purgeOlderThan`), role assignments, security versions, bootstrap
states, API keys and the refresh-token "invalid before" marks.

**Consumers:** the stored layout changed. A storage written by 00.83.x or by an earlier 00.84.00
build is converted when it is first opened (`persistence/storage-layout-migrated` in the log) and
keeps every record; afterwards a release before 00.84.00 can no longer open it — back up the
directory before the upgrade. Installations with more than 100 000 concurrent sessions or live
tokens raise the bound; at the bound the oldest session record is dropped, which the Vaadin
revocation check treats as a revoked session.

## Backups and existing storage directories are owner-only; a foreign storage is refused instead of replaced (SA36, JS-SEC-136, CWE-276, CWE-530, CWE-732, CWE-665, CWE-754)

`issueFullBackup` wrote the copy of the security store with the process umask, usually readable for
every local user, and the owner-only hardening of JS-SEC-017/038 applied only to a directory it
created: a directory that already existed earned a warning and stayed open. On POSIX a backup target
is now created with `0700` (an existing empty one is restricted), an existing storage directory that
belongs to the process user is restricted to its owner when it is opened, and the channel
directories, data files and type dictionary lose their rights for group and others. A storage
directory or backup target that belongs to another user, or cannot be restricted, fails with
`persistence/storage-permissions` or `persistence/backup-permissions`. A storage whose root object
is not a jCustos security root used to be replaced by an empty root without a word; it now fails
start-up with `persistence/foreign-root` and is left untouched. On filesystems without POSIX
attributes owner and permissions still cannot be checked or enforced (JS-SEC-016).

**Consumers:** start-up fails where the storage directory is owned by a different user than the
process (for example a root-owned volume mount) — hand the directory to the process user.
`StorageTreeHardening.hardenOwnerOnly` keeps its signature and never throws, but now restricts an
existing directory it owns; `requireOwnerOnly` and `restrictStorageFiles` are new.

## The Eclipse-Store remember-me store recognises a replayed token, also after a restart (addition to SA28, JS-SEC-128, CWE-613, CWE-294)

`StoreBackedRememberMeService.rotate` revokes all remember-me tokens of a subject when a token that
was already exchanged is presented again — with a store that records rotated tokens.
`EclipseStoreRememberMeTokenStore` inherited the SPI defaults, so with the persistent store a stolen
and already exchanged cookie was merely "unknown" and the thief's successor token stayed valid. The
adapter now implements `markRotated` and `findRotated`: claim and trail are one step under the write
lock and one transaction, the trail is persisted, lives until the consumed token would have expired,
goes with `deleteBySubject` and `purgeExpired`, and is bounded like the other request-keyed stores.
`RememberMeTokenStoreContract` holds both shipped stores to the rotation and replay cases, including
one with 32 parallel presentations of one token. **Consumers:** a third-party `RememberMeTokenStore`
that keeps no trail overrides `implementsRotationTrail()` in its contract test to return `false`.

## Test hygiene: Vaadin sessions in unit tests are strongly referenced

`CurrentInstance` holds the current `VaadinSession` through a `WeakReference`. Four Vaadin
test classes bound an in-memory session and dropped their own reference to it, so a GC pause
between binding and the assertion made `VaadinSession.getCurrent()` return `null` and the
test fail intermittently. The test classes now keep the bound session in a field. No
production code changed.
