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

`LoggingAuditSink` now writes `sessionRef=`, the first 16 hex characters of the SHA-256 of the
session id: stable for correlating events of one session, useless for hijacking. The change is
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

## Test hygiene: Vaadin sessions in unit tests are strongly referenced

`CurrentInstance` holds the current `VaadinSession` through a `WeakReference`. Four Vaadin
test classes bound an in-memory session and dropped their own reference to it, so a GC pause
between binding and the assertion made `VaadinSession.getCurrent()` return `null` and the
test fail intermittently. The test classes now keep the bound session in a field. No
production code changed.
