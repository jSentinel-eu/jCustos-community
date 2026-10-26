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

## Test hygiene: Vaadin sessions in unit tests are strongly referenced

`CurrentInstance` holds the current `VaadinSession` through a `WeakReference`. Four Vaadin
test classes bound an in-memory session and dropped their own reference to it, so a GC pause
between binding and the assertion made `VaadinSession.getCurrent()` return `null` and the
test fail intermittently. The test classes now keep the bound session in a field. No
production code changed.
