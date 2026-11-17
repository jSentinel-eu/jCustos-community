# Cross-site request forgery (CSRF)

Status: 00.84.00 · CWE-352 (Cross-Site Request Forgery) · `RestOriginGuard` is experimental

A browser attaches some credentials to every request for a site by itself, whichever page
started the request: cookies, cached HTTP Basic or Negotiate credentials, TLS client
certificates. A page on another origin can therefore make the browser of a logged-in user send a
state-changing request - an auto-submitted form, a `fetch` with `mode: "no-cors"` - and the
server sees a request with a valid session. That is CSRF. The attacker never reads the answer;
the side effect is the attack.

CSRF depends on how a request is authenticated, not on the endpoint. This page says which
jCustos surfaces are exposed, what protects them, and what you have to switch on.

## Overview

| Surface | Authentication | Protection | Your action |
|---|---|---|---|
| REST endpoints with `Authorization: Bearer` (the documented REST path, the `jcustos-rest` skills) | header set by the client | not needed (see below) | none |
| REST endpoints whose session rides on a cookie | cookie | `RestOriginGuard`, opt-in since 00.84.00 | install the guard, run it first in the router |
| OAuth2 REST callback (login CSRF) | `state` bound to a `__Host-` cookie | `CallbackStateBinding`, on by default since 00.84.00 (SA20, JS-SEC-120) | none |
| OIDC logout, REST (`OidcLogoutHandler`) | cookie | `POST` only plus the `Origin` check of `RestOriginGuard` (SA47, JS-SEC-147) | map the route as `POST` |
| OIDC logout, Vaadin (`AbstractOidcLogoutView`) | Vaadin session | single-use token from `logoutLocation(...)` (SA47, JS-SEC-147) | build sign-out links with `logoutLocation(...)` |
| Vaadin UI: server round trips, push, uploads | Vaadin session | Vaadin's own CSRF token (see below) | none; never set `disable-xsrf-protection` |

## Bearer tokens: nothing to do

A bearer token travels in the `Authorization` header, and a browser never adds that header on
its own. A foreign page cannot read the token, and it cannot set the header on a cross-origin
request without a CORS preflight that your CORS configuration answers. A CSRF token or the
origin guard would add ceremony and no protection. This changes the moment the token is kept in a
cookie that the server reads: that is a cookie session and belongs in the next section.

## Cookie sessions on REST: `RestOriginGuard`

`eu.jsentinel.jcustos.rest.RestOriginGuard` refuses a state-changing request that a browser sent
on behalf of another origin. It needs no token infrastructure: it reads two headers that the
browser sets itself and that a page cannot forge.

### How it decides

1. **Safe methods pass unchecked**: `GET`, `HEAD`, `OPTIONS`, `TRACE` (RFC 9110 §9.2.1, compared
   case-insensitively). Every other method is checked - `POST`, `PUT`, `PATCH`, `DELETE` and any
   method the guard does not know. An endpoint that changes state on `GET` is not protected; that
   endpoint is the bug.
2. **`Sec-Fetch-Site: same-origin` or `none`** (exactly one header line) passes: the browser
   vouches that the application's own page, or the user, started the request.
3. **Otherwise the `Origin` header decides.** It must name the application's own origin or an
   origin on the allowlist. The comparison is exact on scheme, host and port after normalisation
   (lower case, default port left out): no prefix or suffix matching, so
   `https://app.example.attacker.example` is not `https://app.example`. Refused are the opaque
   origin `null`, a value with a path, user information, query or fragment, and an `Origin` that
   arrives on several header lines.
4. **No `Origin`:** a request that carries `Sec-Fetch-Site` with any other value
   (`cross-site`, `same-site`) is refused, because a browser that sends fetch metadata also sends
   `Origin` with every such request. A request with **neither** header comes from a client that is
   not a browser (curl, a server, a mobile app) and passes by default; the strict setting
   `MissingHeaders.REFUSE` refuses it as well.

The application's own origin is taken from the `Host` header, because `RestRequest` does not
carry the request's scheme: host and port decide, a default port (`80`, `443`) in `Host` counts as
no port, and the `Origin` must be an `http` or `https` origin. Behind a reverse proxy that
rewrites `Host`, name the public origins with `withAllowedOrigins(...)`. The allowlist then
**replaces** the `Host` comparison - list the application's own public origin, too, plus every
origin that calls the API with credentials (the `allowedOrigins` of your CORS configuration).

A refused request is answered with `403` through the decision mapper published to
`RestDecisionContext` (so `.problemJsonErrors()` applies), audited as `AccessDenied` with the
reason `csrf:origin-mismatch` and the request path, and the handler does not run. The audit event
carries the request's correlation id (R5).

### Switching it on

jCustos ships no request pipeline. The guard is the **outermost filter**: the bootstrap registers
it, and the router runs it as the first step of every route, in front of the jCustos filters, the
login handler and every other handler.

```java
RestSecurity.bootstrap()
    .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
    .originGuard(RestOriginGuard.sameOrigin()
        .withAllowedOrigins(Set.of("https://api.example", "https://app.example")))
    // .originGuard(RestOriginGuard.sameOrigin()
    //     .withMissingHeaders(RestOriginGuard.MissingHeaders.REFUSE))   // browsers only
    .install();
```

In the router, before anything else that reads or changes state:

```java
if (RestOriginGuard.installed().map(guard -> !guard.allow(request, response)).orElse(false)) {
  return;                      // 403 written and audited; no filter and no handler ran
}
```

The `Router` of the `jcustos-rest` skill templates contains exactly this step; it is a no-op
until a guard is installed. Without the DX bootstrap, call `RestOriginGuard.install(guard)`
yourself, or keep the guard in a field and wrap handlers with
`guard.guard(request, response, handler)`. `RestAuthenticationFilter`, `RestAuthorizationFilter`
and `RestJCustosVersionFilter` run the installed guard before their own checks as well, so a
route behind one of them stays protected when the router step is missing. **A route that passes
neither the router step nor a jCustos filter is not protected** - a login handler of your own,
say.

`OidcLogoutHandler` applies the same `Origin` comparison on its own (without `Sec-Fetch-Site` and
without the strict setting); it does not need the installed guard.

### Browser support and pitfalls

- `Origin` is sent with every non-`GET`/`HEAD` request by all current browsers.
  `Sec-Fetch-Site` arrived in Chrome 76, Firefox 90 and Safari 16.4. An older browser decides
  through `Origin` alone, which is why the guard does not rely on `Sec-Fetch-Site`.
- With `Referrer-Policy: no-referrer` the Fetch standard sends `Origin: null` on a `POST`, also
  to the own origin. Browsers with fetch metadata still pass through `Sec-Fetch-Site:
  same-origin`; older ones are refused. Pages that post to the API should use the default
  `strict-origin-when-cross-origin` or `same-origin`.
- The strict setting breaks every client that is not a browser. Use it only for APIs that only
  browsers call.
- A script that runs on your own origin (XSS) is same-origin and passes. The guard is no XSS
  defence, and neither is any CSRF token.

### Bootstrap finding

`rest/credentialed-cors-without-origin-guard`: CORS allows credentials (`allowCredentials(true)`)
and no `RestOriginGuard` is installed - neither by `.originGuard(...)` nor by the application
before `install()`. Credentialed CORS means that browsers call the API with a cookie from other
origins; CORS decides who may *read* a response, not who may *send* a request. Severity WARNING in
`PRODUCTION` and `STRICT` (STRICT still boots), INFO otherwise. If the API authenticates with
bearer tokens only, drop `allowCredentials(true)` instead.

## SameSite cookies

`SameSite=Lax` - set by all jCustos Vaadin demos (`web.xml`, SA37) and the default of Chrome for
cookies without the attribute - keeps the cookie off cross-site sub-requests and cross-site `POST`
navigations. It complements the guard; it does not replace it:

- "Site" is the registrable domain. A page on a sibling subdomain (`evil.example.com` against
  `app.example.com`) is *same-site*: the browser sends `Lax` and `Strict` cookies along. The
  guard still refuses it, because `same-site` is not `same-origin` and its `Origin` does not
  match.
- `Lax` cookies are sent with top-level `GET` navigations; a state-changing `GET` stays open.
- A cookie without an explicit `SameSite` attribute may be sent with a top-level cross-site `POST`
  in the first two minutes after it was set (Chrome's "Lax-allowing-unsafe" exception).
- A SPA on another site needs `SameSite=None; Secure`; then the guard and its allowlist are the
  protection.

Set `SameSite=Lax` (or `Strict`) on the session cookie **and** install the guard: the attribute
stops the cookie, the guard stops the request.

## Vaadin needs nothing

Vaadin Flow protects its own requests with a CSRF token. Verified against Vaadin 25.3.3
(`flow-server` 25.3.4), the platform version of this release:

- Every server round trip (UIDL request) carries `csrfToken`; `ServerRpcHandler.handleRpc(UI,
  String, VaadinRequest)` checks it with `VaadinService.isCsrfTokenValid(ui, token)` against
  `UI.getCsrfToken()` (constant-time `MessageDigest.isEqual`) and throws
  `InvalidUIDLSecurityKeyException` on a mismatch. Push messages go through the same handler
  (`PushHandler` calls `ServerRpcHandler.handleRpc`).
- Uploads are accepted only with the security key of the stream receiver
  (`StreamReceiverHandler.handleRequest`, again `MessageDigest.isEqual`).
- The check is on unless the init parameter `disable-xsrf-protection`
  (`InitParameters.SERVLET_PARAMETER_DISABLE_XSRF_PROTECTION`, read by
  `AbstractConfiguration.isXsrfProtectionEnabled()`) is set. jCustos and its demos never set it.

The token is part of the page Vaadin renders for the application's own origin; a foreign page
cannot read it. What Vaadin's token does not cover:

- a servlet or REST endpoint in the same application that shares the session cookie - protect it
  with `RestOriginGuard` or a mechanism of your servlet stack;
- state changed by navigation alone, because entering a route is a `GET`. jCustos' own case, the
  OIDC logout view, needs the single-use token of `AbstractOidcLogoutView.logoutLocation(...)`
  since 00.84.00.

## What jCustos does not provide

- A synchronizer or double-submit token for REST. The decision for 00.84.00 (F12, option b) was
  the origin guard; a token mechanism needs decisions about storage, SPA delivery and expiry that
  the guard does not.
- Clickjacking protection (`Content-Security-Policy: frame-ancestors`, `X-Frame-Options`) - a
  separate header of your server or proxy.
