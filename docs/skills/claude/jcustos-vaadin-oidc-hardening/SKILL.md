---
name: jcustos-vaadin-oidc-hardening
description: Layer-5 follow-up to `jcustos-vaadin-oidc` — adds the V00.79 deep-hardening surface to an OIDC Vaadin relying party: **JWE-encrypted ID tokens** (decrypt `JWE(JWS)` ID tokens, e.g. Entra Conditional Access, via `JweUnwrappingJwtValidator` + allow-list), **mTLS client-auth** to the token endpoint (RFC 8705, `MutualTls.sslContext` from a client KeyStore), **OIDC Back-Channel Logout 1.0** (an OP-to-RP `logout_token` endpoint that terminates the right Vaadin sessions out-of-band, via `BackChannelLogoutReceiver` + a `SessionRegistry` that captures each login's `WrappedSession`), and **DPoP** sender-constrained access tokens (RFC 9449, `DpopProofGenerator`) for outbound resource-server calls. Each feature is independently opt-in. Prerequisite: a project that already ran `jcustos-vaadin-oidc`. Use PROACTIVELY when the user mentions DPoP, sender-constrained tokens, mTLS, mutual TLS, client certificate auth, encrypted ID token, JWE, `JweUnwrappingJwtValidator`, back-channel logout, `backchannel_logout`, `logout_token`, single-logout, SLO, "log the user out when they sign out elsewhere", session termination from the IdP, `BackChannelLogoutReceiver`, `SessionRegistry`, PAR, pushed authorization request, JAR, signed request object, "FAPI", "harden my OIDC login", "production OIDC security". Adds dependencies (`jCustos-dpop` for DPoP; mTLS/JWE/back-channel reuse `jCustos-oauth2`/`jCustos-jwt`/`jCustos-identity-oidc` already on the classpath) and ~6 templates (an `OidcClients` replacement wiring JWE + mTLS, a `VaadinBackChannelSessionRegistry`, a `BackChannelLogoutHandler` request handler + its init listener, an `OidcCallbackView` replacement that registers the session, an opt-in `DpopResourceClient`). **PAR (RFC 9126) + JAR (RFC 9101) are documented, not templated** — the primitives exist but the stable `AuthorizationCodeFlow.startRequest` does not yet wire them (it owns PKCE/state), so a clean login integration needs a PAR-aware flow (framework gap, see §Framework feedback). Does NOT cover the OIDC login flow itself — that is `jcustos-vaadin-oidc`.
---

# jCustos ↦ Vaadin Flow — OIDC deep hardening (DPoP / mTLS / JWE / Back-Channel Logout)

This skill hardens the OIDC login produced by `jcustos-vaadin-oidc` with the V00.79
security surface. Every feature is **independently opt-in** — pick what the deployment
needs; none is required for a working login.

| Feature | RFC | What it adds | Risk/effort |
|---|---|---|---|
| **JWE ID tokens** | 7516 | decrypt `JWE(JWS(payload))` ID tokens before validation | low — 1 wrap in `OidcClients` |
| **mTLS token-endpoint auth** | 8705 | present a client cert to the OP token endpoint | low — `SSLContext` on the `HttpClient` |
| **Back-Channel Logout** | OIDC BCL 1.0 | OP tells the RP to kill a user's sessions (single-logout) | **high** — endpoint + session registry |
| **DPoP** | 9449 | sender-constrained access tokens for resource-server calls | medium — opt-in outbound helper |
| **PAR / JAR** | 9126 / 9101 | push / sign the authorization request | documented only (framework gap) |

## How to use this skill

1. Confirm the prerequisite: `jcustos-vaadin-oidc` already ran (there is a
   `…/security/oidc/OidcClients.java`, `…/views/OidcCallbackView.java`, etc.).
2. Ask which hardening features the deployment needs (multi-select — see slots).
3. Render only the templates for the chosen features; merge the POM additions.
4. `mvn compile` + verify per the checklist for each enabled feature.

## Reading the brief — slots

| Slot | Needed for | Example / default |
|---|---|---|
| **Which features** | all | multi-select: JWE / mTLS / back-channel-logout / DPoP |
| **JWE decryption key** | JWE | a `PrivateKey` from the app KeyStore (alias) — the RP's registered encryption key |
| **mTLS KeyStore** | mTLS | PKCS#12 path + password + alias (the client cert registered at the OP) |
| **Back-channel path** | BCL | `/backchannel-logout` (must be registered at the OP as `backchannel_logout_uri`) |
| **Resource server origin** | DPoP | `https://api.example.com` (where DPoP-bound access tokens are presented) |
| **Algorithm profile** | JWE/DPoP | `defaults()` (RSA-OAEP-256 + A128/A256GCM) or `fips()` (RSA-OAEP-256 + A256GCM) |

## Feature 1 — JWE-encrypted ID tokens (RFC 7516)

Some IdPs deliver `id_token` as `JWE(JWS(payload))` (e.g. Entra Conditional Access).
Wrap the existing ID-token JwtValidator in `OidcClients`:

```java
// in OidcClients, when JWE is enabled:
JweDecoder decoder = new NimbusJweDecoder(JweAlgorithmAllowList.defaults()); // or .fips()
JwtValidator idJwt = new JweUnwrappingJwtValidator(baseJwtValidator, decoder, DECRYPTION_KEY);
this.idTokenValidator = new DefaultIdTokenValidator(idJwt);
```

The allow-list is enforced **before** decryption (rejects `RSA1_5`/`dir` downgrades and
`zip`-bombs); a 3-segment plain JWS passes straight through, so this is safe to enable
even if the IdP usually sends unencrypted tokens. `DECRYPTION_KEY` is the RP's private
key whose public half is registered at the OP for ID-token encryption.

## Feature 2 — mTLS client-auth to the token endpoint (RFC 8705)

Build the `OidcClients` `HttpClient` with a client certificate. mTLS is **not** a
`ClientAuthentication` variant — it's TLS-layer:

```java
SSLContext mtls = MutualTls.sslContext(new MutualTlsClientConfig(keyStore, password, alias));
SSLParameters p = new SSLParameters();
p.setProtocols(new String[] {"TLSv1.3"});           // pin — SSLContext alone allows 1.2
HttpClient http = HttpClient.newBuilder().sslContext(mtls).sslParameters(p).build();
```

Use that `http` for discovery + the token-endpoint client. If the OP publishes
`mtls_endpoint_aliases`, remap the token endpoint via
`MutualTls.endpointAlias(aliases, "token_endpoint", fallback)` (https-enforced).

## Feature 3 — OIDC Back-Channel Logout 1.0 (the meaty one)

The OP POSTs a signed `logout_token` to a fixed RP URL when the user logs out
elsewhere; the RP must terminate that user's sessions. Three pieces:

1. **`VaadinBackChannelSessionRegistry implements SessionRegistry`** — a static
   registry mapping `(issuer, sid)` → the user's `WrappedSession`, captured at login.
   `terminate(...)` calls `WrappedSession.invalidate()` out-of-band (it is thread-safe;
   the user's next Vaadin request fails → re-auth). Cleaned on session destroy.
2. **`BackChannelLogoutHandler implements RequestHandler`** — intercepts
   `POST {{BACKCHANNEL_PATH}}`, reads the `logout_token` form param, runs
   `BackChannelLogoutReceiver(new DefaultLogoutTokenValidator(logoutJwtValidator, ISSUER, CLIENT_ID, jtiStore), registry).receive(token)`,
   writes `200` for `Accepted`, `400` for `Rejected` (§2.7). It dereferences **no** URL
   from the token (no SSRF).
3. **`BackChannelLogoutInitListener implements VaadinServiceInitListener`** — registers
   the handler via `event.getSource().addRequestHandler(...)`; also registered for the
   subject store / session capture.

`OidcCallbackView` is replaced to **register the session at login**: after binding the
subject, capture `VaadinSession.getCurrent().getSession()` (the `WrappedSession`) and the
ID-token `sid` claim into the registry. The callback still extends
`AbstractOAuth2CallbackView`, which rotates the session id after `onTokens(...)`; the
rotation keeps the `WrappedSession` object, so the registered handle stays valid.

The validator checks `iss`, `aud`, `exp`/`iat` and the replay window itself (JS-SEC-087) and
needs the expected issuer and client id in its constructor; the constructors without them
are deprecated and reject every token - back-channel logout then stops working.

Security properties: the `logout_token` is fully validated (signature via JWKS, `iss`,
`aud`, the `events` back-channel-logout member, `sub`/`sid`, **`nonce` must be absent**,
`jti` single-use via `InMemoryJtiStore`) before any session is touched.

## Feature 4 — DPoP for outbound resource-server calls (RFC 9449)

If the Vaadin app calls a resource server with the access token, DPoP binds the token to
a key so a stolen token is useless without the key. Opt-in `DpopResourceClient`:

```java
String proof = new DpopProofGenerator().generate(dpopKey, "GET", resourceUri, Optional.of(accessToken));
HttpRequest req = HttpRequest.newBuilder(resourceUri)
    .header("Authorization", "DPoP " + accessToken)
    .header("DPoP", proof)
    .GET().build();
```

On the resource-server side (a server you control) the proof is validated against the
key the token is bound to: `DpopValidationRequest.boundTo(proof, method, uri, accessToken,
expectedJkt)`, where `expectedJkt` is the access token's `cnf.jkt` (JS-SEC-148). A proof
signed with any other key fails with `KeyBindingMismatch` before its `jti` is recorded.
The four-argument `boundTo(...)` without the thumbprint is deprecated and fails closed —
before 00.84.00 it checked `ath` only, so a thief of the token could sign a proof with a
key of his own. Proofs above 100 kB and `jti` values above 128 characters are rejected.

> The access token must itself be DPoP-bound (`cnf.jkt`) by the OP — which requires
> sending a DPoP proof to the **token endpoint**. The stable `HttpTokenEndpointClient` /
> `AuthorizationCodeFlow` do **not** attach a token-endpoint DPoP proof yet (framework
> gap). So this feature is useful today for **presenting** DPoP at a resource server you
> also control; full OP-issued DPoP binding is a V00.80 item.

## Feature 5 — PAR + JAR (documented, not templated)

The primitives exist (`HttpPushedAuthorizationRequestClient`, `AuthorizationRequestSigner`)
but the stable `AuthorizationCodeFlow.startRequest` **owns PKCE + state + nonce** and does
not call them. Re-implementing the login redirect through PAR/JAR would mean
re-implementing PKCE/state outside the flow — fragile. So this skill **documents** the
building blocks and the limitation rather than ship a broken parallel flow. Adopt PAR/JAR
when a PAR-aware `AuthorizationCodeFlow` lands (see Framework feedback). The
hand-assembly, if a team insists:

```java
var par = new HttpPushedAuthorizationRequestClient(parEndpoint, clientAuth, http);
String requestUri = par.push(authParams).getOrThrow().requestUri();   // authParams incl. code_challenge you manage
URI redirect = HttpPushedAuthorizationRequestClient.authorizationRedirect(authzEndpoint, CLIENT_ID, requestUri);
```

## Templates

**Templated (new files):**

| Template | Target | Feature |
|---|---|---|
| `pom-snippet.xml.tmpl` | `pom.xml` (adds `jCustos-dpop` only when DPoP enabled) | DPoP |
| `VaadinBackChannelSessionRegistry.java.tmpl` | `…/security/oidc/VaadinBackChannelSessionRegistry.java` | BCL |
| `BackChannelLogoutHandler.java.tmpl` | `…/security/oidc/BackChannelLogoutHandler.java` | BCL |
| `BackChannelLogoutInitListener.java.tmpl` | `…/security/oidc/BackChannelLogoutInitListener.java` | BCL |
| `DpopResourceClient.java.tmpl` | `…/security/oidc/DpopResourceClient.java` | DPoP |
| `services-VaadinServiceInitListener.tmpl` | append `…BackChannelLogoutInitListener` | BCL |

**Documented manual edits (not templated — too small + would duplicate the
`jcustos-vaadin-oidc` files; same convention as `jcustos-vaadin-hardening`'s
version-store edit):**

- **JWE / mTLS** → the 2–4 line edits to `OidcClients` shown in §Feature 1 / §Feature 2
  (wrap the validator; build the `HttpClient` with the mTLS `SSLContext`). The
  back-channel handler needs `OidcClients` to also expose a **logout-token JwtValidator**
  (same JWKS, `iss`, `aud = CLIENT_ID`, `exp` not required) + the shared
  `InMemoryJtiStore` — add two getters.
- **Session registration** → in `OidcCallbackView`, after `setCurrentSubject(...)`, add:
  `VaadinBackChannelSessionRegistry.register(OidcClients.ISSUER, idToken.subject().orElse(""), idToken.jwt().claim("sid", String.class), VaadinSession.getCurrent().getSession());`

Substitution tokens reuse `jcustos-vaadin-oidc`'s set plus: `{{BACKCHANNEL_PATH}}`
(`/backchannel-logout`), `{{RESOURCE_ORIGIN}}`. Render only the templates for the chosen
features.

## Verification checklist (per enabled feature)

- **JWE**: a real `JWE(JWS)` ID token validates; a non-allow-listed `enc`/`alg` is
  rejected; a plain JWS still logs in.
- **mTLS**: the token request presents the client cert (the OP accepts it); without the
  cert the OP rejects. TLS 1.3 pinned.
- **Back-Channel Logout**: a valid `logout_token` POST → `200` and the user's open Vaadin
  session is invalidated on its next request; a forged / `nonce`-bearing / replayed token
  → `400`, no session touched.
- **DPoP**: the resource server accepts `Authorization: DPoP <token>` + a valid `DPoP`
  proof header; a missing/invalid proof is rejected.

## Framework feedback (raise — not blocking)
This skill surfaces three integration gaps worth closing in the framework:
1. **No Vaadin Back-Channel-Logout adapter.** The endpoint + `WrappedSession`-based
   `SessionRegistry` + handler are non-trivial and re-templated per app. A
   `jCustos-identity-oidc-vaadin` `BackChannelLogoutRequestHandler` +
   `VaadinSessionRegistry` would remove ~120 lines from this skill.
2. **PAR / JAR not wired into `AuthorizationCodeFlow`.** `startRequest` owns PKCE/state,
   so PAR/JAR can't be layered without re-implementing them. A PAR/JAR-aware flow (or a
   `startRequest` overload accepting a `PushedAuthorizationRequestClient` +
   `AuthorizationRequestSigner`) is needed for a clean login integration.
3. **DPoP not wired into the token endpoint.** `HttpTokenEndpointClient` can't attach a
   token-endpoint DPoP proof, so OP-issued DPoP-bound access tokens aren't obtainable via
   the flow. A `DpopProofGenerator` hook on the token client would close it.

(Plus the `OidcLoginFlow` orchestrator noted in `jcustos-vaadin-oidc`.)

## What this skill deliberately does NOT cover
- The OIDC login flow itself — `jcustos-vaadin-oidc` (prerequisite).
- Front-Channel Logout (`FrontChannelLogoutEndpoint` exists; the back-channel variant is
  the robust default and is what this skill templates).
- A live resource-server example for DPoP — the helper is provided; the server side is
  out of scope.
- PAR/JAR end-to-end (documented, pending the framework gap).

## Compact recipe
1. Confirm `jcustos-vaadin-oidc` ran. Ask which features (multi-select).
2. **JWE / mTLS** (if chosen): apply the documented `OidcClients` edits (§Feature 1/2) +
   add the `logoutJwtValidator()` / `jtiStore()` getters. **Back-channel** (if chosen):
   render `VaadinBackChannelSessionRegistry` + `BackChannelLogoutHandler` +
   `BackChannelLogoutInitListener`, append the service line, and add the one-line session
   registration to `OidcCallbackView`. **DPoP** (if chosen): render `DpopResourceClient`.
3. Merge POM (`jCustos-dpop` only when DPoP enabled).
4. `mvn compile`; walk the per-feature verification checklist.
