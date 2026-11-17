# 5-Minute Setup — OpenID Connect Relying Party

This guide wires a Vaadin app to an OpenID Connect provider (Keycloak, Microsoft
Entra ID, Auth0, Okta, Google, GitHub) as a relying party, then layers on the
V00.79 hardening features. Everything here is library-only — no Spring Security,
no Jakarta Security.

> REST and standalone adapters follow the same shape via `RestSecurity.bootstrap()`
> / `StandaloneSecurity.bootstrap()`.

## 1. Minimal OIDC login (≈5 lines)

```java
JCustosRuntime runtime = VaadinSecurity.bootstrap()
    .mode(JCustosBootstrapMode.PRODUCTION)
    .oidc(o -> o
        .issuer("https://idp.example.com/realms/app")
        .clientId("my-rp")
        .clientAuthentication(new ClientSecretBasic("my-rp", SecretValue.ofString(secret)))
        .redirectUri(URI.create("https://app.example.com/oauth2/callback")))
    .install();
```

Discovery (`.well-known/openid-configuration`), JWKS rotation, ID-token validation
(signature, `iss`, `aud`, `exp`, `nonce`, `at_hash`), and the authorization-code +
PKCE flow are wired for you.

### Callback and logout views (00.84.00)

- **Callback:** extend `AbstractOAuth2CallbackView` (`jCustos-oauth2-vaadin`). It passes the
  `iss` parameter of the response to the flow and refuses a response that names several
  issuers (RFC 9207, JS-SEC-150), and after your `onTokens(...)` it rotates the session id
  through `LoginSessionRotation.afterLogin(...)` — failing closed when the id cannot be
  rotated (JS-SEC-146, CWE-384). A callback that does not extend the base view must call
  `LoginSessionRotation.afterLogin()` itself and pass `iss` into `CallbackParams`.
- **Issuer binding for hand-built flows:**
  `config.withExpectedIssuer(metadata.issuer(), metadata.authorizationResponseIssParameterSupported())`
  on the `OAuth2ClientConfig`; one redirect URI per IdP.
- **Logout:** extend `AbstractOidcLogoutView`; it ends the local session in every case and
  redirects to the provider (JS-SEC-147) — provided the `post_logout_redirect_uri` your
  `logoutRequest()` sends is allowlisted. Override `initiator()` with the target registered
  at the provider:

  ```java
  @Override
  protected LogoutInitiator initiator() {
    return new RpInitiatedLogoutInitiator(
        PostLogoutRedirectValidator.allowOnly(URI.create("https://app.example.com/")));
  }
  ```

  The default initiator has no allowlist and refuses every target (JS-SEC-089, CWE-601):
  the view then ends only the local session and sends the browser to the login route, and
  the provider's session stays open. A `logoutRequest()` without a
  `post_logout_redirect_uri` needs no override; the provider then shows its own page.
  Navigating to the route alone logs nobody out — link to it with
  `AbstractOidcLogoutView.logoutLocation(MyLogoutView.class)`, which carries a single-use
  token bound to the session. No `onBeforeLogout()` override is needed to clear the subject.
- **Deny-by-default:** login, callback and logout views carry `@PublicRoute` and live
  outside any restricted router layout (JS-SEC-154).

## 2. Vendor profiles (one line per IdP)

A `VendorProfile` bundles the IdP-specific claim mappers (roles, groups, tenant)
so you don't wire each by hand. Add the vendor module and call `.vendor(...)`:

```java
.oidc(o -> o
    .issuer("https://login.microsoftonline.com/<tenant>/v2.0")
    .clientId("…")
    .vendor(EntraProfile.INSTANCE))      // wids/roles/groups → roles, tid → tenant
```

| IdP | Module | Profile |
|---|---|---|
| Keycloak | `jCustos-identity-vendor-keycloak` | `KeycloakProfile.INSTANCE` |
| Entra ID | `jCustos-identity-vendor-entra` | `EntraProfile.INSTANCE` |
| Auth0 | `jCustos-identity-vendor-auth0` | `Auth0Profile.INSTANCE` |
| Okta | `jCustos-identity-vendor-okta` | `OktaProfile.INSTANCE` |
| Google | `jCustos-identity-vendor-google` | `GoogleProfile.INSTANCE` |
| GitHub | `jCustos-identity-vendor-github` | `GitHubProfile.INSTANCE` |

An explicit `.rolesMapper(...)` after `.vendor(...)` still wins. Vendor mappers
trust **signed** ID-token claims only (never an unverified UserInfo `sub`).

## 3. Hardening (V00.79)

All of the following are opt-in and composable. They are wired with direct API
today (the fluent one-liners are staged); each primitive is independently usable.

### DPoP — sender-constrained tokens (RFC 9449)

```java
JtiStore jtis = new InMemoryJtiStore();                       // replay store (B3)
DpopProofValidator dpop = new NimbusDpopProofValidator(Set.of("RS256", "ES256"), jtis, Instant::now);
// outbound: new DpopProofGenerator().generate(signingJwk, "POST", uri, Optional.of(accessToken));
```

A resource server validates a proof against the key the access token is bound to:
`DpopValidationRequest.boundTo(proof, method, uri, accessToken, expectedJkt)` with the
token's `cnf.jkt` as `expectedJkt` (JS-SEC-148). A proof signed with another key fails with
`KeyBindingMismatch` before its `jti` is recorded; the four-argument `boundTo(...)` is
deprecated and fails closed. Proofs above 100 kB (`JoseLimits`) and `jti` values above 128
characters are rejected; `InMemoryJtiStore` keeps the SHA-256 of a `jti`, never the value.

### Replay stores (RFC 9449 §11 / OIDC BCL)

`InMemoryJtiStore` (single-use `jti`, soonest-to-expire eviction) and
`InMemoryNonceStore` back DPoP-proof and nonce single-use. Swap a shared
(JDBC/Redis) implementation of `JtiStore` / `NonceStore` for multi-node.

### Back-/Front-Channel Logout (OIDC BCL/FCL 1.0)

```java
SessionRegistry sessions = new InMemorySessionRegistry();
var receiver = new BackChannelLogoutReceiver(
    new DefaultLogoutTokenValidator(jwtValidator, ISSUER, CLIENT_ID, jtis), sessions);   // behind backchannel_logout_uri
// the validator checks iss, aud, exp/iat and the replay window itself (JS-SEC-087);
// the constructors without ISSUER and CLIENT_ID are deprecated and reject every token
// receiver.receive(logoutToken) → Accepted(200) / Rejected(400); never dereferences a token URL (no SSRF)
```

### Encrypted ID tokens — JWE (RFC 7516)

Some IdPs (e.g. Entra Conditional Access) deliver `JWE(JWS(payload))`. Wrap the
validator; the allow-list rejects `RSA1_5`/`dir` downgrades:

```java
JwtValidator idTokenValidator = new JweUnwrappingJwtValidator(
    innerValidator, new NimbusJweDecoder(JweAlgorithmAllowList.defaults()), decryptionKey);
```

### mTLS client-auth (RFC 8705)

See [`mtls-setup.md`](../security/credentials/standards/mtls-setup.md):

```java
SSLContext ctx = MutualTls.sslContext(new MutualTlsClientConfig(keyStore, pw, "client"));
HttpClient http = HttpClient.newBuilder().sslContext(ctx).build();
```

### PAR + JAR (RFC 9126 / RFC 9101)

```java
var par = new HttpPushedAuthorizationRequestClient(parEndpoint, clientAuth, http);
String requestUri = par.push(authParams).getOrThrow().requestUri();
URI redirect = HttpPushedAuthorizationRequestClient.authorizationRedirect(authzEndpoint, clientId, requestUri);

String requestObject = new AuthorizationRequestSigner(new NimbusJwtSigner(), signingKey, clientId)
    .sign(authParams, issuer);    // RFC 9101 signed request object
```

## 4. FIPS

For a FIPS deployment, select `AlgorithmProfile.FIPS_140_3` on the validators,
`JweAlgorithmAllowList.fips()` for JWE, RSA-2048+/P-256 keys for DPoP/JAR, and
TLS 1.3 throughout. Full matrix: [`fips-profile.md`](../security/credentials/standards/fips-profile.md).

## 5. STRICT mode

`JCustosBootstrapMode.STRICT` turns missing critical wiring into a startup
exception instead of a warning (e.g. `jwt/jwe-without-decryption-key`,
`oauth2/mtls-keystore-empty`, `oauth2/par-without-endpoint`). Run STRICT in CI to
catch misconfiguration before production.
