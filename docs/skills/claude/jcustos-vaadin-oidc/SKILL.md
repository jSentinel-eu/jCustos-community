---
name: jcustos-vaadin-oidc
description: Layer-4 follow-up to `jcustos-vaadin` — replaces the local username/password `AuthenticationService` with **OpenID Connect federated login** (SSO) against an external IdP, using the released V00.76–V00.79 identity stack. Wires the OIDC authorization-code + PKCE flow end-to-end in a Vaadin app: a "Login with <IdP>" route that starts the flow (`AuthorizationCodeFlow.startRequest`), an `@Route("oauth2/callback")` view that exchanges the code, validates the ID token (signature/iss/aud/nonce/exp via `DefaultIdTokenValidator` + `HttpJwksClient`), maps the validated claims to a `JCustosSubject` through a one-line **vendor profile** (Keycloak / Entra / Auth0 / Okta / Google / GitHub), binds it into the Vaadin session, and an RP-initiated logout route (`AbstractOidcLogoutView`). Bootstrap is additive via the layer-1 `BootstrapExtension` SPI — `VaadinSecurity.bootstrap().oidc(o -> o.issuer(...).clientId(...).vendor(...))` — so the roles/permissions/views/audit from `jcustos-vaadin` keep working; only the *authentication source* changes from local to federated. Prerequisite: a project that already ran `jcustos-vaadin`. Use PROACTIVELY when the user mentions OIDC, OpenID Connect, SSO, single sign-on, "login with Google / Microsoft / Entra / Azure AD / Keycloak / Auth0 / Okta / GitHub", social login, federated login, identity provider, IdP, `OidcBootstrap`, `.oidc(...)`, `VaadinSecurity.bootstrap().oidc`, `IdTokenValidator`, `OidcDiscoveryClient`, vendor profile, `KeycloakProfile`, `EntraProfile`, authorization-code flow, PKCE, `/oauth2/callback`, "replace my login form with SSO", "delegate auth to Keycloak". Adds dependencies (`jCustos-identity-oidc`, `jCustos-identity-oidc-vaadin`, `jCustos-oauth2`, `jCustos-oauth2-vaadin`, `jCustos-jwt`, one `jCustos-identity-vendor-<idp>` module), ~7 templates (`OidcClients` wiring + `OidcBootstrapExtension` + `OidcLoginView` + `OidcCallbackView` + `OidcLogoutView` + nonce-store helper) and 1 append-safe META-INF/services entry. Does NOT cover DPoP / mTLS / PAR / JAR / JWE-encrypted-ID-tokens / back-channel logout — those are the layer-5 `jcustos-vaadin-oidc-hardening` skill (the V00.79 deep-hardening surface).
---

# jCustos ↦ Vaadin Flow — OpenID Connect federated login (SSO)

This skill turns a `jcustos-vaadin` app's **local** username/password login into
**OIDC federated login** against an external IdP. The user clicks "Login with
&lt;IdP&gt;", is redirected to the provider, comes back to a callback route, and the
app validates the ID token and creates a `JCustosSubject` from the provider's
claims via a one-line **vendor profile**. Everything else from `jcustos-vaadin`
(roles, permissions, `@VisibleFor` / `SecuredUi`, audit + session views) is unchanged
— only the *source of identity* moves from the local `UserDirectory` to the IdP.

It is a **layer-4** skill in the same additive family as `-persistence` (layer-2) and
`-hardening` (layer-3): it contributes to the bootstrap through the layer-1
`BootstrapExtension` SPI and does **not** overwrite `JCustosBootstrapInitListener.java`.

## How to use this skill

1. Confirm the prerequisite: the module already ran `jcustos-vaadin` (there is a
   `…/security/bootstrap/JCustosBootstrapInitListener.java`, a `BootstrapBuilder`,
   a `BootstrapExtension` SPI, and `MyLoginView` + `MainLayout`).
2. Read the brief, extract the slots (below), ask only when >1 is missing.
3. Render the templates from `references/`, merge the POM, append the one services line.
4. Replace (or hide) the local login form with the OIDC login route.
5. Verify with `mvn compile` + a dev run against the IdP.

## The integration at a glance — the OIDC authorization-code + PKCE flow

```
 Browser            Vaadin app (this skill)                 IdP (issuer)
   │                       │                                     │
   │  GET /login           │                                     │
   │──────────────────────▶│ OidcLoginView                       │
   │                       │  flow.startRequest(nonce) ──┐        │
   │                       │  store nonce by stateKey    │        │
   │  302 → authz endpoint ◀──────────────────────────────        │
   │─────────────────────────────────────────────────────────────▶│  user authenticates
   │  302 → /oauth2/callback?code&state ◀──────────────────────────│
   │──────────────────────▶│ OidcCallbackView                     │
   │                       │  flow.handleCallback(code,state) ───▶│  token endpoint (PKCE)
   │                       │  ◀── TokenResponse(idToken, access)  │
   │                       │  idTokenValidator.validate(           │
   │                       │      idToken, expect(iss,aud,nonce))  │  (sig via JWKS)
   │                       │  claimsMapper.map(idToken,userInfo)   │
   │                       │  subjectStore.setCurrentSubject(subject)           │
   │  302 → /dashboard ◀───│                                       │
```

The framework provides the **primitives**; this skill provides the **orchestration
code** (the callback route + login route + the small wiring class). The DX
`.oidc(...)` builder only **records + validates** config (issuer, clientId, scopes
must include `openid`, redirect URI https/loopback) — it does **not** create routes or
run flows. That is by design (library-centric, no bootstrap side effects); the skill
fills the gap.

## Relationship to `jcustos-vaadin` (what changes)

| From `jcustos-vaadin` | After this skill |
|---|---|
| `MyAuthenticationService` (checks local `UserDirectory`) | not used for login; OIDC is the auth source. Keep it only if you also want local fallback. |
| `MyLoginView` (username/password form) | replaced by `OidcLoginView` (redirect to IdP) — or keep both and add a "Login with &lt;IdP&gt;" button |
| roles via `MyAuthorizationService` / local roles | roles come from the IdP claims via the **vendor profile** (`.vendor(...)`); `MyAuthorizationService` can stay as a fallback / for local-only permissions |
| `VaadinSessionSubjectStore` | unchanged — the OIDC callback binds into the same store |
| audit / sessions / `@VisibleFor` / `SecuredUi` views | unchanged |

## Reading the brief — slots to extract

| Slot | Example | Default if missing |
|---|---|---|
| **IdP vendor** | keycloak / entra / auth0 / okta / google / github | ask (drives the vendor module + `*Profile.INSTANCE`) |
| **Issuer URL** | `https://login.example.com/realms/app` | ask (no sensible default) |
| **Client ID** | `my-vaadin-rp` | ask |
| **Client secret** | `s3cret` (confidential) or none (public + PKCE) | ask; if "public"/"SPA" → `NoneAuthentication` + PKCE |
| **Redirect URI** | `https://app.example.com/oauth2/callback` | `<app base URL>/oauth2/callback` (must be registered at the IdP) |
| **Post-logout URI** | `https://app.example.com/` | app root `/` |
| **Base package** | `com.acme.bookstore` | from existing `@Route` packages |
| **Scopes** | `openid profile email` | `openid profile email` |

If >1 slot is missing, ask all in ONE `AskUserQuestion`. Issuer + clientId + vendor
are mandatory — never invent them.

## Rendering templates

Every file in `references/` ends with `.tmpl`. Substitute then write.

| Token | Replace with |
|---|---|
| `{{BASE_PACKAGE}}` / `{{BASE_PATH}}` | `com.acme.bookstore` / `com/acme/bookstore` |
| `{{VENDOR}}` | `keycloak` / `entra` / `auth0` / `okta` / `google` / `github` |
| `{{VENDOR_PROFILE}}` | `KeycloakProfile` / `EntraProfile` / `Auth0Profile` / `OktaProfile` / `GoogleProfile` / `GitHubProfile` |
| `{{VENDOR_PROFILE_PKG}}` | `eu.jsentinel.jcustos.identity.vendor.<vendor>` |
| `{{ISSUER}}` / `{{CLIENT_ID}}` | `https://login.example.com/realms/app` / `my-vaadin-rp` |
| `{{CLIENT_SECRET}}` | the secret, or empty for a public client |
| `{{REDIRECT_URI}}` / `{{POST_LOGOUT_URI}}` | `https://app.example.com/oauth2/callback` / `https://app.example.com/` |
| `{{SCOPES}}` | `"openid", "profile", "email"` (Java vararg list) |

| Template | Target | Kind |
|---|---|---|
| `pom-snippet.xml.tmpl` | merge into `pom.xml` | merge |
| `OidcClients.java.tmpl` | `…/security/oidc/OidcClients.java` (lazy singletons: discovery → metadata, flow, id-token validator, claims mapper, userinfo) | new |
| `OidcBootstrapExtension.java.tmpl` | `…/security/bootstrap/OidcBootstrapExtension.java` (`wantsOidc()=true` + `contributeOidc(o)`) | new |
| `BootstrapExtension.java.tmpl` | `…/security/bootstrap/BootstrapExtension.java` — **replacement**: add `default void contributeOidc(OidcBootstrap o) {}` + `default boolean wantsOidc() { return false; }` to the SPI the `jcustos-vaadin` skill generated | replace |
| `BootstrapBuilder.java.tmpl` | `…/security/bootstrap/BootstrapBuilder.java` — **replacement**: conditionally chain `.oidc(o -> extensions.forEach(e -> e.contributeOidc(o)))` only when `extensions.stream().anyMatch(BootstrapExtension::wantsOidc)` (calling `.oidc(noop)` would fail STRICT for a missing issuer) | replace |
| `OidcLoginView.java.tmpl` | `…/views/OidcLoginView.java` (`@Route("login")` + `@PublicRoute` — starts the flow + redirects) | new (replaces `MyLoginView`) |
| `OidcCallbackView.java.tmpl` | `…/views/OidcCallbackView.java` (`@Route("oauth2/callback")` + `@PublicRoute`, extends `AbstractOAuth2CallbackView` — passes `iss`, rotates the session id) | new |
| `OidcLogoutView.java.tmpl` | `…/views/OidcLogoutView.java` (`@Route("logout")` + `@PublicRoute`, extends `AbstractOidcLogoutView`) | new |
| `services-BootstrapExtension.tmpl` | append `{{BASE_PACKAGE}}.security.bootstrap.OidcBootstrapExtension` to the existing `…bootstrap.BootstrapExtension` services file (append-safe) | append |

**Bootstrap mechanism (precise):** `JCustosBootstrapInitListener.java` is **not**
touched. Instead the two generated bootstrap files are replaced to teach the existing
SPI a new `contributeOidc` channel, then `OidcBootstrapExtension` (registered via
ServiceLoader) supplies the actual `.oidc(...)` config. The `wantsOidc()` guard keeps
projects that don't run this skill unaffected (no `.oidc(...)` call → no STRICT issuer
requirement). This is the same "extend the SPI, ship an extension" shape the
`-persistence` / `-hardening` layers use.

## POM patch — what to merge

Add (idempotent), reusing the existing `<jcustos.version>` property:

```xml
<dependency><groupId>eu.jsentinel</groupId><artifactId>jCustos-jwt</artifactId><version>${jcustos.version}</version></dependency>
<dependency><groupId>eu.jsentinel</groupId><artifactId>jCustos-oauth2</artifactId><version>${jcustos.version}</version></dependency>
<dependency><groupId>eu.jsentinel</groupId><artifactId>jCustos-oauth2-vaadin</artifactId><version>${jcustos.version}</version></dependency>
<dependency><groupId>eu.jsentinel</groupId><artifactId>jCustos-identity-oidc</artifactId><version>${jcustos.version}</version></dependency>
<dependency><groupId>eu.jsentinel</groupId><artifactId>jCustos-identity-oidc-vaadin</artifactId><version>${jcustos.version}</version></dependency>
<dependency><groupId>eu.jsentinel</groupId><artifactId>jCustos-identity-vendor-{{VENDOR}}</artifactId><version>${jcustos.version}</version></dependency>
```

No new annotation-processor paths (the AutoService processor from `jcustos-vaadin` is reused).

## The flow in code (what the templates implement)

1. **Wiring (`OidcClients`)** — built once, lazily, from the issuer:
   - `OidcProviderMetadata md = new HttpOidcDiscoveryClient(http).discover(URI.create(ISSUER)).getOrThrow();`
   - `var tokenClient = new HttpTokenEndpointClient(md.tokenEndpoint(), clientAuth, http);`
   - `var config = new OAuth2ClientConfig(clientAuth, Optional.of(md.authorizationEndpoint()), md.tokenEndpoint(), …, Optional.of(URI.create(REDIRECT_URI)), Set.of(SCOPES), /*pkce*/true, /*rotate*/false, Duration.ofMinutes(5)).withExpectedIssuer(md.issuer(), md.authorizationResponseIssParameterSupported());`
     — binds the authorisation response to its issuer (RFC 9207, JS-SEC-150): a response that
     names another issuer, or none when the issuer announces `iss`, is refused before the
     state is consumed or the token endpoint is called. One redirect URI per IdP.
   - `var flow = new HttpAuthorizationCodeFlow(config, tokenClient, new VaadinSessionStateStore());`
   - `var jwt = new NimbusJwtValidator(AlgorithmProfile.STRICT_MODERN.toAllowList(), new HttpJwksClient(md.jwksUri()), ClaimExpectations…(ISSUER, CLIENT_ID), Instant::now);`
   - `var idTokenValidator = new DefaultIdTokenValidator(jwt);`
   - `var claimsMapper = {{VENDOR_PROFILE}}.INSTANCE.subjectMapper().orElse(new DefaultClaimsToSubjectMapper(... vendor roles/permissions/tenant mappers ...));`
   - `clientAuth` = `new ClientSecretBasic(CLIENT_ID, SecretValue.ofString(SECRET))` (confidential) **or** `new NoneAuthentication(CLIENT_ID)` (public; PKCE carries the proof).
2. **Login (`OidcLoginView` @Route("login"))**:
   - `String nonce = randomUrlSafe();`
   - `var req = flow.startRequest(new StartRequestParams(Set.of(), Map.of(), Optional.of(nonce), resumeTarget));`
   - the flow keeps the nonce with the state; the callback gets it back as `CallbackResult.nonce()`
   - `UI.getCurrent().getPage().setLocation(req.redirectTo().toString());`
3. **Callback (`OidcCallbackView` @Route("oauth2/callback"), extends `AbstractOAuth2CallbackView`)**:
   the base view reads `code` / `state` / `error` / `iss` and refuses a response with
   several `iss` values; it calls `flow.handleCallback(new CallbackParams(code, state, error, errDesc, iss))`.
   The view implements `flow()`, `successTarget()` (`"dashboard"`), `errorTarget()` (`"login"`) and
   `onTokens(CallbackResult result)`:
   - `var idt = idTokenValidator.validate(result.tokens().idToken().orElseThrow(), IdTokenExpectations.of(ISSUER, CLIENT_ID, result.nonce()));` — on failure bind nothing
   - optional UserInfo: `userInfoClient.fetch(result.tokens().accessToken()).toOptional()`
   - `JCustosSubject subject = claimsMapper.map(idt.getOrThrow(), userInfo);`
   - `SubjectStores.subjectStore().setCurrentSubject(subject, JCustosSubject.class);`
   - stash the raw ID token in the session for the logout's `id_token_hint`

   After `onTokens` the base view runs `LoginSessionRotation.afterLogin(...)`: the HTTP
   session id is rotated, the `SessionPolicy` observes the login, the rotation is audited and
   the security-version snapshot taken (JS-SEC-146, CWE-384). If the id cannot be rotated the
   login is undone and the view forwards to `errorTarget()`. A callback that does not extend
   the base view must call `LoginSessionRotation.afterLogin()` itself and pass `iss` into
   `CallbackParams`.
4. **Logout (`OidcLogoutView` extends `AbstractOidcLogoutView`)**: `endSessionEndpoint()` from `md.endSessionEndpoint().orElseThrow()`; `logoutRequest()` returns `new LogoutRequest(storedIdToken, Optional.of(POST_LOGOUT_URI), Optional.empty())` (`idTokenHint` is non-null — pass `""` if absent); `initiator()` returns `new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(URI.create(POST_LOGOUT_URI)))`, the one target the view sends (JS-SEC-089, CWE-601). The override is required: the base class's default initiator has no allowlist and refuses every `post_logout_redirect_uri`, and the view then ends only the local session, sends the browser to `/login` and leaves the IdP session open (CWE-613) — the next "Login with &lt;IdP&gt;" on that browser signs the same user in without a password. The base view ends the local session in every case — subject, token credential and snapshot cleared, `LogoutPerformed` audited, Vaadin session closed, HTTP session invalidated — and, with the allowlisted target, redirects to the provider (JS-SEC-147); no `onBeforeLogout()` override is needed. Navigating to `/logout` alone logs nobody out: every sign-out link or button uses `AbstractOidcLogoutView.logoutLocation(OidcLogoutView.class)`, which carries a single-use token bound to the session; without it the view asks for a confirmation click (CWE-352):
   ```java
   Button signOut = new Button("Sign out",
       click -> UI.getCurrent().navigate(AbstractOidcLogoutView.logoutLocation(OidcLogoutView.class)));
   ```

## Verification checklist

- [ ] `mvn -q compile` is clean.
- [ ] The IdP has `{{REDIRECT_URI}}` registered as an allowed redirect URI (exact match).
- [ ] Scopes include `openid`.
- [ ] Dev run: clicking "Login with &lt;IdP&gt;" redirects to the IdP; after auth the browser lands on `/oauth2/callback` and then `/dashboard` with the subject's display name visible.
- [ ] Roles from the IdP show up (e.g. an admin-realm-role user sees the admin views) — proves the vendor profile mapped claims → `RoleName`s.
- [ ] The IdP has `{{POST_LOGOUT_URI}}` registered as a post-logout redirect URI (exact match), and `OidcLogoutView` overrides `initiator()` with `PostLogoutRedirectValidator.allowOnly(URI.create(OidcClients.POST_LOGOUT_URI))`.
- [ ] Logout redirects through the IdP `end_session_endpoint` and back to `{{POST_LOGOUT_URI}}`; the session subject is cleared. Landing on `/login` without passing the IdP means the target was refused (the log has a WARN that the end-session redirect could not be computed, and `oidc/logout-redirect-unvalidated` without the override): the IdP session is still open.
- [ ] A tampered/expired ID token is rejected (callback reroutes to login, not a 500).

## Pitfalls

### Nonce threading
`startRequest(...)` stores the nonce with the state; `handleCallback(...)` consumes the
state single-use and returns it in `CallbackResult.nonce()` (JS-SEC-059). Pass it to
`IdTokenExpectations.of(ISSUER, CLIENT_ID, result.nonce())` — without it the ID-token
`nonce` check cannot run. No separate nonce store is needed.

### Public routes outside restricted layouts
Login, callback and logout carry `@PublicRoute` (the bootstrap runs with deny-by-default)
and use no router layout: a restriction on a layout applies to every view in it
(JS-SEC-154).

### Redirect URI must match exactly
The IdP compares `redirect_uri` byte-for-byte. `https://app/oauth2/callback` ≠
`https://app/oauth2/callback/`. Register the exact `{{REDIRECT_URI}}`.

### The post-logout target needs an allowlist
Since 00.84.00 `AbstractOidcLogoutView.initiator()` defaults to an initiator without an
allowlist, which refuses every `post_logout_redirect_uri` (JS-SEC-089). The template's
`initiator()` override names `POST_LOGOUT_URI`; keep it when you edit the view, and add every
further target you send to `allowOnly(...)`. Without it the logout looks successful locally
but never reaches the IdP.

### https / loopback only
The DX bootstrap rejects a non-https redirect URI unless it's `localhost`/`127.0.0.1`
(dev). Production must be https.

### Public vs confidential client
A browser SPA / public client has no secret → use `NoneAuthentication(CLIENT_ID)` and
rely on PKCE (`pkceRequired=true`, the default here). A server-side confidential client
uses `ClientSecretBasic`. Never ship a secret to a public client.

### Vendor claim differences
Roles live in different claims per IdP (Keycloak `realm_access.roles`, Entra
`wids`/`roles`/`groups`, Auth0 namespaced, Okta `groups`, Google `hd`/`email_verified`,
GitHub via UserInfo only). The `.vendor(...)` profile handles this — don't hand-roll a
mapper unless the user has custom claims, in which case add `.rolesMapper(...)` *after*
`.vendor(...)` (it wins).

### State store is session-scoped
`VaadinSessionStateStore` is per-Vaadin-session and single-use; a login started in one
browser cannot complete in another. That is correct CSRF behaviour.

## Framework feedback (worth raising, not blocking)
The Vaadin OIDC RP wiring is still fairly low-level: the consumer hand-assembles
discovery + flow + id-token validation + subject binding (the callback base view now
carries the `iss` check and the session rotation, the flow the nonce). A framework-side
**`OidcLoginFlow` orchestrator** (one call: callback → validated `JCustosSubject`) would
shrink this skill's callback template further. Until then this skill carries that
orchestration.

## What this skill deliberately does NOT cover

- **DPoP / mTLS / PAR / JAR / JWE-encrypted ID tokens / back-channel + front-channel
  logout** — the V00.79 deep-hardening surface; a layer-5 `jcustos-vaadin-oidc-hardening`
  skill is the right home.
- **Runtime multi-IdP switching** — one IdP per build here. For a chooser, register one
  `.oidc(...)` per IdP and one callback route and redirect URI each, every flow with
  `withExpectedIssuer(...)` of its own issuer (a shared redirect URI lets one IdP's response
  be replayed against another — mix-up, RFC 9207).
- **Refresh-token rotation / silent renew** — the ID token establishes the session;
  long-lived sessions + refresh are a separate concern.
- **Local + federated side by side** — supported (keep `MyAuthenticationService` and add
  a "Login with &lt;IdP&gt;" button instead of replacing `MyLoginView`), but the default
  recipe is federated-only for clarity.

## Compact procedural recipe
1. Confirm `jcustos-vaadin` ran (bootstrap SPI + views present).
2. Extract slots (vendor, issuer, clientId, secret/public, redirect URI). Ask if >1 missing.
3. Merge `pom-snippet.xml.tmpl` (oidc + oauth2(+vaadin) + jwt + vendor module).
4. Render `OidcClients`, `OidcBootstrapExtension`, `OidcLoginView`,
   `OidcCallbackView`, `OidcLogoutView`.
5. Append the `OidcBootstrapExtension` line to the `BootstrapExtension` services file.
6. Replace `MyLoginView` with `OidcLoginView` (or add a button) and point the
   `MainLayout` sign-in action at `/login`; the sign-out action navigates to
   `AbstractOidcLogoutView.logoutLocation(OidcLogoutView.class)` — a plain link to `/logout`
   only shows the confirmation button.
7. `mvn compile` + dev-run against the IdP; walk the verification checklist.
