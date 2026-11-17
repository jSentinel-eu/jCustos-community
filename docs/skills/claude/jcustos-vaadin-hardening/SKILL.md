---
name: jcustos-vaadin-hardening
description: Layer-3 follow-up to `jcustos-vaadin` (and optionally `jcustos-vaadin-persistence`) — wires the V00.71 production-hardening features: modern password hashing via Argon2id (`BouncyCastleHashingServices.modern()` from `jCustos-crypto-bc`), optional HIBP password-leak check (`HaveIBeenPwnedCompromisedPasswordChecker` from `jCustos-credentials-hibp`), and Phase-4c JCustos-version drift detection (`JCustosVersionStore` + `JCustosVersionEnforcerListener`) so revoking a role mid-session forces the affected user back to the login view on the next navigation. Prerequisite: a project that already ran `jcustos-vaadin`. Use PROACTIVELY when the user mentions Argon2id, modern crypto, bcrypt, scrypt, BouncyCastle hashing, password upgrade, compromised password, HIBP, k-anonymity, "production crypto", "swap PBKDF2 for Argon2id", drift detection, `JCustosVersion`, session invalidation on role change, "revoke session immediately", `JCustosVersionEnforcer`, `JCustosVersionEnforcerListener`, "kick user out on role revoke", "stale subject", compliance hardening, "production-ready jCustos", "V00.71 features". File-level signals: an existing `JCustosBootstrapInitListener.java` with `.credentials(c -> c.hashing(PasswordHashingServices.defaults()))` (PBKDF2 default that this skill replaces); an `AdminRolesView` that mutates roles but doesn't bump version (this skill adds the call); absence of `META-INF/services/eu.jsentinel.jcustos.session.JCustosVersionStore`. Adds 2 dependencies (`jCustos-crypto-bc`, `jCustos-credentials-hibp`), 5 new templates (`PasswordPreflight`, `PreflightPasswordPolicy`, `VersionBumper`, `HardeningBootstrapExtension`, `SubjectIdResolverImpl`), 1 replacement template (`AdminRolesView` calls `VersionBumper.bump(user)` after every role mutation). The bootstrap chain is extended via the layer-1 `BootstrapExtension` SPI — no overwrite of `JCustosBootstrapInitListener.java`. Order with `jcustos-vaadin-persistence` is irrelevant, 3 new META-INF/services entries (`JCustosVersionStore`, `SubjectIdResolver`, `PasswordPolicy`). Does NOT cover token-based first-admin bootstrap or storage persistence — those are the layer-2 `jcustos-vaadin-persistence` skill; does NOT cover API keys / refresh tokens / rate limiting (shipped as the V00.70 account-lifecycle / token / rate-limit services) or OAuth2 / OIDC federation (the released V00.76–V00.79 identity stack: `jCustos-jwt` / `-oauth2` / `-identity-oidc`, vendor profiles, DPoP, mTLS) — both out of this hashing + drift hardening skill's scope.
---

# jCustos hardening — layer 3

Additive layer on top of `jcustos-vaadin` (and optionally on top of
`jcustos-vaadin-persistence`). Lifts the security stack from "demo-grade
defaults" to "V00.71 production hardening" in three concerns:

1. **Modern password hashing** — PBKDF2 → Argon2id. Stored hashes
   created under the old profile auto-migrate on next successful
   login (`RehashDecisionEngine` flags them as
   `ALGORITHM_DEPRECATED`).
2. **HIBP password-leak check (opt-in at setup / password change)**
   — k-anonymity range API call. Plain password never leaves the
   JVM; only the first 5 SHA-1 hex chars are transmitted.
3. **Phase-4c drift detection** — when an admin revokes or grants a
   role, the affected user's session ends and the browser is sent to
   `{{SUBJECT_PREFIX}}LoginView`: at once over `@Push`, because the
   version store is registered as an `ObservableJCustosVersionStore`
   (R8, JS-SEC-167), otherwise with the user's next request. No more
   "this user keeps using a role we just revoked until they log out."
   The layer-1 listener's `VaadinJCustosStarter.serviceInit(event, ...)`
   installs the check and the proactive reaction as soon as this layer
   registers the store — there is no init listener of its own any more
   (JS-SEC-168).
4. **PRODUCTION profile** — render the layer-1
   `JCustosBootstrapInitListener` with `{{BOOTSTRAP_PROFILE}}` =
   `productionDefaults` (JS-SEC-137). Together with the layer-1
   `denyByDefault(true)` and `.logout(...)` the bootstrap then reports
   no error; anything missing later surfaces as an error instead of
   being suppressed.

**The hashing service is the one the directory uses.** The layer-1 and
layer-2 user directories and the first-administrator setup hash and
verify through `ConfiguredHashingService`, which resolves
`JCustosServiceResolver.credentialHashingService()` on every call — the
service `contributeCredentials(c -> c.hashing(BouncyCastleHashingServices.modern()))`
configures. New hashes are therefore Argon2id, older envelopes are
upgraded on the next successful login, and the administrator the setup
creates can log in (JS-SEC-134). A directory built on the legacy slot
`JCustosServiceResolver.passwordHashingService()` never sees
`.hashing(...)`: it keeps writing PBKDF2 and cannot read the setup's
envelope.

**The first administrator passes the preflight.** `PreflightPasswordPolicy`
(minimum length, local blocklist, HIBP) is registered in
`META-INF/services/eu.jsentinel.jcustos.bootstrap.PasswordPolicy`; the
persistence layer's `BootstrapWiring` applies it to the setup, so
`password` or `12345678` are refused for the most privileged account,
not only in the role administration.

## How to use this skill

1. **Verify the prerequisite** — `jcustos-vaadin` is present
   (`JCustosBootstrapInitListener.java`, `AdminRolesView.java`
   exist).
2. **Apply the POM patch** — adds 2 dependencies.
3. **Add 5 new templates** under their target paths.
4. **Replace 1 existing template** (only `AdminRolesView` now — bootstrap goes through the additive Extension SPI) — `JCustosBootstrapInitListener`
   gets new bootstrap calls, `AdminRolesView` calls the bumper.
5. **Add 3 META-INF/services entries** — `JCustosVersionStore`,
   `SubjectIdResolver` and `PasswordPolicy`.
6. **Verify**: compile, run, log in as admin, revoke a role on
   another logged-in user → that user's browser is sent to `/login`
   without a click (with `@Push`; otherwise on the next click).

## Reading the brief — slots

| Slot | Example | Default if missing |
|---|---|---|
| `{{HIBP_ENABLED}}` | `true`, `false` | `false` (opt-in: requires network egress to `api.pwnedpasswords.com`) |

`{{BASE_PACKAGE}}`, `{{SUBJECT_TYPE}}`, `{{SUBJECT_PREFIX}}` are
inherited from the previous skill output.

## What changes from `jcustos-vaadin`

| File | Change |
|---|---|
| `pom.xml` | + `jCustos-crypto-bc` + (if HIBP) `jCustos-credentials-hibp` |
| `security/bootstrap/HardeningBootstrapExtension.java` (NEW) | implements `BootstrapExtension` SPI from layer 1; `contributeCredentials(c)` calls `c.hashing(BouncyCastleHashingServices.modern())`; `contributeSessions(s)` wires `securityVersion` - the SPI-registered store wrapped in an `ObservableJCustosVersionStore` (R8) - and `subjectIdResolver` via `JCustosServiceResolver.find...`. Picked up by `BootstrapBuilder.apply(...)` at runtime — **no overwrite of the layer-1 listener.** The layer-1 listener's `VaadinJCustosStarter.serviceInit(...)` then installs `JCustosVersionEnforcerListener` and `VaadinJCustosVersionChangeBridge` |
| `security/services/SubjectIdResolverImpl.java` | **NEW** — implements `SubjectIdResolver<{{SUBJECT_TYPE}}>`; returns `SubjectId.of(user.id().toString())` |
| `security/services/VersionBumper.java` | **NEW** — `VersionBumper.bump(user)` increments the per-subject version on role change, through the registered (observable) store |
| `security/services/PasswordPreflight.java` | **NEW** — local blocklist + (optional) HIBP check; called from the role-add dialog and, through `PreflightPasswordPolicy`, from the first-administrator setup. local list and HIBP combined by `CompositeCompromisedPasswordChecker`, local first. `-Djcustos.demo.hibpEndpoint=<url>` points the range query at a mirror (HTTPS, or HTTP on loopback with `-Djcustos.dev=true`) |
| `security/services/PreflightPasswordPolicy.java` | **NEW** — `PasswordPolicy` for the first-administrator setup: minimum length + `PasswordPreflight` |
| `META-INF/services/eu.jsentinel.jcustos.bootstrap.PasswordPolicy` | **NEW** — points at `PreflightPasswordPolicy` |
| `views/admin/AdminRolesView.java` | `assignRole / revokeRole / deleteUser` now call `VersionBumper.bump(user)` after the mutation |
| `META-INF/services/eu.jsentinel.jcustos.session.JCustosVersionStore` | **NEW** — `eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore` |
| `META-INF/services/eu.jsentinel.jcustos.authorization.api.SubjectIdResolver` | **NEW** — points at `SubjectIdResolverImpl` |

## POM patch

```xml
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-crypto-bc</artifactId>
    <version>${jcustos.version}</version>
</dependency>
<!-- only if {{HIBP_ENABLED}} = true -->
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-credentials-hibp</artifactId>
    <version>${jcustos.version}</version>
</dependency>
```

## Rendering templates

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge into `pom.xml` (skip the HIBP block if `{{HIBP_ENABLED}}=false`) |
| `SubjectIdResolverImpl.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/SubjectIdResolverImpl.java` |
| `VersionBumper.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/VersionBumper.java` |
| `PasswordPreflight.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/PasswordPreflight.java` |
| `PreflightPasswordPolicy.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/PreflightPasswordPolicy.java` |
| `services-PasswordPolicy.tmpl` | `src/main/resources/META-INF/services/eu.jsentinel.jcustos.bootstrap.PasswordPolicy` |
| `HardeningBootstrapExtension.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/HardeningBootstrapExtension.java` |
| `services-BootstrapExtension.tmpl` | **APPEND** lines to `src/main/resources/META-INF/services/{{BASE_PACKAGE}}.security.bootstrap.BootstrapExtension` (deduplicated union with existing content) |
| `AdminRolesView.java.tmpl` | OVERWRITE existing |
| `services-JCustosVersionStore.tmpl` | `src/main/resources/META-INF/services/eu.jsentinel.jcustos.session.JCustosVersionStore` |
| `services-SubjectIdResolver.tmpl` | `src/main/resources/META-INF/services/eu.jsentinel.jcustos.authorization.api.SubjectIdResolver` |

## Drift-detection flow

```
LoginView.checkCredentials → success
  → captureJCustosVersionSnapshot() (framework)
    → reads InMemoryJCustosVersionStore.current(key) for (tenant=DEFAULT, subject=userId)
    → stores snapshot in VaadinSession via VaadinJCustosVersionContext

Admin → /admin/roles → revokes role from user X
  → AdminRolesView calls VersionBumper.bump(user X)
    → InMemoryJCustosVersionStore.increment(key) → +1

    → ObservableJCustosVersionStore notifies VaadinJCustosVersionChangeBridge
      → ui.access(...) on every open UI of user X
        → snapshot != current → subject dropped, audit SessionStale,
          UI sent to {{SUBJECT_PREFIX}}LoginView over @Push, session closed

User X without push, or on another node, clicks or navigates
  → JCustosVersionEnforcerListener (request handler / beforeEnter)
    → snapshot != current → session ended, reroute to {{SUBJECT_PREFIX}}LoginView
    → audit SessionStale event
```

Result: user X is forced to re-authenticate - at once with push, on the
next click without. New session captures fresh snapshot — they see the
updated role set. The observable store is node-local: a cluster that
shares one version store reacts at once on the node that made the change
and on the next request everywhere else.

## Verification checklist

1. `./mvnw -pl <module> -am compile` — green.
2. `./mvnw -pl <module> jetty:run`.
3. Open `http://localhost:8080/login` — log in as admin (browser A).
4. In a private window (browser B), log in as `user`.
5. In browser A → `/admin/roles` → assign `ADMIN` to `user`.
6. In browser B → do nothing. **Expected:** B is sent to `/login`
   without a click (the demo application uses `@Push`). After
   re-login, the welcome page shows the ADMIN badge.
7. Check `/audit` — a `SessionStale` event appears for browser B.
8. (If HIBP enabled) try setting `Password1!` in any password field
   wired through `PasswordPreflight`. **Expected:** rejection
   message "this password is on a known-bad list".
9. Hash inspection: look at the rendered admin user's password hash
   on disk (persistence skill) or in memory. **Expected:** the envelope
   carries `alg=Argon2id` (`$pwh$v=1$ct=PASSWORD$alg=Argon2id$…`), not
   PBKDF2.
10. First administrator (with the persistence skill): set up with
    `password123` → refused; set up with a strong password → you can log
    in with it.

## Pitfalls

### Drift detection requires BOTH SPIs

`JCustosVersionStore` + `SubjectIdResolver` must BOTH be SPI-registered
or the snapshot-capture in `LoginView` silently no-ops. Symptom: roles
revoked mid-session don't kick anyone — the user just keeps going.
This skill registers both; do not delete either META-INF entry.

### `VersionBumper.bump(...)` must run *after* the directory mutation

`AdminRolesView` calls `assignRole` / `revokeRole` / `deleteUser` THEN
calls `VersionBumper.bump(user)`. Reversed order means: the bumper
reads the version, the mutation happens, but the bumped version is
based on the pre-mutation read — race-free because the increment is
atomic, but logically odd. Keep the order.

### HIBP needs network egress

The HIBP checker makes a `GET https://api.pwnedpasswords.com/range/<5-hex-prefix>`
on every check. Behind a corporate firewall this hangs without a
proxy. The template uses `Duration.ofSeconds(5)` as the request
timeout — failure to reach HIBP returns `CheckFailed`, and the
preflight's `CompositeCompromisedPasswordChecker` is built with
`CheckFailurePolicy.ALLOW`, so it counts as "allow" (fail-open by
design: a network outage should not block legitimate password
changes). Use `CheckFailurePolicy.BLOCK` where an unchecked password
must not be set; the change service then answers "try again later".

### Argon2id is intentionally slow

Argon2id with the modern profile defaults targets ~250 ms per hash.
Login throughput drops compared to PBKDF2-100k. Adjust via
`Argon2idDefaults` overrides if your hardware can't sustain it; do
not weaken below `iterations=2, memory=64 MiB`.

### Mixed-algorithm verification

Existing PBKDF2 hashes (created under `jcustos-vaadin`) still
verify under `BouncyCastleHashingServices.modern()` — the registry
keeps all four providers (PBKDF2, bcrypt, scrypt, Argon2id) on the
verification path. The rehash engine upgrades them silently on the
next successful login. Production deployments with millions of stale
PBKDF2 hashes can budget the transition by enabling the modern
profile and waiting one login cycle per user.

### `Q_ADMIN` / `NERD` / `NOBODY` roles not bumped

`VersionBumper.bump(user)` knows nothing about which role changed —
it just increments the version. Any role mutation triggers the
drift, including roles whose absence would not affect the user's
access. That is intentional: an admin who revokes anything wants
that user out, full stop.

## What this skill deliberately does NOT cover

- **API keys / refresh tokens / rate limiting** — shipped as the V00.70
  account-lifecycle / token / rate-limit services; out of this skill's
  hashing + drift scope.
- **OAuth2 / OIDC federation (SSO login with Keycloak / Entra / Auth0 /
  Okta / Google / GitHub)** — the released V00.76–V00.79 identity stack
  (`jCustos-jwt` / `-oauth2` / `-identity-oidc`, vendor profiles, DPoP,
  mTLS, PAR/JAR/JWE); belongs in a dedicated identity skill, not here.
- **Tenant-scoped policies** — single-tenant only.
- **Persistent JCustosVersionStore** — when combined with
  `jcustos-vaadin-persistence`, swap the META-INF/services entry to point
  at `EclipseStoreJCustosVersionStore` via a custom provider class
  (manual one-line edit; not templated).
- **Multi-factor authentication** — separate concern, not part of
  V00.71.
