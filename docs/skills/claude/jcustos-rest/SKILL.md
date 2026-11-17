---
name: jcustos-rest
description: Battle-tested integration of jCustos (V00.73+) into a JDK-`HttpServer`-based REST application. Minimal stack — V00.73 fluent `RestSecurity.bootstrap()` + `@JCustosAutoService`-registered `AuthenticationService` / `AuthorizationService` + in-memory user directory (fixed-password demo accounts only behind a development switch) + in-memory `TokenStore` for Bearer tokens + 4 endpoint groups (auth, audit, sessions, users). Use PROACTIVELY when the project shows REST signals (`HttpServer`, `HttpHandler`, `com.sun.net.httpserver`, JAX-RS, `@Produces`, `@Consumes`) AND the user mentions jCustos, integrate jCustos REST, secure my REST API, `RestSecurity.bootstrap`, `RestSubjectResolver`, `RestAuthorizationFilter`, `RestRequest`, `RestResponse`, `BearerTokenExtractor`, "add auth to my REST server", "minimum viable REST auth", "/api/auth/login + token". Provides POM patch (`jCustos-rest`, `jCustos-dx-rest`, `jakarta.servlet-api`), 15 ready-to-render templates (User + Credentials + UserDirectory + TokenStore + JSON helper + Router + 4 handler groups), opt-in development seed (`-Djcustos.demo.insecure-seed-accounts=true`), Bearer-token-based session management, problem+JSON error bodies. Does NOT cover OpenAPI metadata, CORS configuration, refresh tokens, API keys, rate limiting (all available since V00.72 — see `jCustos-dx-rest.openApiMetadata(...)` / `.cors(...)` and the V00.70 token / rate-limit services), nor OAuth2 / OIDC / JWT-bearer resource-server validation (the released V00.76–V00.79 identity stack — a separate skill), and does NOT cover token-based first-admin bootstrap or persistence — those are the `jcustos-rest-persistence` skill.
---

# jCustos ↦ REST — full integration

Drops the jCustos security stack into a JDK-`HttpServer`-based
REST app. End state: a running server with:

- an in-memory user directory that starts **empty**; the fixed-password
  accounts admin/admin and user/user exist only with
  `-Djcustos.demo.insecure-seed-accounts=true`, and the server refuses
  that switch outside `DEVELOPMENT` mode
- a server bound to the loopback interface only, deny-by-default on
- `POST /api/auth/login` returns a Bearer token — the only response
  that ever carries one
- `POST /api/auth/logout` revokes it
- `GET /api/whoami` returns the current subject
- `GET /api/audit` (`@RequiresPermission("audit:read")`)
- `GET /api/sessions`, `DELETE /api/sessions/{ref}` (`@RequiresPermission("admin:sessions")`;
  a session is named by its `SessionRef`, `sref-…`, never by its token)
- `GET /api/users`, `POST /api/users`, `DELETE /api/users/{id}`, `POST /api/users/{id}/roles/{role}`, `DELETE /api/users/{id}/roles/{role}` (`@RequiresPermission("admin:roles")`)

Audit + sessions are in-memory (ring buffer + map). Layer 2
(`jcustos-rest-persistence`) swaps in Eclipse-Store; Layer 3
(`jcustos-rest-hardening`) adds Argon2id + drift detection.

## How to use this skill

1. **Read the user's brief.** Default slots: package, port (8080).
2. **Echo extracted slots back** in one block.
3. **Apply the POM patch** (4 deps: jCustos-rest, jCustos-dx-rest,
   autoservice-annotations, jakarta.servlet-api).
4. **Render every template** in `references/` with substitutions.
5. **Run** `./mvnw -pl <module> -am compile` then
   `./mvnw -pl <module> exec:java -Dexec.mainClass="<base>.RestServer"`.
6. **Verify**: start with `-Djcustos.demo.insecure-seed-accounts=true`, then
   `curl -X POST -d '{"username":"admin","password":"admin"}'
   http://127.0.0.1:8080/api/auth/login` returns a token.

## Slots

| Slot | Example | Default |
|---|---|---|
| `{{BASE_PACKAGE}}` | `com.acme.api` | — |
| `{{BASE_PATH}}` | `com/acme/api` | derived from package |
| `{{SUBJECT_TYPE}}` | `User`, `Account` | `User` |
| `{{SUBJECT_PREFIX}}` | `My`, `App`, empty | `My` |
| `{{ADMIN_USERNAME}}` / `{{ADMIN_PASSWORD}}` | `admin / admin` | |
| `{{USER_USERNAME}}` / `{{USER_PASSWORD}}` | `user / user` | |
| `{{BOOTSTRAP_PROFILE}}` | `DEVELOPMENT`, `PRODUCTION`, `STRICT` | `DEVELOPMENT` |
| `{{REST_PORT}}` | `8080`, `9000` | `8080` |

## Template targets

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge into `pom.xml` |
| `Subject.java.tmpl` | `{{BASE_PATH}}/security/model/{{SUBJECT_TYPE}}.java` |
| `Credentials.java.tmpl` | `{{BASE_PATH}}/security/model/Credentials.java` |
| `UserDirectory.java.tmpl` | `{{BASE_PATH}}/security/model/UserDirectory.java` |
| `InMemoryUserDirectory.java.tmpl` | `{{BASE_PATH}}/security/model/InMemoryUserDirectory.java` |
| `UserDirectoryProvider.java.tmpl` | `{{BASE_PATH}}/security/model/UserDirectoryProvider.java` |
| `AuthorizationRole.java.tmpl` | `{{BASE_PATH}}/security/roles/AuthorizationRole.java` |
| `AppPermission.java.tmpl` | `{{BASE_PATH}}/security/permissions/AppPermission.java` |
| `AuthenticationService.java.tmpl` | `{{BASE_PATH}}/security/services/{{SUBJECT_PREFIX}}AuthenticationService.java` |
| `AuthorizationService.java.tmpl` | `{{BASE_PATH}}/security/services/{{SUBJECT_PREFIX}}AuthorizationService.java` |
| `TokenStore.java.tmpl` | `{{BASE_PATH}}/security/TokenStore.java` |
| `SessionStoreProvider.java.tmpl` | `{{BASE_PATH}}/security/SessionStoreProvider.java` |
| `MyRestSubjectResolver.java.tmpl` | `{{BASE_PATH}}/security/{{SUBJECT_PREFIX}}RestSubjectResolver.java` |
| `Json.java.tmpl` | `{{BASE_PATH}}/Json.java` |
| `Router.java.tmpl` | `{{BASE_PATH}}/Router.java` |
| `AuthHandler.java.tmpl` | `{{BASE_PATH}}/handlers/AuthHandler.java` |
| `AuditHandler.java.tmpl` | `{{BASE_PATH}}/handlers/AuditHandler.java` |
| `SessionsHandler.java.tmpl` | `{{BASE_PATH}}/handlers/SessionsHandler.java` |
| `UsersHandler.java.tmpl` | `{{BASE_PATH}}/handlers/UsersHandler.java` |
| `RestServer.java.tmpl` | `{{BASE_PATH}}/RestServer.java` |

## Key design choices

- **JDK `HttpServer` only.** No Jetty / Spring / JAX-RS to keep the
  surface tiny. Real deployments swap the server, but the
  `RestSubjectResolver` + handlers stay.
- **Bearer-token sessions.** Login returns 32 random bytes as hex;
  the `TokenStore` keeps only the token's SHA-256 → user **id**,
  security-version snapshot, creation and last-activity time. The
  resolver loads the user on every request, so a deleted user or a
  revoked role takes effect for open tokens at once (JS-SEC-132).
  Logout removes the mapping. Every session is named by
  `SessionRef.of(token)` — audit events, session records, the admin
  endpoint — never by the token (JS-SEC-117).
- **Permission annotations on handler methods.** Routes name a
  `public static` handler method; the `Router` hands it to
  `RestAuthorizationFilter.authorizeAndHandle(request, response, handler,
  method, handlerClass)` (JS-SEC-114), which evaluates the annotation,
  audits the decision and renders refusals; no per-handler
  `if (!subject.hasPerm) { return 403; }`. Routes are path patterns
  (`/api/users/{id}/roles/{role}`), the most specific wins, and a
  duplicate route key fails at start-up.
- **Every header line reaches the library.** The `Router` refuses a
  repeated `Authorization`, `X-Api-Key` or `Cookie` header with 400
  before anything runs and builds the `RestRequest` with
  `RestHeaderLines` (JS-SEC-113).
- **One correlation id per request, guard first.** The `Router` runs
  guard, filters and handler inside `RestAuditCorrelation.call(...)`,
  so the login handler's own `LoginSucceeded` and the version filter's
  `SessionStale` carry the same `corr=` as the filters' events (R5).
  Its first step is a `RestOriginGuard` installed with
  `.originGuard(...)` - a no-op in this bearer-token skill, the CSRF
  protection once the session moves into a cookie.
- **Per-request session checks.** `MyRestSubjectResolver` reports
  session metadata (idle / absolute lifetime), the version snapshot
  (drift, layer 3) and `resolveSessionId`; the login saves a
  `SessionRecord` under the `SessionRef`, and a record set to
  `REVOKED` ends the session on its next request (JS-SEC-131).
- **Login protocol.** `AuthHandler.login` runs a per-address rate
  limit, then `beforeAttempt` and exactly one of `confirmSuccess`,
  `recordFailure`, `abandonAttempt` on the registered
  `LoginAttemptPolicy`. An unknown name costs one KDF run; a
  verification shed under load answers 503, not 401 (JS-SEC-126); a
  check that throws counts as a failed attempt and answers 401.
  Every 401 goes through the published decision mapper and carries
  `WWW-Authenticate` (JS-SEC-086).
- **Errors as plain text.** Production swaps the body strategy via
  `.errorBodies(new ProblemJsonErrorBodyStrategy())` in the bootstrap
  chain — that's a `jCustos-dx-rest` one-liner.

## Pitfalls

### `jakarta.servlet-api` provided

Same as the Vaadin skill: `RestJCustosVersionContext` and other
internals reference servlet-api types via type-only paths. Without
`jakarta.servlet-api` in `provided` scope the compiler stops on
`HttpSessionBindingListener` or similar.

### `PRODUCTION` / `STRICT` profiles

The demo runs `DEVELOPMENT`. A `PRODUCTION` or `STRICT` bootstrap also
needs a `LogoutService` (`.logout(...)`, otherwise
`logout/missing-service`), and the development seed switch is refused.

### Token theft is not addressed

Bearer tokens are not bound to client IP or device. A leaked token
grants access until logout, revocation, or the session policy's idle
(30 min) / absolute (12 h) lifetime ends it. For real
deployments add device binding or move to short-lived JWT +
refresh-token flow (`jCustos-rest`'s `TokenService` shipping in
V00.71).

### Cookie sessions need the origin guard

The skill authenticates with bearer tokens, which a browser never sends
on its own: no CSRF exposure, nothing to configure. If you move the
session into a cookie, every state-changing route becomes reachable
from any page the user visits. Install the guard -
`.originGuard(RestOriginGuard.sameOrigin())`, behind a proxy with
`.withAllowedOrigins(Set.of("https://app.example"))` - and keep the
`Router`'s first step. A same-origin guard expects `https` origins (plain
`http` only for a loopback host); a deployment that browsers reach over
plain `http` on another host adds `.withScheme("http")`. Credentialed CORS
without a guard is reported as `rest/credentialed-cors-without-origin-guard`,
a credentialed CORS origin the guard refuses as
`rest/credentialed-cors-origin-not-accepted`. Background and the interplay
with `SameSite`: `docs/security/csrf.md`.

### Audit-sink at scale

The default ring buffer holds 256 events. The `/api/audit` endpoint
returns everything in JSON in one shot — fine for demo, ruinous at
production scale. Layer 2 (`jcustos-rest-persistence`) swaps to
`EclipseStoreAuditEventStore` with pagination support.
