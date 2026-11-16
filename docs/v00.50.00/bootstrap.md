# Bootstrap mechanism — first administrator setup

A fresh installation does not ship with any administrator account. The
**bootstrap mechanism** authorizes the **one-time** creation of the very
first administrator while the system is still uninitialized. Once an
administrator exists, the mechanism turns itself off.

**The bootstrap token is not the administrator password.** It only
authorizes the initial setup. The administrator chooses a real password
during setup; that password is hashed and stored.

---

## Modes

| Mode | When the token is generated | Where the token lives | Survives restart? |
|---|---|---|---|
| `PERSISTENT_FILE` | Once, until setup completes | File on disk (POSIX `0600`) | Yes |
| `TRANSIENT_CONSOLE` | On every server start while uninitialized | In memory only | No — a new token is generated next start |
| `DISABLED` | Never | n/a | n/a |

Configuration. System properties take precedence; if a property is unset
or blank, the corresponding environment variable is consulted; if both are
unset, the default applies.

| System property | Environment variable | Default (demos) | Values |
|---|---|---|---|
| `security.bootstrap.mode` | `SECURITY_BOOTSTRAP_MODE` | `TRANSIENT_CONSOLE` | `DISABLED` / `TRANSIENT_CONSOLE` / `PERSISTENT_FILE` |
| `security.bootstrap.token.file` | `SECURITY_BOOTSTRAP_TOKEN_FILE` | `./data/bootstrap.token` | filesystem path (used only in `PERSISTENT_FILE` mode) |
| `security.bootstrap.token.ttl` | `SECURITY_BOOTSTRAP_TOKEN_TTL` | `PT24H` | ISO-8601 duration, e.g. `PT15M`, `PT12H` |

Reading is centralized in `BootstrapConfigurationLoader` (jSentinel-core). The
demos call it with their own defaults — no duplicated property parsing.
Invalid values fail fast with `IllegalArgumentException`.

### Hard guard: DISABLED + no admin = startup failure

`BootstrapStartup.initializeIfRequired(...)` refuses to start the
application if the bootstrap mode is `DISABLED` **and** no administrator
account exists. This catches the "nobody can ever log in"
misconfiguration and surfaces it immediately with a clear
`IllegalStateException`, instead of leaving a quietly unusable server
running.

---

## Library API (`jSentinel-core` / `com.svenruppert.jsentinel.bootstrap`)

| Type | Purpose |
|---|---|
| `BootstrapMode`, `BootstrapConfiguration` | Configuration |
| `BootstrapConfigurationLoader` | Loads config from sysprops + env vars (centralized) |
| `BootstrapStatus` | Adapter-neutral, leak-safe status snapshot (never carries the token) |
| `BootstrapToken`, `BootstrapTokenGenerator` | Token model + `SecureRandom` generator (XXXX-XXXX-XXXX-XXXX-XXXX, ~100 bits, no `O 0 I 1`) |
| `BootstrapTokenStore`, `InMemoryBootstrapTokenStore`, `FileBootstrapTokenStore` | Token persistence; since 00.84.00 `FileBootstrapTokenStore` adopts only a file it can have written itself (on POSIX a regular file of the process user without access for group or others, token in the generator's format) and otherwise generates a fresh token (JS-SEC-130) |
| `BootstrapTokenOutput`, `ConsoleBootstrapTokenOutput`, `FileBootstrapTokenOutput` | Operator-facing banner emitter |
| `BootstrapStateService` | Tells whether bootstrap is required |
| `BootstrapStartup` | One-shot init on server boot |
| `AdministratorAccountStore`, `NewAdministrator` | App-side seam |
| `PasswordHasher`, `Pbkdf2PasswordHasher` | Password hashing (PBKDF2-HMAC-SHA256; 600 000 iterations since 00.84.00, previously 120 000 — older hashes still verify and report `needsRehash`) |
| `PasswordPolicy`, `MinimumLengthPasswordPolicy` | Password validation |
| `CreateInitialAdminCommand`, `InitialAdminCreationResult` | Service contract |
| `InitialAdminBootstrapService` | Orchestrator: validate → check race → hash → create → invalidate token, all under a single `ReentrantLock` |

### Other reusable jSentinel-core types extracted in this round

| Type | Package | Purpose |
|---|---|---|
| `PermissionGuard` | `authorization.api` | `hasPermission` / `requirePermission` (and role variants) on any `HasPermissions`/`HasRoles`. Used by demo-vaadin's UI guard. |
| `AccessDeniedException` | `authorization.api` | Generic exception thrown by `PermissionGuard.requirePermission`. |
| `StaticRolePermissionMapping` | `authorization.api.permissions` | Immutable {role → permissions} mapping with a builder. |
| `RolePermissionResolver` | `authorization.api.permissions` | Merges permissions across multiple roles. |
| `SecuredOperationDescriptor`, `SecuredOperationRegistry`, `OperationVisibilityService` | `authorization.api.operations` | Generic operation discovery. Demo-rest uses this for the `/api/operations` endpoint and stores `httpMethod`/`path` in the descriptor's `attributes`. |

### REST adapter additions (`jSentinel-rest`)

| Type | Purpose |
|---|---|
| `RestHeaders` | Case-insensitive header lookup |
| `BearerTokenExtractor` | Parses `Authorization: Bearer …` (case-insensitive scheme, trimmed token, never logged) |
| `RestAuthenticationFilter` | Authenticated-only filter for endpoints without a specific permission gate (returns 401 + body `Unauthorized` when no subject is resolved) |
| `BodyRestRequest` | Body-capable `RestRequest`. Adapters supply raw bytes; helpers decode as UTF-8 string. |
| `BootstrapRestStatusMapper` | Maps `InitialAdminCreationResult` to HTTP status code + stable error code. |

The library has no Vaadin, Servlet, or REST-framework dependencies.

---

## Three setup paths

### 1. REST (`demo-rest`)

Endpoints:

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/bootstrap/status` | `{ "bootstrapRequired": true, "mode": "..." }` — never returns the token |
| `POST` | `/api/bootstrap/admin` | body: `{ bootstrapToken, username, password, displayName?, email? }` |

Possible response codes: `201 created`, `400 bad_request` / `password_policy_violation` / `invalid_username`, `403 invalid_bootstrap_token`, `409 system_already_initialized`, `500 internal_error`. Bodies are short and generic — no token, no stack traces, no class names.

Run:

```bash
# transient — token printed to stdout
mvn -pl :demo-rest exec:java -Dsecurity.bootstrap.mode=TRANSIENT_CONSOLE

# persistent — token written to file
mvn -pl :demo-rest exec:java \
    -Dsecurity.bootstrap.mode=PERSISTENT_FILE \
    -Dsecurity.bootstrap.token.file=./data/bootstrap.token
```

### 2. CLI (`demo-rest`)

```text
> init-admin
Bootstrap token: ********
Admin username [admin]: admin
New admin password: ********
Repeat password: ********
Display name (optional):
Email (optional):
Administrator created. You can now log in with the chosen password.
```

The CLI calls the same `/api/bootstrap/*` endpoints. Passwords are read via
`Console.readPassword()` when a TTY is available, otherwise fall back to
visible input (e.g. when piped).

### Standalone Vaadin demo vs. REST-authoritative architecture

There are two Vaadin demos in this repo, each wiring the bootstrap
mechanism in a different way:

| Demo | Where setup happens | When to use |
|---|---|---|
| `demo-vaadin` | In-JVM via `InitialAdminBootstrapService` | Single-tier app — Vaadin process owns the user store. See [`demo-vaadin.md`](demo-vaadin.md). |
| `demo-vaadin-rest-client` | REST call to `POST /api/bootstrap/admin` against `demo-rest` | Two-tier app — separate REST backend owns the user store. See [`demo-vaadin-rest-client.md`](demo-vaadin-rest-client.md). |

`BootstrapStatus` (in `jSentinel-core`) and `BootstrapRestStatusMapper`
(in `jSentinel-rest`) are designed so both wirings reuse the same
result types — no code duplication.

### 3. Vaadin `/setup` (`demo-vaadin`)

The Vaadin demo defaults to `TRANSIENT_CONSOLE` so it works out-of-the-box:

```bash
# Default — transient token printed to the server console
cd demo-vaadin && mvn jetty:run

# Persistent token file
mvn -pl :demo-vaadin jetty:run \
    -Dsecurity.bootstrap.mode=PERSISTENT_FILE \
    -Dsecurity.bootstrap.token.file=./data/bootstrap.token

# Disable the bootstrap mechanism entirely
mvn -pl :demo-vaadin jetty:run -Dsecurity.bootstrap.mode=DISABLED
```

- `BootstrapServiceInitListener` (`VaadinServiceInitListener` SPI) eagerly
  initializes the bootstrap on Vaadin service start, so the token banner
  appears in the console **immediately** — without having to navigate to
  any view first.
- `/setup` is shown only while the system is uninitialized.
- `/login` redirects to `/setup` until the first administrator exists.
- After setup, the view forwards to `/login` and is no longer reachable.
- The Vaadin form calls `InitialAdminBootstrapService` directly in-JVM —
  the same authoritative service the REST endpoint uses. The UI never
  decides whether bootstrap is allowed; the service does.

If you want to clear the pre-populated admin to play through the flow
on every restart, the bootstrap wiring already does that for you when
the mode is non-`DISABLED`: `BootstrapWiring.build()` calls
`DemoUserDirectory.enableBootstrapMode()` which removes any
admin-tagged entries from the in-memory user directory before the
first navigation event.

### 4. Vaadin `/setup` against a REST backend (`demo-vaadin-rest-client`)

The second Vaadin demo treats the REST server as the authoritative
source. The flow is identical from the user's perspective, but
internally the form submits via `DemoBackendClient.createInitialAdmin(...)`
which calls `POST http://localhost:8080/api/bootstrap/admin`.

```bash
# Terminal 1 — backend (TRANSIENT_CONSOLE prints the token to its console)
mvn -pl :demo-rest exec:java

# Terminal 2 — Vaadin frontend
mvn -pl :demo-vaadin-rest-client jetty:run
# Browser: http://localhost:9090/
```

`http://localhost:9090/` redirects to `/setup` because
`backend.bootstrapStatus()` reports `bootstrapRequired = true`. Paste
the token from the backend console and submit. Upon `Created`, the
UI navigates to `/login`.

This wiring is documented in detail in
[`demo-vaadin-rest-client.md`](demo-vaadin-rest-client.md).

---

## Security rules

- The token is **never** written to the application logger.
- The token is **never** echoed in HTTP responses.
- The token is **never** included in Vaadin notifications.
- In persistent mode, only the **path** to the token file is logged.
- Token files are created **atomically** with `rw-------` (0600) on POSIX
  file systems via `Files.newByteChannel(..., CREATE_NEW, ...,
  PosixFilePermissions.asFileAttribute(...))`. There is no window during
  which the file exists with default umask permissions.
- Tokens have a configurable validity (default `BootstrapConfiguration.DEFAULT_VALIDITY`
  = 24 h). Tokens older than the validity are
  - **regenerated** on the next startup in `PERSISTENT_FILE` mode, and
  - **rejected** by `InitialAdminBootstrapService` (returned as
    `InvalidBootstrapToken`, with no leak about whether the rejection was
    "wrong value" or "expired").
- Passwords are passed as `char[]` and cleared after hashing.
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes, never plaintext.
- The `check-admin-exists / create / invalidate-token` sequence runs under
  a `ReentrantLock`, so two parallel setup requests cannot both create an
  administrator. There is a dedicated parallelism test for this.
- After successful setup the token is invalidated. Persistent mode also
  deletes the token file. If deletion fails, the setup still succeeds and
  a `WARNING` is emitted via `java.util.logging` (without the token
  value) so operators can manually clean the stale token store.

---

## Operator hygiene

- The token file must **not** be committed to a repository.
- The token file must **not** be shared on chat or email.
- After setup, delete the token file even if the server already removed it.
- In transient mode, the printed token banner must not be archived in CI logs.
- For production, consider replacing `MinimumLengthPasswordPolicy(8)` with a
  stronger application policy.
- Production deployments should also pair the bootstrap mechanism with the
  audit, brute-force, and session policies described in
  `Konzept-V00.60.00.md`.
