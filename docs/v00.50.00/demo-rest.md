# Demo REST application

`demo-rest` is a self-contained, runnable example showing how to use
`jSentinel-core` and `jSentinel-rest` to protect HTTP handlers with permissions.

It uses **JDK APIs only** (`com.sun.net.httpserver.HttpServer` for the server,
`java.net.http.HttpClient` for the CLI). No web framework is involved.

The demo is **not** production-grade authentication. Token storage,
password handling, and the user store are intentionally simple. Real systems
must replace these with hashed credentials, signed tokens, expiry/refresh,
and a proper authentication backend.

> **Related demos**: For the in-JVM Vaadin equivalent see
> [`demo-vaadin.md`](demo-vaadin.md). For a Vaadin UI that talks to
> *this* server over HTTP see
> [`demo-vaadin-rest-client.md`](demo-vaadin-rest-client.md). The
> three demos cover the same security model from three angles
> (no UI / Vaadin in-JVM / Vaadin against REST).

> Transport-level constants (`DemoEndpoints`) and the tiny JSON
> helper (`DemoJson`) live in the dedicated `demo-rest-shared` module
> so server and client code can share them without dragging in the
> server's domain classes.

---

## Module layout

```text
demo-rest/
├── server/
│   ├── DemoRestServer            main, starts HttpServer
│   ├── DemoHttpRouter            HttpHandler, dispatches by method+path
│   ├── DemoHandlers              login/me/operations/documents/admin/logout
│   ├── DemoBootstrapHandlers     /api/bootstrap/status + /api/bootstrap/admin
│   ├── DemoHttpRequest           BodyRestRequest impl (byte[] body)
│   ├── DemoHttpResponse          buffering RestResponse impl
│   ├── DemoSubjectResolver       Bearer token lookup via BearerTokenExtractor
│   ├── DemoTokenStore            in-memory token → user
│   ├── DemoOperationRegistry     thin wrapper around SecuredOperationRegistry
│   ├── DemoBootstrapEnvironment  one-line call to BootstrapConfigurationLoader
│   └── DemoAdministratorAccountStore  bootstrap-side adapter over DemoUserStore
│
├── cli/
│   ├── DemoRestCli               main
│   ├── CliCommandLoop            read/dispatch/print, includes init-admin
│   ├── CliSession                token + last operations cache
│   └── CliOperationClient        HttpClient wrapper
│
├── domain/
│   ├── DemoRole, DemoPermission
│   ├── DemoRolePermissionMapping (delegates to StaticRolePermissionMapping)
│   ├── DemoUser, DemoUserStore   hashed-password store
│   └── DemoDocument, DemoDocumentStore
│
```

`DemoEndpoints` and `DemoJson` are not in this module — they live in
`demo-rest-shared` (the small transport-level module shared with the
Vaadin REST client demo). `demo-rest` depends on `demo-rest-shared`
and re-uses them transparently.


Generic logic — bearer extraction, authentication filter, operation
registry, bootstrap configuration loading — lives in `jSentinel-core` /
`jSentinel-rest`. `demo-rest` only carries demo data and demo wiring.

---

## Demo users

| username | password | role          |
|----------|----------|---------------|
| `admin`  | `admin`  | `ROLE_ADMIN`  |
| `editor` | `editor` | `ROLE_EDITOR` |
| `viewer` | `viewer` | `ROLE_VIEWER` |

These are **demo credentials only**. Do not reuse in production.

Since 00.84.00 (JS-SEC-137) the server listens on the loopback interface
only and creates **none** of these accounts by default. They exist only
when the server is started with the development switch
`-Djcustos.demo.insecure-seed-accounts=true` — for a throw-away local
instance, never for one others can reach:

- with the bootstrap mechanism enabled
  (`-Dsecurity.bootstrap.mode=TRANSIENT_CONSOLE`, the default, or
  `-Dsecurity.bootstrap.mode=PERSISTENT_FILE`) the switch adds `editor`
  and `viewer`; `admin` is **not** pre-populated;
- with `-Dsecurity.bootstrap.mode=DISABLED` it adds `admin` as well.
  Bootstrap mode `DISABLED` without the switch refuses to start, because
  nothing could create an administrator.

Without the switch the first administrator must be created via the
bootstrap token — see [`docs/bootstrap.md`](bootstrap.md) and the CLI
command `init-admin`. The example sessions below assume the switch (and,
for `login admin admin`, bootstrap mode `DISABLED`).

## Demo permissions and role mapping

Permissions live in `demo-rest/.../domain/DemoPermission.java`:

```text
document:read
document:create
document:update
document:delete
admin:access
```

Role-permission mapping (`DemoRolePermissionMapping`):

```text
ROLE_ADMIN  -> document:read, document:create, document:update, document:delete, admin:access
ROLE_EDITOR -> document:read, document:create, document:update
ROLE_VIEWER -> document:read
```

These permissions are demo-specific. They live only in `demo-rest` and must
not be moved into `jSentinel-core`, `jSentinel-vaadin`, or `jSentinel-rest`.

---

## Endpoints

| Method | Path                    | Authorization                    |
|--------|-------------------------|----------------------------------|
| POST   | `/api/login`            | anonymous                        |
| POST   | `/api/logout`           | authenticated                    |
| GET    | `/api/me`               | authenticated                    |
| GET    | `/api/operations`       | authenticated, filtered server-side |
| GET    | `/api/documents`        | `@RequiresPermission("document:read")`   |
| POST   | `/api/documents`        | `@RequiresPermission("document:create")` |
| DELETE | `/api/documents/{id}`   | `@RequiresPermission("document:delete")` |
| GET    | `/api/admin/status`     | `@RequiresPermission("admin:access")`    |

Permission-protected endpoints run through `RestAuthorizationFilter` from
`jSentinel-rest`. The filter resolves the subject, scans the handler method
for a `@RequiresPermission` annotation, and maps the decision:

- `Granted` → the handler runs.
- `Unauthenticated` → 401 with body `Unauthorized`. The handler does **not** run.
- `Forbidden` → 403 with body `Forbidden`. The handler does **not** run.

Error bodies are short and generic — no stack traces, no internal class names.

---

## Run

### Start the server

```bash
mvn -pl :demo-rest -am compile
mvn -pl :demo-rest exec:java
```

The server binds to `http://localhost:8080`. Pass a different port as the
first argument:

```bash
mvn -pl :demo-rest exec:java -Dexec.args="9000"
```

### Start the CLI in another terminal

```bash
mvn -pl :demo-rest exec:java \
    -Dexec.mainClass=com.svenruppert.jsentinel.demo.rest.cli.DemoRestCli
```

Pass a non-default base URL as an argument:

```bash
mvn -pl :demo-rest exec:java \
    -Dexec.mainClass=com.svenruppert.jsentinel.demo.rest.cli.DemoRestCli \
    -Dexec.args="http://localhost:9000"
```

---

## CLI commands

```text
login <username> <password>
me
operations
call <operation-id> [argument]
logout
init-admin              create the first administrator (interactive)
help
exit
```

`init-admin` is only useful while the system is uninitialized. It prompts
for the bootstrap token (masked when a TTY is available), the chosen admin
username, the new password (twice), and optional displayName/email. The
CLI calls the same `/api/bootstrap/admin` endpoint as the Vaadin `/setup`
view.

---

## Example sessions

### Viewer

```text
> login viewer viewer
Login successful. Current user: Viewer User

> operations
Available operations:
- list-documents     GET    /api/documents (List documents)

> call list-documents
200 OK
{"documents":[{"id":1,"title":"Welcome"},{"id":2,"title":"Sample document"}]}

> call delete-document 1
Unknown operation. Run 'operations' first to refresh the server-provided list.
```

If the viewer crafts the call manually anyway, the server returns `403`:

```text
> call delete-document 1     # only available if previously cached for an admin session
403 Forbidden
Forbidden
```

### Editor

```text
> login editor editor
Login successful. Current user: Editor User

> operations
Available operations:
- list-documents     GET    /api/documents (List documents)
- create-document    POST   /api/documents (Create document)

> call create-document "Specs draft"
201 Created
{"id":3,"title":"\"Specs"}
```

### Admin

```text
> login admin admin
Login successful. Current user: Admin User

> operations
Available operations:
- list-documents     GET    /api/documents (List documents)
- create-document    POST   /api/documents (Create document)
- delete-document    DELETE /api/documents/{id} (Delete document)
- admin-status       GET    /api/admin/status (Admin status)

> call admin-status
200 OK
{"status":"ok","message":"Admin endpoint executed."}

> call delete-document 1
204 No Content
```

---

## Authorization scenarios

The demo demonstrates three outcomes:

1. **Unauthenticated** — request without a token (or with an invalid token).
   The server responds with `401 Unauthorized`. The handler does not run.

2. **Authenticated but unauthorized** — valid token, missing permission.
   The server responds with `403 Forbidden`. The handler does not run.

3. **Authorized** — valid token, required permission present. The handler runs
   and produces the normal response.

These three cases are covered by `DemoRestServerTest` in
`demo-rest/src/test/java/.../server/DemoRestServerTest.java`.

---

## CLI does not make local authorization decisions

The CLI does not contain any role or permission logic. The list of available
operations always comes from `GET /api/operations`, which is filtered by the
server using the same permission model that protects the handlers.

The CLI just renders the server-provided list. The server is the single source
of truth.

---

## Relationship to `jSentinel-rest` and `jSentinel-core`

`jSentinel-rest` provides:

- `RestRequest`, `RestResponse`, `RestHandler` — minimal abstractions
- `BodyRestRequest` — body-capable request (handlers pattern-match on this)
- `RestSubjectResolver` — contract for resolving the current subject
- `RestHeaders`, `BearerTokenExtractor` — header lookup + Bearer parsing
- `RestAccessContextFactory` — neutral access context creation
- `RestAuthenticationFilter` — 401-only filter for authenticated-only paths
- `RestAuthorizationFilter` — pre-handler permission/role enforcement
- `HttpStatusDecisionMapper` — maps decisions to HTTP status
- `BootstrapRestStatusMapper` — `InitialAdminCreationResult` → status code

`jSentinel-core` provides:

- `SecuredOperationRegistry` + `OperationVisibilityService` — generic
  operation discovery (the `/api/operations` endpoint sits on top)
- `StaticRolePermissionMapping` + `RolePermissionResolver` — role→
  permission helpers
- `BootstrapConfigurationLoader` + `BootstrapStatus` — config + status
- `PermissionGuard` + `AccessDeniedException` — generic permission checks

`demo-rest` plugs in only the demo-specific pieces:

- `DemoSubjectResolver` — wraps `BearerTokenExtractor`
- `DemoRolePermissionMapping` — wraps `StaticRolePermissionMapping`
- `DemoOperationRegistry` — wraps `SecuredOperationRegistry`
- `DemoBootstrapEnvironment` — wraps `BootstrapConfigurationLoader`
- `DemoHandlers` / `DemoBootstrapHandlers` — annotated handler methods

The demo proves how a real project plugs its own domain rights into the
generic library. URL-shortener-specific or other application-specific
permissions are **not** part of this demo and must live in the consuming
application.
