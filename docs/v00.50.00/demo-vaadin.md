# Demo: Standalone Vaadin

`demo-vaadin` is a **single-JVM** Vaadin Flow application. Authentication,
authorization and the user store all live in the same process — there is
no separate backend service.

Use this demo to learn or showcase the basics: how to plug roles,
permissions, view-level annotations and UX-level guards into a Vaadin
UI without any HTTP boundary in between. For a two-tier setup
(Vaadin UI calls a separate REST backend) see
[`demo-vaadin-rest-client.md`](demo-vaadin-rest-client.md).

---

## Module layout

```text
demo-vaadin/
└── src/main/java/com/svenruppert/jsentinel/demo/app/
    ├── Application.java                    @Theme + @Push + AppShellConfigurator
    ├── MySessionAccessor.java              session helpers
    ├── security/
    │   ├── MyLoginListener.java            extends LoginListener<MyUser>
    │   ├── bootstrap/                       BootstrapWiring (in-JVM bootstrap)
    │   ├── model/                           DemoUserDirectory + InMemoryDemoUserDirectory + Provider
    │   ├── permissions/                     DemoPermission, PermissionGuard adapter
    │   ├── roles/                           AuthorizationRole, MyRoleAccessEvaluator, @VisibleFor
    │   └── services/                        MyAuthenticationService, MyAuthorizationService (SPI)
    └── views/
        ├── MyLoginView.java
        ├── SetupView.java                   in-JVM bootstrap setup (NOT a REST call)
        ├── MainView.java                    AppLayout + tabs + sign-out
        ├── components/
        │   ├── PermissionDemoCard.java      Pattern A vs Pattern B
        │   └── ViewNavigationCard.java
        ├── workspaces/                       per-tab content (Admin / Editor / User / Public / Useless)
        ├── AdminView.java                    standalone @VisibleFor(ADMIN)
        ├── NerdView.java                     standalone @VisibleFor(NERD, ADMIN)
        └── PublicView.java                   public route
```

In-JVM means: `MyAuthenticationService.checkCredentials(...)` calls the
local `DemoUserDirectory`, no HTTP. The bootstrap setup
(`SetupView`) calls `InitialAdminBootstrapService` directly in the
same VM via `BootstrapWiring`.

---

## Demo users

| username | password | role(s) |
|---|---|---|
| `user` | `user` | `USER` |
| `demo` | `demo` | `NERD` (and `USER` transitively) |
| (admin is NOT pre-populated) | — | created by you via the bootstrap flow |

These are demo credentials, hashed at startup with PBKDF2. Do not reuse.
Since 00.84.00 (JS-SEC-137) `user` and `demo` are created only when the
demo is started with the development switch
`-Djcustos.demo.insecureDemoAccounts=true` — for a local try-out, never on
an instance others can reach:

```bash
cd demo-vaadin && mvn jetty:run -Djcustos.demo.insecureDemoAccounts=true
```

The first administrator is created during the **first run** via the
bootstrap token printed to the server console.

---

## Run

```bash
# Once at the start, so all sibling modules land in ~/.m2:
mvn install -DskipTests

# Start the demo
cd demo-vaadin && mvn jetty:run
# Browser: http://localhost:8080/
```

Default Vaadin port is `8080`. Override with `-Djetty.http.port=...`
on the `jetty:run` invocation if needed.

### First run: bootstrap

On startup, the Jetty console prints a banner like:

```
============================================================
Initial administrator setup required.

Open /setup to create the first administrator.

Bootstrap token:
  AAAA-BBBB-CCCC-DDDD-EEEE

This token is single-use and only valid while the system is uninitialized.
============================================================
```

1. Browser opens `http://localhost:8080/`.
2. The framework redirects through `/login` → `/setup` because no
   admin exists.
3. Paste the **token** from the console, choose a username (default
   `admin`), password (twice), optional display name / email.
4. Submit → `Created` notification → redirect to `/login`.
5. Log in with the chosen username + password.

The token file lives only in memory by default
(`TRANSIENT_CONSOLE` mode). For a persistent token file, override:

```bash
cd demo-vaadin && mvn jetty:run \
    -Dsecurity.bootstrap.mode=PERSISTENT_FILE \
    -Dsecurity.bootstrap.token.file=./data/bootstrap.token
```

Bootstrap mode `DISABLED` does not skip the flow in this demo: the demo
has no administrator account of its own, so start-up stops with
"Bootstrap is DISABLED but no administrator account exists" (the guard in
`BootstrapStartup`). Use `TRANSIENT_CONSOLE` or `PERSISTENT_FILE`.

See [`bootstrap.md`](bootstrap.md) for the full bootstrap matrix.

---

## What to look at after login

### Welcome screen

Shows the logged-in user's display name and roles. `MainView` carries
`@SecureRoute()` (since 00.84.00, JS-SEC-158): every authenticated
subject reaches it, an anonymous visitor is sent to the login view. It is
the forward target for a signed-in subject that a role check refuses, so
it must admit every signed-in subject.

### Side navigation

Tabs visible per role:

| Tab | Visible to | Notes |
|---|---|---|
| Home | everyone | the welcome screen |
| Admin | `ADMIN` | `AdminWorkspace` |
| Nerd Zone | `ADMIN` or `NERD` | `NerdWorkspace` |
| My Area | every authenticated user | `UserWorkspace` |
| Public | every authenticated user | `PublicAllWorkspace` |
| Playground | always | `DemoUselessWorkspace` |

### `PermissionDemoCard` — UX vs. server-guard pattern

Each workspace embeds a `PermissionDemoCard` showing two button rows
for the three demo permissions (`demo:view`, `demo:edit`, `demo:admin`):

- **Pattern A** — Buttons are added to the layout *only* if the
  current subject has the permission (UX adaptation).
- **Pattern B** — Buttons are always added; on click the handler
  calls `PermissionGuard.requirePermission(...)`. If the subject
  lacks the permission, an `AccessDeniedException` is thrown and a
  red notification appears.

Pedagogical point: hiding UI elements is a comfort. The actual guard
is the server-side check before performing the action.

### `ViewNavigationCard` and standalone routes

Every workspace also embeds a `ViewNavigationCard` with `RouterLink`s
to standalone routes:

| Route | Annotation | Result for non-matching role |
|---|---|---|
| `/admin` | `@VisibleFor({ADMIN})` | anonymous: reroute to login; signed in without the role: forward to `MainView` |
| `/nerd` | `@VisibleFor({ADMIN, NERD})` | anonymous: reroute to login; signed in without the role: forward to `MainView` |
| `/public` | `@PublicRoute` | always reachable (the demo runs deny-by-default since 00.84.00, so a public view has to say so) |

With the demo accounts switched on, open them as `user/user` (USER only)
→ forwarded to `MainView`. Then log in as `demo/demo` (NERD) and reach
`/nerd` but not `/admin`.

### Sign out

The `Sign out` button uses `VaadinLogoutService` with
`LogoutPolicy.fullInvalidate("/login")`:

1. Subject removed from `SubjectStores`.
2. Browser redirect via `Page.setLocation(...)` (so the response
   carries the redirect before the next two steps fire).
3. HTTP session invalidated.
4. Vaadin session closed.

Result: the next request comes in with a fresh session and lands on
`/login` (or `/setup` if you cleared the admin too).

---

## Configuration

| System property | Environment variable | Default | Effect |
|---|---|---|---|
| `security.bootstrap.mode` | `SECURITY_BOOTSTRAP_MODE` | `TRANSIENT_CONSOLE` | `DISABLED` skips bootstrap; `PERSISTENT_FILE` writes to a token file |
| `security.bootstrap.token.file` | `SECURITY_BOOTSTRAP_TOKEN_FILE` | `./data/bootstrap.token` | Token file location for `PERSISTENT_FILE` |
| `security.bootstrap.token.ttl` | `SECURITY_BOOTSTRAP_TOKEN_TTL` | `PT24H` | ISO-8601 duration; expired tokens get regenerated on startup |

---

## What this demo does **not** do

- **No REST boundary.** Every check happens in the same JVM. For the
  two-tier picture see [`demo-vaadin-rest-client.md`](demo-vaadin-rest-client.md).
- **No audit log.** Login, logout, access-denied events are not
  captured (`JSentinelAuditService` is § 2 in `Konzept-V00.60.00.md`,
  not yet implemented).
- **No brute-force throttling** on login.
- **No session policy** (timeout, inactivity, rotation) — only the
  Vaadin/servlet defaults apply.

---

## Tests

```bash
mvn -pl :demo-vaadin -am test
```

The Vaadin demo currently has **no UI tests** (no Karibu/TestBench
infrastructure). The 9 tests in `jSentinel-vaadin` cover the framework
side; the demo wiring is exercised manually via `jetty:run`.
