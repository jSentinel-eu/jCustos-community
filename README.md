# jCustos — Community Edition

Pluggable authentication, authorization, and annotation-driven protection for
Vaadin Flow, lightweight REST, and plain-Java / desktop / CLI applications.
Uses Java SPI (`ServiceLoader`) for application-provided services.

Free software under the [EUPL 1.2](LICENSE), and complete on its own: a
framework-neutral core, three adapters (Vaadin, REST, standalone), the fluent
DX layer, compile-time tooling, modern password hashing, Eclipse-Store
persistence, the signed security event bus, and the full OIDC relying-party
stack with six vendor profiles — 37 library and testkit modules plus 15 demos.
Concrete roles and permissions live in applications or demo modules, never in
the library.

## Editions

jCustos is open core, split along one line: **building and securing an
application is free; operating and proving it is commercial.**

This repository is the Community Edition. Everything in it is production-ready
and unrestricted — nothing is time-limited, feature-gated or nagware. Signed
event envelopes, replay protection, Argon2id hashing and the whole identity
stack are security primitives, and security primitives stay free.

The **[Enterprise Edition](docs/editions/edition-matrix.md)** adds what teams
need when someone external asks what happened: tamper-evident audit chains with
signed, re-verifiable exports, metrics and health indicators, and event
exporters for webhooks, SIEM and OpenTelemetry. It plugs into the SPIs defined
here; this repository never references it.

- [Edition matrix](docs/editions/edition-matrix.md) — what is in which edition
- [Moving to the Enterprise Edition](docs/editions/migrating-to-the-enterprise-edition.md) — one line per dependency
- [Contributing](CONTRIBUTING.md) — pull requests need the [CLA](CLA.md)

## Module Structure

| Module | Artifact | Description |
|---|---|---|
| `jCustos-core` | `jCustos-core` | Generic, framework-neutral security concepts and decision logic. Owns every SPI contract, all 11 persistence-store interfaces (Phase 2), the JCustosVersion drift-detection stack (Phase 4), and the account-lifecycle / token / rate-limit services (Phase 7) |
| `jCustos-vaadin` | `jCustos-vaadin` | Vaadin Flow adapter — view and navigation security; ships the Phase-8 `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SessionManagementView` building blocks |
| `jCustos-rest` | `jCustos-rest` | Framework-light REST adapter — request and handler security; ships the Phase-4c `RestJCustosVersionFilter` and the Phase-8d `OpenApiJCustosMetadataGenerator` |
| `jCustos-standalone` | `jCustos-standalone` | Plain-Java / desktop / CLI adapter — ThreadLocal subject + dynamic-proxy method-level enforcement |
| `jCustos-test` | `jCustos-test` | Reusable test fixtures: `FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5 `JCustosTestExtension`. Pull in as `<scope>test</scope>` |
| `jCustos-processor` | `jCustos-processor` | Compile-time annotation processor: generates `<Type>Secured` subclasses for `@Secured`-annotated concrete classes. Wire as `<annotationProcessorPath>`, not as a regular dependency |
| `jCustos-persistence-testkit` | `jCustos-persistence-testkit` | Contract test suites for every persistence-store SPI in `jCustos-core` — `@Test default`-method interfaces a custom store adapter implements to be vetted against the library's persistence contract. Persistence-tech-agnostic |
| `jCustos-persistence-eclipsestore` | `jCustos-persistence-eclipsestore` | Eclipse-Store (`org.eclipse.store:storage-embedded`) reference impl of every persistence-store SPI; passes the same 95+ contract suite as the in-memory defaults. Drop-in for apps that want durable persistence |
| `jCustos-crypto-bc` | `jCustos-crypto-bc` | V00.71 optional opt-in module: Argon2id, bcrypt and scrypt password hash providers via BouncyCastle (`bcprov-jdk18on:1.78.1`). `BouncyCastleHashingServices.modern()` wires the modern profile. The core stays JDK-only when this module is absent |
| `jCustos-credentials-hibp` | `jCustos-credentials-hibp` | V00.71 optional opt-in module: HaveIBeenPwned k-anonymity compromised-password checker. Uses JDK `HttpClient` only — no extra runtime dependencies. Plaintext never leaves the JVM (only the SHA-1 first-5-hex prefix is transmitted) |
| `demo-rest-shared` | `demo-rest-shared` | Transport-level constants + tiny JSON helper, shared between the REST server and any client |
| `demo-vaadin` | `demo-vaadin` | Standalone Vaadin demo (WAR) — auth runs in-JVM |
| `demo-rest` | `demo-rest` | Runnable REST reference: JDK-only HTTP server + CLI client |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin demo where `demo-rest` is the authoritative backend; UI talks to it through one encapsulated Java client |
| `demo-standalone` | `demo-standalone` | Interactive CLI demo (library + member directory) showing both `SecuredProxy.wrap(...)` (dynamic-proxy) **and** the annotation-processor-generated `<Type>Secured` wrapper |

### Dependency Rules

```text
jCustos-core                       -> (no project deps)
jCustos-vaadin                     -> jCustos-core
jCustos-rest                       -> jCustos-core
jCustos-standalone                 -> jCustos-core
jCustos-test                       -> jCustos-core (compile; the test extension implements JUnit lifecycle types)
jCustos-processor                  -> jCustos-core, com.svenruppert:proxybuilder:00.11.00, com.svenruppert:proxybuilder-annotations:00.11.00
jCustos-persistence-testkit        -> jCustos-core (compile; suites use ServiceLoader-free wiring)
jCustos-persistence-eclipsestore   -> jCustos-core, org.eclipse.store:storage-embedded:4.1.0
                                       (test scope: jCustos-persistence-testkit)
jCustos-crypto-bc                  -> jCustos-core, org.bouncycastle:bcprov-jdk18on:1.78.1
                                       (V00.71 optional opt-in)
jCustos-credentials-hibp           -> jCustos-core (JDK HttpClient only;
                                       V00.71 optional opt-in)
demo-rest-shared                    -> (no project deps; transport-only)
demo-vaadin                         -> jCustos-core, jCustos-vaadin
demo-rest                           -> jCustos-core, jCustos-rest, demo-rest-shared
demo-vaadin-rest-client             -> jCustos-core, jCustos-vaadin, demo-rest-shared
                                       (test scope only: demo-rest)
demo-standalone                     -> jCustos-core, jCustos-standalone
                                       (annotationProcessorPath: jCustos-processor)
```

`jCustos-core` has no Vaadin, Servlet, or REST-framework dependencies.
The four adapter modules (`jCustos-vaadin`, `jCustos-rest`,
`jCustos-standalone`, `jCustos-processor`) never depend on each other.
`jCustos-persistence-eclipsestore` is the only module with a third-party
storage dependency. `jCustos-crypto-bc` is the only module that pulls in
BouncyCastle — it stays opt-in so the core remains JDK-only.

## Claude Code Skills

The repository ships **ten battle-tested Claude Code skills** under
[`docs/skills/claude/`](docs/skills/claude/) that automate the
integration of jCustos into a fresh application. Each skill is a
SKILL.md (with frontmatter description Claude Code uses for
auto-discovery) plus a `references/` directory of `.java.tmpl`
templates that get rendered with project-specific slots.

Every skill listed below was validated against the reactor itself —
the matching `demo-jcustos-*` module in this repository is the
verbatim output of running the skill, and all ten modules compile in
the standard reactor build.

### The skill matrix

The skills are organised as **three adapters** (Vaadin, REST,
Standalone/CLI) **× three layers** (basic → persistence → hardening),
plus one **hybrid** that turns a Vaadin frontend into a REST-backend
client:

|                    | **Vaadin Flow**                                                          | **REST (JDK HttpServer)**                                            | **Standalone (CLI/desktop)**                                                  |
| ------------------ | ------------------------------------------------------------------------ | -------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| **Layer 1 — basic**       | [`jcustos-vaadin`](docs/skills/claude/jcustos-vaadin/SKILL.md)                       | [`jcustos-rest`](docs/skills/claude/jcustos-rest/SKILL.md)                       | [`jcustos-standalone`](docs/skills/claude/jcustos-standalone/SKILL.md)                       |
| **Layer 2 — persistence** | [`jcustos-vaadin-persistence`](docs/skills/claude/jcustos-vaadin-persistence/SKILL.md) | [`jcustos-rest-persistence`](docs/skills/claude/jcustos-rest-persistence/SKILL.md) | [`jcustos-standalone-persistence`](docs/skills/claude/jcustos-standalone-persistence/SKILL.md) |
| **Layer 3 — hardening**   | [`jcustos-vaadin-hardening`](docs/skills/claude/jcustos-vaadin-hardening/SKILL.md)   | [`jcustos-rest-hardening`](docs/skills/claude/jcustos-rest-hardening/SKILL.md)   | [`jcustos-standalone-hardening`](docs/skills/claude/jcustos-standalone-hardening/SKILL.md)   |
| **Hybrid**                | [`jcustos-vaadin-rest-client`](docs/skills/claude/jcustos-vaadin-rest-client/SKILL.md) — Vaadin frontend delegates auth to a `jcustos-rest` backend |||

Each cell points at the canonical `SKILL.md`; the `references/`
sibling holds the templates Claude Code renders into the consumer's
codebase.

### One sentence per skill

- **`jcustos-vaadin`** — `VaadinSecurity.bootstrap()` + `@JCustosAutoService` Authn/Authz + pre-seeded `admin/admin` & `user/user` + `LoginView` + AppLayout `MainLayout` hosting a public `PublicHomeView` and a `@VisibleFor(USER)` `DashboardView` + filterable audit grid + session inventory + role admin. **Also exports** the project-local `BootstrapExtension` SPI plus the `BootstrapBuilder` helper that loads every registered extension via `ServiceLoader` — the seam through which layer 2 and layer 3 plug in additively.
- **`jcustos-vaadin-persistence`** — Eclipse-Store-backed audit + session + bootstrap stores, plus the V00.70 token-based first-admin flow (`SetupView` → `InitialAdminBootstrapService`); the plaintext `admin/admin` seed is replaced. **Plugs in** as a `PersistenceBootstrapExtension` (`order=10`) — no overwrite of the layer-1 entry-point listener.
- **`jcustos-vaadin-hardening`** — `BouncyCastleHashingServices.modern()` (Argon2id) replaces PBKDF2, optional HIBP password-leak check, and Phase-4c drift detection (`JCustosVersionEnforcerListener` + `VersionBumper.bump(user)` after every role mutation) — a revoked role reroutes the affected user to login on their next click. **Plugs in** as a `HardeningBootstrapExtension` (`order=20`); composes additively with persistence.
- **`jcustos-rest`** — `RestSecurity.bootstrap()` + Bearer-token `TokenStore` + JDK-`HttpServer`-based Router with `POST /api/auth/login` + `whoami` + audit + sessions + users endpoints, gated by `@RequiresPermission` semantics. Same `BootstrapExtension` SPI surface as the Vaadin variant.
- **`jcustos-rest-persistence`** — same Eclipse-Store swap as the Vaadin variant, with `POST /api/setup` replacing the Vaadin `SetupView` and a 503 bootstrap-required guard on every other endpoint until the first admin is provisioned. Bootstrap-chain contributions flow through `PersistenceBootstrapExtension`.
- **`jcustos-rest-hardening`** — Argon2id + drift detection wired through `RestJCustosVersionFilter`; revoking a role makes every open Bearer token for that user start returning 401 on the next request. Bootstrap-chain contributions flow through `HardeningBootstrapExtension`.
- **`jcustos-standalone`** — `StandaloneSecurity.bootstrap()` + `StandaloneLoginFlow` + `SecuredProxy.wrap(DocumentService.class, impl)` for runtime enforcement on an interface, interactive CLI with `list / create / delete / audit / whoami / quit`. Same `BootstrapExtension` SPI surface.
- **`jcustos-standalone-persistence`** — Eclipse-Store persistence + a CLI `setup` prompt that reads the bootstrap token + creates the first admin before the regular login loop unlocks. `PersistenceBootstrapExtension`.
- **`jcustos-standalone-hardening`** — Argon2id, HIBP, and drift wiring for the CLI; drift detection is best-effort because CLI lifetimes are short, but the API surface stays uniform across all three adapters. `HardeningBootstrapExtension`.
- **`jcustos-vaadin-rest-client`** — small hybrid skill that patches a `jcustos-vaadin` consumer so its `AuthenticationService` POSTs to `/api/auth/login` and its `AuthorizationService` reads roles from `/api/whoami` on a `jcustos-rest` backend — server holds the truth, the Vaadin app keeps only the UI shell.

### Side-by-side reference output

The skills are not just documentation — every skill has a
corresponding `demo-jcustos-*` module in the reactor that contains
the verbatim, compilable result of running the skill on a fresh
module:

```bash
./mvnw -pl :demo-jcustos-vaadin,                  \
           :demo-jcustos-vaadin-persistence,      \
           :demo-jcustos-vaadin-hardening,        \
           :demo-jcustos-rest,                    \
           :demo-jcustos-rest-persistence,        \
           :demo-jcustos-rest-hardening,          \
           :demo-jcustos-standalone,              \
           :demo-jcustos-standalone-persistence,  \
           :demo-jcustos-standalone-hardening,    \
           :demo-jcustos-vaadin-rest-client       \
       -am compile -DskipTests
```

Every directory matches one cell of the matrix above. The skills
double as a regression test: a future API rename in `jCustos-core`
or `jCustos-dx-*` that breaks a skill template breaks the
corresponding demo module in the next reactor build.

### How composition works

Layer 1 ships a project-local SPI (`BootstrapExtension`) plus a
helper (`BootstrapBuilder`) that the entry-point listener
(`JCustosBootstrapInitListener` / `RestServer.start()` /
`Main.main()`) delegates to:

```java
// Layer 1: BootstrapExtension.java — project-local SPI
public interface BootstrapExtension {
  default void contributeAudit(AuditBootstrap a) {}
  default void contributeSessions(SessionBootstrap s) {}
  default void contributeCredentials(CredentialBootstrap c) {}
  default int order() { return 0; }
}

// Layer 1: entry-point listener — never re-rendered by later layers
JCustosRuntime runtime = BootstrapBuilder.apply(
    VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
).install();
```

`BootstrapBuilder.apply(...)` loads every registered
`BootstrapExtension` via `ServiceLoader`, sorts by `order()`, and
invokes the three `contribute*` hooks **inside a single**
`.audit(...) / .sessions(...) / .credentials(...)` call on the
fluent chain. Layer 2 and layer 3 each ship one extension class plus
a one-line entry in `META-INF/services/<base>.security.bootstrap.BootstrapExtension`
— neither rewrites the entry-point listener:

```java
// Layer 2: PersistenceBootstrapExtension (order=10)
public final class PersistenceBootstrapExtension implements BootstrapExtension {
  static {                                                  // eager open
    STORAGE = JCustosStorageProvider.storage();
    BootstrapWiring.instance();                             // print token
  }
  @Override public void contributeAudit(AuditBootstrap a) {
    a.storeBacked(STORAGE.auditEventStore()).logging();
  }
  @Override public void contributeSessions(SessionBootstrap s) {
    s.storeBacked(STORAGE.sessionStore());
  }
  @Override public int order() { return 10; }
}

// Layer 3: HardeningBootstrapExtension (order=20)
public final class HardeningBootstrapExtension implements BootstrapExtension {
  @Override public void contributeCredentials(CredentialBootstrap c) {
    c.hashing(BouncyCastleHashingServices.modern());
  }
  @Override public void contributeSessions(SessionBootstrap s) {
    JCustosServiceResolver.findJCustosVersionStore().ifPresent(s::securityVersion);
    JCustosServiceResolver.findSubjectIdResolver().ifPresent(s::subjectIdResolver);
  }
  @Override public int order() { return 20; }
}
```

The same `.sessions(...)` sub-builder is configured twice within one
`.sessions(...)` call (`storeBacked(...)` by persistence,
`securityVersion(...)` + `subjectIdResolver(...)` by hardening) — both
contributions land on the same sub-builder and stack. This is what
makes the order persistence-vs-hardening irrelevant.

Adding a future layer (a hypothetical
`jcustos-vaadin-mfa`, a project-local `RateLimitBootstrapExtension`,
…) means shipping a new `BootstrapExtension` implementation + one
service-file line. No existing skill changes; no entry-point listener
rewrite.

### Using a skill

To consume a skill in your own project:

1. Copy the skill directory from
   `docs/skills/claude/<skill-name>/` into Claude Code's skill
   location: `~/.claude/skills/<skill-name>/`. Claude Code
   auto-discovers any directory at this path containing a `SKILL.md`
   with proper frontmatter.
2. From within Claude Code, invoke the skill — either via the
   `/<skill-name>` slash command or by describing your intent
   ("integrate jCustos into my Vaadin app", "secure my REST API
   with admin/user", "add token-based bootstrap to my REST module").
   Claude Code's auto-discovery matches the description against the
   SKILL.md frontmatter and triggers the skill.
3. Claude Code reads the `SKILL.md`, asks for the slots that are
   missing from your brief (typically: target Maven module, base
   package, subject type name), renders every `.java.tmpl` /
   `services-*.tmpl` / `pom-snippet.xml.tmpl` from `references/`
   with those slots substituted, and writes the rendered files into
   your project tree at the paths the SKILL.md specifies.
4. Run `./mvnw -pl <your-module> -am compile` to verify — the same
   command the reactor runs to validate the matching
   `demo-jcustos-*` module.

### Suggested application order

```
Day 1: jcustos-<adapter>                  → working login + roles + admin UI
Day X: jcustos-<adapter>-persistence      → users / audit / sessions survive restart
Day Y: jcustos-<adapter>-hardening        → Argon2id + drift detection + HIBP

For Vaadin+REST hybrids:
  Backend: jcustos-rest [+ -persistence + -hardening]
  Frontend: jcustos-vaadin + jcustos-vaadin-rest-client
```

Layer 1 is the only hard prerequisite — it ships the
`BootstrapExtension` SPI plus the `BootstrapBuilder` helper that the
later layers plug into. Once layer 1 is in place, layer 2 and layer
3 can be applied in **either** order, **only one** of them, or
**both** — the bootstrap chain composes them additively (see
"How composition works" above). No "merge manually" caveat, no
second-writer-wins on the listener file.

| What you need | Skills to run |
|---|---|
| In-memory demo for first 5 minutes | layer 1 only |
| Production-grade auth, in-memory user store | layer 1 + layer 3 |
| Persistent users, PBKDF2 still acceptable | layer 1 + layer 2 |
| Full production setup | layer 1 + layer 2 + layer 3 (any order) |

### What the skills deliberately do NOT cover

- **OpenAPI metadata, CORS, refresh tokens, API keys, rate
  limiting** — V00.72+ features available via the
  `jCustos-dx-rest.openApiMetadata(...)` / `.cors(...)` surface
  but not templated.
- **Custom `JCustosSubject` mappers** — beyond the defaults, mapping
  lives in `JCustosSubjectMapper` and stays project-specific.
- **Multi-tenant policies** — the skills are single-tenant; multi-tenant
  variants are roadmap V00.74+.
- **Multi-factor authentication** — separate concern.
- **Refresh-token rotation in the hybrid** — the Vaadin client stores
  the Bearer token in `VaadinSession`; rotation belongs in the REST
  backend or a follow-up skill.

## Quick Start

### Build

```bash
# Full build (Maven 4 via the wrapper, Java 26+)
./mvnw clean install
```

The project is pinned to Maven 4 (`minimum-maven.version=4.0.0-rc-5`)
through `./mvnw`; the wrapper downloads the right distribution on first
use. `install` (rather than `package`) is required at least once
because the demos depend on each other through the local `~/.m2`
repository (see § *Module Structure* — `demo-vaadin-rest-client`
depends on `demo-rest` for tests, and `demo-rest-shared` is consumed
by both REST-side modules).

### Pick the right demo

| You want to see … | Run |
|---|---|
| Vaadin role/permission UI in a single JVM, no backend | [`demo-vaadin`](docs/v00.50.00/demo-vaadin.md) |
| Pure REST security (HTTP server + interactive CLI), no UI | [`demo-rest`](docs/v00.50.00/demo-rest.md) |
| Vaadin UI talking to a separate REST backend (real two-tier setup) | [`demo-vaadin-rest-client`](docs/v00.50.00/demo-vaadin-rest-client.md) |
| Plain-Java / CLI / desktop integration (no HTTP, no Vaadin) | `mvn -pl demo-standalone exec:java -Dexec.mainClass=eu.jsentinel.jcustos.demo.standalone.DemoApp` |

### `demo-vaadin` — Standalone Vaadin demo

```bash
cd demo-vaadin && mvn jetty:run
# Browser: http://localhost:8080/
```

First run shows the bootstrap setup (the demo prints a token to the
console). After setup, log in as the chosen admin. Demo users
`user/user` and `demo/demo` are pre-populated; `admin` is created via
the bootstrap flow. Walkthrough: [`docs/demo-vaadin.md`](docs/v00.50.00/demo-vaadin.md).

### `demo-rest` — REST server + CLI

```bash
# Terminal 1 — JDK-only HTTP server on http://localhost:8080
mvn -pl :demo-rest exec:java
# Prints a bootstrap token to the console (TRANSIENT_CONSOLE mode).

# Terminal 2 — interactive CLI
mvn -pl :demo-rest exec:java \
    -Dexec.mainClass=eu.jsentinel.jcustos.demo.rest.cli.DemoRestCli
# Use `init-admin` to create the first admin via the bootstrap token.
# Then `login admin <new-password>` and play with `operations` / `call …`.
```

Demo users: `editor/editor`, `viewer/viewer`. `admin` is created via
the bootstrap flow; with `-Dsecurity.bootstrap.mode=DISABLED` the
default `admin/admin` is pre-populated instead. Walkthrough:
[`docs/demo-rest.md`](docs/v00.50.00/demo-rest.md).

### `demo-vaadin-rest-client` — Vaadin UI + REST backend

```bash
# Terminal 1 — backend (same as the REST demo above)
mvn -pl :demo-rest exec:java
# Prints a bootstrap token to the console.

# Terminal 2 — Vaadin UI
mvn -pl :demo-vaadin-rest-client jetty:run
# Browser: http://localhost:9090/
```

Browser opens `/setup` (because the backend has no admin yet). Paste
the token from the backend console, choose a username and password,
submit — the **Vaadin UI calls** `POST /api/bootstrap/admin` against
the backend, no in-JVM auth. Then log in. The UI never speaks HTTP
directly: only the encapsulated `DemoBackendClient` does.
Walkthrough: [`docs/demo-vaadin-rest-client.md`](docs/v00.50.00/demo-vaadin-rest-client.md).

### `demo-standalone` — Interactive CLI

```bash
mvn -pl demo-standalone exec:java \
    -Dexec.mainClass=eu.jsentinel.jcustos.demo.standalone.DemoApp
```

Demo users are seeded: `admin/admin`, `librarian/librarian`,
`alice/alice`. The CLI exposes **both** enforcement paths side by
side:

- **Runtime / dynamic-proxy** — book commands (`list`, `borrow`,
  `return`, `add`, `remove`) run through
  `SecuredProxy.wrap(LibraryService.class, …)`. `LibraryService` is
  an interface; the JDK proxy calls into `JCustosEnforcer` on every
  invocation.
- **Compile-time / annotation processor** — member commands
  (`members`, `invite`, `remove-member`, `reset-members`) operate on
  `MemberDirectory`, a concrete class annotated with `@Secured`. The
  `jCustos-processor` annotation processor generates
  `MemberDirectorySecured` at compile time; each guarded method
  inserts a `JCustosEnforcer.require…(…)` call ahead of
  `super.<method>(…)`.

Both paths share the same `JCustosEnforcer`, so the rules are
identical. Rejections surface as `DENIED — …` lines in the terminal.

### Tests

```bash
# Whole reactor — over 1600 tests across all modules
./mvnw test

# Single module
./mvnw -pl :jCustos-core -am test
./mvnw -pl :demo-rest -am test
./mvnw -pl :demo-vaadin-rest-client -am test
```

Library test totals as of V00.70.00:
`jCustos-core` 956, `jCustos-vaadin` 172, `jCustos-rest` 71,
`jCustos-standalone` 30, `jCustos-test` 44, `jCustos-processor` 11,
`jCustos-persistence-testkit` 104, `jCustos-persistence-eclipsestore`
104 — all green. Demo tests: `demo-vaadin` 103, `demo-rest` 48,
`demo-vaadin-rest-client` 13, `demo-standalone` 34.

### Mutation coverage

```bash
./mvnw -pl :jCustos-core org.pitest:pitest-maven:mutationCoverage
```

The parent POM pins `pitest-test-classes=com.svenruppert.*`. Reports
land under `<module>/target/pit-reports/index.html`. Current state per
library module (V00.70.00):

| Module | Coverage | Tests |
|---|---:|---:|
| `jCustos-core` | **86 %** (1191/1381) | 956 |
| `jCustos-vaadin` | **79 %** (242/305) | 172 |
| `jCustos-rest` | **95 %** (86/91) | 71 |
| `jCustos-standalone` | **97 %** (33/34) | 30 |
| `jCustos-processor` | **82 %** (23/28) | 11 |
| `jCustos-persistence-eclipsestore` | **70 %** (231/328) | 104 |
| `jCustos-test` | n/a (test fixtures) | 44 |
| `jCustos-persistence-testkit` | n/a (contracts verified through consumers) | 104 |

For the per-module progression across `00.51.00 → 00.60.00 → 00.70.00`
see the *Mutation coverage* section of each
[release-notes file](RELEASE-NOTES-00.70.00.md).

### Add the dependency

For a Vaadin Flow application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>jCustos-vaadin</artifactId>
  <version>00.70.00</version>
</dependency>
```

For a REST handler / servlet application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>jCustos-rest</artifactId>
  <version>00.70.00</version>
</dependency>
```

For a plain-Java / desktop / CLI application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>jCustos-standalone</artifactId>
  <version>00.70.00</version>
</dependency>
```

`jCustos-core` is pulled in transitively by any of the three adapters.

## Vaadin Integration

To secure a Vaadin Flow application, implement the following SPI contracts and
register them via `META-INF/services/` files. Reference: `demo-vaadin`.

### 1. Define a user type

```java
public record MyUser(String username, Set<String> roles) {}
```

### 2. Implement `AuthenticationService<T, U>`

Validates credentials and loads the user subject.

```java
public class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser> {

  @Override
  public boolean checkCredentials(Credentials credentials) { /* ... */ }

  @Override
  public MyUser loadSubject(Credentials credentials) { /* ... */ }

  @Override
  public Class<MyUser> subjectType() { return MyUser.class; }
}
```

Register in `META-INF/services/eu.jsentinel.jcustos.authentication.AuthenticationService`:
```
com.example.MyAuthenticationService
```

### 3. Implement `AuthorizationService<U>`

Maps a user to roles. Only `rolesFor()` is required — `permissionsFor()` has a
default implementation returning empty permissions.

```java
public class MyAuthorizationService implements AuthorizationService<MyUser> {
  @Override
  public HasRoles rolesFor(MyUser subject) { /* ... */ }
}
```

Register in `META-INF/services/eu.jsentinel.jcustos.authorization.api.AuthorizationService`.

### 4. Define a restriction annotation with `@JCustosAnnotation`

```java
@Retention(RUNTIME)
@JCustosAnnotation(MyRoleAccessEvaluator.class)
public @interface VisibleFor {
  MyRole[] value();
}
```

Or use the generic annotations from `jCustos-core`:

```java
@RequiresRole("ROLE_ADMIN")
@RequiresPermission("demo:edit")
```

### 5. Implement `AccessEvaluator`

```java
public class MyRoleAccessEvaluator
    implements AccessEvaluator<VisibleFor> {

  @Override
  public AccessDecision evaluate(AccessContext context, VisibleFor annotation) {
    // return AccessDecision.granted() or AccessDecision.denied("login", false)
  }
}
```

Or extend `RoleBasedAccessEvaluator`:

```java
public class MyRoleAccessEvaluator
    extends RoleBasedAccessEvaluator<VisibleFor, MyUser> {

  @Override
  public Set<RoleName> requiredRoles(VisibleFor annotation) { /* ... */ }

  @Override
  public String alternativeNavigationTarget(
      AccessContext context, VisibleFor annotation) { /* ... */ }
}
```

Register in `META-INF/services/eu.jsentinel.jcustos.authorization.api.AccessEvaluator`.

### 6. Extend `LoginListener<U>`

```java
public class MyLoginListener extends LoginListener<MyUser> {
  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }
  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }
}
```

Register in `META-INF/services/eu.jsentinel.jcustos.authorization.LoginListener`.

### 7. Extend `LoginView`

Create your login UI by extending the abstract `LoginView` base class.

### 8. Annotate route views

```java
@Route("admin")
@VisibleFor(MyRole.ADMIN)
public class AdminView extends Div { /* ... */ }
```

## REST Integration

To secure REST handlers, implement `RestSubjectResolver`, annotate handlers with
generic permission annotations, and run them through `RestAuthorizationFilter`.

A complete runnable reference lives in `demo-rest`: a JDK-only HTTP server
(`com.sun.net.httpserver.HttpServer`) and an interactive CLI
(`java.net.http.HttpClient`) demonstrating login, server-side operation
filtering, and the `200 / 401 / 403` decision flow. See
[`docs/demo-rest.md`](docs/v00.50.00/demo-rest.md) for run instructions and example
sessions.

### 1. Define project permissions and role mapping

```java
public enum DemoPermission {
  DOCUMENT_READ("document:read"),
  DOCUMENT_DELETE("document:delete");

  private final PermissionName permissionName;
  // ...
}
```

```java
public final class DemoRolePermissionMapping implements RolePermissionMapping {
  @Override
  public Set<PermissionName> permissionsFor(RoleName role) { /* ... */ }
}
```

### 2. Implement `RestSubjectResolver`

```java
public final class MyRestSubjectResolver implements RestSubjectResolver {

  private static final BearerTokenExtractor BEARER = new BearerTokenExtractor();

  @Override
  public Optional<JCustosSubject> resolveSubject(RestRequest request) {
    return BEARER.extract(request)        // case-insensitive Bearer parser
        .flatMap(myTokenStore::resolve)
        .map(this::toSubject);
  }
}
```

The library does not enforce a token strategy. `BearerTokenExtractor` and
`RestHeaders` (case-insensitive header lookup) live in `jCustos-rest` —
no need to roll your own.

### 3. Annotate handlers

```java
public final class DocumentHandlers {
  @RequiresPermission("document:read")
  public void read(RestRequest request, RestResponse response) { /* ... */ }

  @RequiresPermission("document:delete")
  public void delete(RestRequest request, RestResponse response) { /* ... */ }

  @RequiresPermission("document:create")
  public void create(RestRequest request, RestResponse response) {
    // Pattern-match instead of casting to a concrete adapter request type
    if (request instanceof BodyRestRequest body) {
      String json = body.bodyAsUtf8();
      // ...
    }
  }
}
```

Use `BodyRestRequest` (in `jCustos-rest`) when a handler needs the request
body. Adapters supply the raw bytes; helpers decode UTF-8.

### 4. Wire the filter

```java
RestAuthorizationFilter filter =
    new RestAuthorizationFilter(new MyRestSubjectResolver());

filter.authorizeAndHandle(
    request, response, handlers::delete, handlerMethod);
```

The filter:

1. Resolves the subject from the request.
2. Scans the handler method/class for a security annotation.
3. Builds an `AccessContext` with `resourceType="rest-endpoint"`.
4. Runs the matching `AuthorizationEvaluator`.
5. Maps the decision: `Granted` runs the handler; `Unauthenticated` → `401`;
   `Forbidden` → `403`. Error bodies are short and generic — no internals leak.

### 5. Authenticated-only endpoints

For endpoints that need any authenticated subject but no specific permission
(`/me`, `/logout`, …), use `RestAuthenticationFilter` instead of writing
your own subject check:

```java
RestAuthenticationFilter authFilter = new RestAuthenticationFilter(resolver);
authFilter.requireAuthenticated(request, response, handlers::me);
// 401 with body "Unauthorized" if no subject; delegates otherwise
```

### 6. (Optional) Operation discovery filtered server-side

`demo-rest` shows a `GET /api/operations` endpoint that returns only the
operations the current subject is allowed to invoke. Built on
`SecuredOperationRegistry` + `OperationVisibilityService` from
`jCustos-core` — the same permission model that protects the handlers is
used to filter the discovery list. Clients never make local authorization
decisions.

## Standalone Integration

To secure plain-Java code — desktop, CLI, daemon — pick whichever of
the two paths fits your service shape and drive the login lifecycle
with `StandaloneLoginFlow`. There is no listener, no filter chain, no
navigation phase; both paths land in the same `JCustosEnforcer` as
the Vaadin and REST adapters.

- **Interface available** → wrap once with
  `SecuredProxy.wrap(MyService.class, impl)` (runtime / JDK proxy).
- **Concrete class, no interface** → annotate with `@Secured`, add
  `jCustos-processor` to the `<annotationProcessorPaths>`, and
  instantiate the generated `<Type>Secured` subclass (compile-time).

A complete runnable reference lives in `demo-standalone`: an
interactive library-borrowing CLI with three seeded users that
exercises **both** paths — `LibraryService` (interface) via
`SecuredProxy`, `MemberDirectory` (concrete class) via the
processor-generated `MemberDirectorySecured`.

### 1. Define the service interface

```java
public interface LibraryService {
  @RequiresPermission("book:list")
  List<String> listBooks();

  @RequiresPermission("book:borrow")
  void borrowBook(String title);

  @RequiresRole("ADMIN")
  void removeBook(String title);
}
```

### 2. Wrap the implementation

```java
LibraryService secured =
    SecuredProxy.wrap(LibraryService.class, new InMemoryLibraryService());

secured.listBooks();             // runs if the bound subject has book:list
secured.removeBook("x");         // throws AccessDeniedException for non-ADMIN
```

`SecuredProxy.wrap(...)` returns a JDK dynamic-proxy implementing the
interface. Every call scans the method (then the declaring class) for a
`@JCustosAnnotation`-meta-annotated annotation, runs the matching
evaluator, and either delegates to the real implementation or throws
`AccessDeniedException`. `Object` methods bypass enforcement.

For callbacks / lambdas where wrapping an interface is awkward, call
the single-shot helper:

```java
SecuredProxy.requireAllowed(MyOps.class, "delete");
// throws AccessDeniedException if the calling subject is not allowed
```

#### Compile-time path (concrete class)

For concrete classes (no interface) the annotation processor in
`jCustos-processor` generates a sealed `<Type>Secured` subclass at
build time:

```java
@Secured
public class MemberDirectory {
    @RequiresPermission("member:list")
    public List<String> listMembers() { /* … */ }

    @RequiresAnyPermission({"member:add", "member:invite"})
    public void addMember(String name, String email) { /* … */ }
}

// Compile produces MemberDirectorySecured automatically.
MemberDirectory members = new MemberDirectorySecured();
members.listMembers();           // JCustosEnforcer.requirePermission("member:list") first
```

Wire the processor as an `<annotationProcessorPath>` in the consuming
module's `maven-compiler-plugin` configuration — never as a regular
compile dependency. The generated class extends the original (so the
original must not be `final`).

### 3. Drive the login flow

```java
StandaloneLoginFlow<Credentials, User> flow = new StandaloneLoginFlow<>();
LoginResult<User> result = flow.login(new Credentials("alice", "alice"), "alice");

switch (result) {
  case LoginResult.Success<User> s   -> /* proceed */;
  case LoginResult.Rejected<User> r  -> /* wrong credentials */;
  case LoginResult.LockedOut<User> l -> /* throttled — retry in l.decision().remaining() */;
}
```

The flow consults `LoginAttemptPolicy.beforeAttempt(...)` first, then
calls the SPI-registered `AuthenticationService.checkCredentials` /
`loadSubject`, binds the subject through the active `SubjectStore`,
records success/failure on the policy, and publishes `LoginSucceeded` /
`LoginFailed` to the `JCustosAuditService`. `flow.logout()` clears the
SubjectStore for the current thread.

### 4. SubjectStore — ThreadLocal by default

`jCustos-standalone` registers `ThreadLocalSubjectStore` as the SPI
`SubjectStore`. It is **not** inherited across threads — a value bound
on the main thread is invisible to a background `Executor`. Propagating
the subject to worker threads is the application's responsibility:
capture the user before submitting work, then call
`SubjectStores.subjectStore().setCurrentSubject(user, User.class)` on
the worker thread (or use a `Runnable` wrapper that does that).

## Decision Model

The library uses sealed decision hierarchies that adapters dispatch
on via `switch`:

| Type | Module | Variants |
|---|---|---|
| `AuthorizationDecision` | `jCustos-core` | `Granted` / `Unauthenticated(reason)` / `Forbidden(reason)` / `StepUpRequired(reason, method)` |
| `AccessDecision` | `jCustos-core` | Vaadin-oriented (legacy): `Granted` / `Reroute(target, asForward)` / `RerouteToError(type, message)` / `RerouteWithParameter(s)` |
| `JCustosVersionStatus` | `jCustos-core/session` | `Current(at)` / `Drifted(snapshot, current)` — Phase 4c drift verdict |
| `JCustosVersionEnforcer.EnforcementOutcome` | `jCustos-core/session` | `Continue` / `SessionStale(status)` — adapter-neutral request verdict for drift |
| `RateLimitDecision` | `jCustos-core/ratelimiting` | `Allowed(eventsInWindow, limit, window)` / `Throttled(eventsInWindow, limit, window, retryAfter)` |
| `LoginAttemptDecision`, `SessionDecision`, `SessionPolicyDecision`, `NavigationAccessDecision`, `LoginResult<U>`, `InitialAdminCreationResult` | various | further sealed verdicts for login throttling, session lifetime, navigation, standalone login, bootstrap |

Adapters map these to framework-specific behavior:

- `jCustos-vaadin` → navigation: continue, reroute to login, reroute
  to step-up, or reroute to error. `JCustosVersionEnforcerListener`
  reroutes drifted sessions to the configured login view.
- `jCustos-rest` → HTTP status: `200`/handler, `401`, `403`, or
  `401 + WWW-Authenticate: StepUp` / `SessionStale` (RFC 7235).

## Annotation-Driven Protection

`JCustosAnnotationScanner` scans classes, methods, or any `AnnotatedElement`
for restriction annotations meta-annotated with `@JCustosAnnotation`. Both
adapters use the same scanner.

Generic annotations (in `jCustos-core`):

- `@RequiresRole({"ROLE_ADMIN"})` → `RequiresRoleEvaluator` (any-of semantics; honours `RoleHierarchy`)
- `@RequiresPermission({"document:delete"})` → `RequiresPermissionEvaluator` (all-of semantics)
- `@RequiresAllPermissions({"a", "b"})` → `RequiresAllPermissionsEvaluator` (explicit AND)
- `@RequiresAnyPermission({"a", "b"})` → `RequiresAnyPermissionEvaluator` (OR)
- `@RequiresPolicy("doc.owner-or-admin")` → `RequiresPolicyEvaluator`
- `@ProtectedBy(...)` → `ProtectedByEvaluator`
- `@Secured` (class-level, source-retention) → not an evaluator; **trigger for the compile-time annotation processor** in `jCustos-processor`

Project-specific annotations are encouraged for Vaadin views (e.g. `@VisibleFor`).

## Method Security — runtime vs. compile-time

For non-navigation enforcement (CLI services, REST handlers, plain-Java
classes) the framework offers two paths, both routed through the same
`JCustosEnforcer` in `jCustos-core`:

| Path | Target | Wiring | When to choose |
|---|---|---|---|
| Runtime / JDK Dynamic Proxy | Java **interface** | `SecuredProxy.wrap(MyService.class, impl)` (in `jCustos-standalone`) | The service has a clean interface; you're happy paying a per-call reflection check. Works for callbacks / lambdas via `SecuredProxy.requireAllowed(Class, methodName)`. |
| Compile-time / Annotation Processor | **Concrete class** annotated with `@Secured` | `<annotationProcessorPath>` for `jCustos-processor`; instantiate the generated `<Type>Secured` subclass | The class has no interface, or you want a stable stacktrace / no per-call reflection. Method-security annotations on `final`, `private` or `static` methods raise compile errors. Underlying generator: `com.svenruppert:proxybuilder:00.11.00` + `proxybuilder-annotations:00.11.00`. |

Both paths land in the same `JCustosEnforcer.require…(…)` helpers,
so a permission rule applies identically regardless of which path
expressed it. `demo-standalone` exercises both side by side
(`LibraryService` via `SecuredProxy.wrap`, `MemberDirectory` via
`MemberDirectorySecured`).

## Reusable security building blocks

### Core SPI + enforcement

| Type | Module / package | Purpose |
|---|---|---|
| `JCustosServiceResolver` | `jCustos-core/.../authorization/api` | Central SPI cache. Strict accessors throw `IllegalStateException`; `find…()` returns `Optional`; `set…(…)` is a programmatic test seam. Covers Authentication / Authorization / Audit / Action / LoginAttempt / Session / PasswordHasher / Logout / RoleHierarchy / ResourceResolver / JCustosVersionStore / SubjectIdResolver / Step-Up route. |
| `JCustosEnforcer` | `jCustos-core/.../authorization/api` | Central enforcement entry point. Generic `enforce(Method, Class)` for the runtime/dynamic-proxy path; explicit `requirePermission` / `requireAllPermissions` / `requireAnyPermission` / `requireRole` / `requireAnyRole` / `requirePolicy` for the compile-time/annotation-processor path. Throws `AccessDeniedException` on deny. |
| `SecuredProxy` | `jCustos-standalone` | `SecuredProxy.wrap(Interface, impl)` returns a JDK dynamic proxy that routes every call through `JCustosEnforcer.enforce(method, declaringClass)`. `requireAllowed(Class, methodName)` is the single-shot variant for callbacks / lambdas. |
| `SecuredAnnotationProcessor` | `jCustos-processor` | Compile-time annotation processor. For each `@Secured` concrete class it emits `<Type>Secured extends <Type>` and rewrites every annotated method as `JCustosEnforcer.require…(…)` + `super.<method>(…)`. Built on `com.svenruppert:proxybuilder:00.11.00` (+ `proxybuilder-annotations:00.11.00`). |
| `PermissionGuard` | `jCustos-core/.../authorization/api` | Stateless `hasPermission` / `requirePermission` (and role variants) on any `HasPermissions`/`HasRoles`. |
| `SubjectIdResolver<U>` | `jCustos-core/.../authorization/api` | Phase 4c-Followup. Maps a typed user to `SubjectId` (+ optional `TenantId`). Apps register to unlock Vaadin's automatic JCustosVersion-snapshot capture in `LoginView`. |

### Audit pipeline

| Type | Module / package | Purpose |
|---|---|---|
| `JCustosAuditService` + sealed `AuditEvent` (27 record variants) | `jCustos-core/.../audit` | Typed publish/query audit pipeline. Variants: `LoginSucceeded`, `LoginFailed`, `LogoutPerformed`, `AccessGranted`, `AccessDenied`, `ActionDenied`, `BruteForceLimitReached`, `SessionCreated`, `SessionExpired`, `SessionInvalidated`, `SessionStale`, `RoleAssigned`, `RoleRevoked`, `UserCreated`, `UserDeleted`, `BootstrapAdminCreated`, `BootstrapTokenRejected`, `PolicyEvaluated`, `StepUpChallenged`, `PasswordResetRequested`, `PasswordResetCompleted`, `EmailVerificationRequested`, `EmailVerified`, `ApiKeyUsed`, `ApiKeyDenied`, `TokenRotated`, `RateLimitExceeded`. |
| `AuditEventStore` + `InMemoryAuditEventStore` | `jCustos-core/.../audit` | Persistence SPI for audit events (Phase 2). Eclipse-Store impl available. |
| `RingBufferAuditSink`, `LoggingAuditSink`, `CompositeAuditService`, `DefaultCompositeAuditService` | `jCustos-core/.../audit` | Default sinks; the RingBuffer backs the Vaadin `/audit`-route and the REST `GET /api/audit` endpoint. |
| `StoreBackedJCustosAuditService` | `jCustos-core/.../audit` | `JCustosAuditService` over `AuditEventStore` (Phase 4b). Tenant-scoped, swallows store failures so audit cannot break the security flow. |

### Authentication, sessions, drift detection

| Type | Module / package | Purpose |
|---|---|---|
| `AuthenticationService<T,U>` | `jCustos-core/.../authentication` | SPI: credential validation + subject loading. |
| `PasswordHasher`, `PasswordHash`, `Pbkdf2PasswordHasher` | `jCustos-core/.../authentication` | Hash + verify + `needsRehash` (drift detection). 00.84.00 (JS-SEC-072): default 600 000 iterations, stored parameters validated before derivation. |
| `LoginAttemptPolicy` + `InMemoryLoginAttemptPolicy` + `StoreBackedLoginAttemptPolicy` | `jCustos-core/.../bruteforce` | Login throttling. `LoginAttemptDecision = Allowed \| LockedOut(Duration, int)`. Store-backed variant uses `LoginAttemptStore` (Phase 4b). |
| `ClientAddressResolver` + `DefaultClientAddressResolver` + `TrustedProxyClientAddressResolver` | `jCustos-core/.../net` | 00.84.00 (JS-SEC-061, CWE-348). Decides which address keys throttling and audit lines. Default: the connection peer, no header. `trustedProxies(...)` honours `X-Forwarded-For` from configured proxies only. Adapters `VaadinClientAddress`, `RestClientAddress`; DX `.clientAddress(...)`. See `docs/security/deployment/reverse-proxy.md`. |
| `SessionPolicy<U>` + `TimeoutSessionPolicy` | `jCustos-core/.../session` | Idle/absolute lifetime checks. |
| `SessionStore`, `SessionRecord`, `JCustosVersion`, `JCustosVersionKey`, `JCustosVersionStore` | `jCustos-core/.../session` | Persistent session records + monotonic per-subject security version (Phase 2 + 4a). `SessionStore.findAll()` lists every session for an admin view. |
| `JCustosVersionCheck`, sealed `JCustosVersionStatus`, `JCustosVersionEnforcer`, sealed `EnforcementOutcome` | `jCustos-core/.../session` | Phase 4c drift detection. Adapter-neutral check + enforcer; publishes `SessionStale` audit on drift. |
| `LogoutService`, `SubjectClearingLogoutService`, `SubjectSessionRegistry` + `StoreBackedSubjectSessionRegistry` | `jCustos-core/.../logout` | `logout(SubjectId, LogoutScope)` SPI with multi-session logout via store-backed registry. Vaadin-side: `VaadinLogoutService` rotates HTTP session. |
| `StandaloneLoginFlow`, `LoginResult` | `jCustos-standalone` | CLI/Desktop login driver — consults policy, calls `AuthenticationService`, binds subject, audits. |
| `RememberMeTokenStore` + `StoreBackedRememberMeService` | `jCustos-core/.../authentication` | Phase 2c + 4b. Hash-only persistent-login tokens, tenant-scoped issue/validate/revoke. |
| `ApiKeyStore`, `ApiKeyRecord`, `ApiKeyAuthenticationService` | `jCustos-core/.../authentication` | Phase 2d + 7b. Hash-only API keys with scopes; `ApiKeyAuthenticationService.authenticate` returns the active record or empty with a `ApiKeyDenied` audit reason. |
| `RefreshTokenStore`, `RefreshTokenRecord`, `TokenService` | `jCustos-core/.../authentication` | Phase 2d + 7b. Rotating refresh tokens with replay defense via `markReplaced`; access tokens are returned to the caller without server-side persistence. Emits `TokenRotated`. 00.84.00 (JS-SEC-071): rotation claims the old token atomically before issuing; a replayed token revokes its family and is audited. |

### Account lifecycle + notifications

| Type | Module / package | Purpose |
|---|---|---|
| `PasswordResetTokenStore`, `PasswordResetTokenRecord`, `PasswordResetService` | `jCustos-core/.../accountlifecycle` | Phase 2c + 7a. Single-use hash-only reset tokens; tenant-scoped `request` / `validate` / `consume`. |
| `EmailVerificationTokenStore`, `EmailVerificationTokenRecord`, `EmailVerificationService` | `jCustos-core/.../accountlifecycle` | Phase 2c + 7a. Same lifecycle as password reset, carries the verified email on the record. |
| `JCustosNotificationSender` + `LoggingNotificationSender`, `JCustosNotification` + `Kind` enum | `jCustos-core/.../accountlifecycle` | Phase 7a. Notification dispatcher — apps plug in mail / SMS / log transport. Default sender logs `NOTIFY type=…` lines. |
| `BootstrapStateStore` + `StoreBackedBootstrapStateService` | `jCustos-core/.../bootstrap` | Phase 2b + 4b. Tenant-scoped "is the system bootstrapped?" state with idempotent `markCompleted`. |

### Authorization model + role hierarchy

| Type | Module / package | Purpose |
|---|---|---|
| `RoleAssignmentStore`, `RoleAssignmentKey`, `StoreBackedRoleAuthorizationService<U>` | `jCustos-core/.../authorization/api/roles` | Phase 2b + 4b. Persistent role assignments + generic `AuthorizationService<U>` reading from the store. |
| `RoleHierarchy` + `StaticRoleHierarchy`, `NoopRoleHierarchy` | `jCustos-core/.../authorization/api/roles` | Role-inheritance SPI; honoured by `RequiresRoleEvaluator` and `RolePermissionResolver`. |
| `ActionAuthorizationService<U>`, `ActionPermission`, `StaticActionAuthorizationService` | `jCustos-core/.../action` | Stable SPI for `isAllowed`/`requireAllowed` action checks with `ACTION_DENIED` audit on denial. |
| `StaticRolePermissionMapping`, `RolePermissionResolver` | `…/api/permissions` | Immutable role → permissions map with a builder; hierarchy-aware permission merge. |
| `SecuredOperationDescriptor`, `SecuredOperationRegistry`, `OperationVisibilityService` | `…/api/operations` | Generic operation discovery with subject-aware filtering. |

### Rate limiting

| Type | Module / package | Purpose |
|---|---|---|
| `RateLimitStore`, `RateLimitKey` | `jCustos-core/.../ratelimiting` | Phase 2d. Event-based sliding-window persistence (records timestamps, the policy decides the window). |
| `RateLimitPolicy` + `InMemoryRateLimitPolicy`, sealed `RateLimitDecision` | `jCustos-core/.../ratelimiting` | Phase 7c. Pluggable per-scope rate-limit policy (separate from `LoginAttemptPolicy`). Sliding-window default; `Throttled` carries `retryAfter` for the HTTP header. |

### Vaadin adapter

| Type | Module / package | Purpose |
|---|---|---|
| `LoginView`, `LoginListener<U>`, `AuthorizationListener`, `SessionLifetimeListener`, `VaadinLogoutService` | `jCustos-vaadin` | Annotation-driven view protection + Vaadin session/lifecycle integration. `LoginView.captureJCustosVersionSnapshot()` automatically records the Phase-4c snapshot when `JCustosVersionStore` and `SubjectIdResolver` are wired. |
| `VaadinJCustosVersionContext`, `JCustosVersionEnforcerListener` | `jCustos-vaadin/session/vaadin` | Phase 4c. Per-VaadinSession snapshot carrier + `@ListenerPriority(Integer.MAX_VALUE)` BeforeEnterListener that reroutes drifted sessions to the configured login view. |
| `SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem`, `SecuredVisibility`, `SecuredVisibilityMode`, `SessionManagementView` | `jCustos-vaadin/components` | Phase 8a/8b. Permission-aware UI components (HIDE vs DISABLE on denial) and a reusable session-management Composite. |

### REST adapter

| Type | Module / package | Purpose |
|---|---|---|
| `RestHeaders`, `BearerTokenExtractor` | `jCustos-rest` | Case-insensitive header lookup and Bearer-token parsing. |
| `RestAuthenticationFilter`, `RestAuthorizationFilter` | `jCustos-rest` | 401/403 filters; the authorization filter additionally consults `SessionPolicy.evaluate(...)` when subject-resolved metadata is available. |
| `BodyRestRequest` | `jCustos-rest` | Body-capable `RestRequest`. |
| `BootstrapRestStatusMapper` | `jCustos-rest` | `InitialAdminCreationResult` → HTTP status code + stable error code. |
| `RestJCustosVersionContext`, `RestJCustosVersionFilter` | `jCustos-rest` | Phase 4c. Drift filter that returns `401 + WWW-Authenticate: SessionStale` (RFC 7235) on a stale session. |
| `OpenApiJCustosMetadataGenerator`, `JCustosRequirement`, `HandlerJCustosMetadata` | `jCustos-rest/openapi` | Phase 8d. Extracts the five framework `@Requires…`-annotations from a handler class as a JSON-free structured tree apps merge into their own OpenAPI builder. |

### Bootstrap

| Type | Module / package | Purpose |
|---|---|---|
| `BootstrapConfigurationLoader`, `BootstrapStatus` | `jCustos-core/.../bootstrap` | Centralised sysprop+env+default loading with TTL parsing; leak-safe status snapshot. |
| `AdministratorAccountStore`, `BootstrapTokenStore`, `BootstrapTokenOutput`, `InitialAdminBootstrapService` | `jCustos-core/.../bootstrap` | First-run admin creation flow; modes `PERSISTENT_FILE` / `TRANSIENT_CONSOLE` / `DISABLED`. |

### Multi-tenancy

| Type | Module / package | Purpose |
|---|---|---|
| `TenantId`, `ResourceRef`, `ResourceAccessContext` | `jCustos-core/.../authorization/api/tenant` + `…/policy/resource` | Phase 1. Adapter-neutral tenant scope (`TenantId.DEFAULT` for single-tenant) + tenant-aware resource references. Every Phase-2 store key and Phase-4/7 service is tenant-scoped. |

## Stable vs. Experimental API

Anything **not** marked `@ExperimentalJCustosApi` is covered by the
project's SemVer commitments: interfaces grow only through `default`
methods, records and enums only additively, annotations only through
elements with defaults.

**Stable** includes role-based access, the REST adapter contracts,
`JCustosSubject`, `AccessContext`, `AuthorizationDecision` and the
scanner; the DX bootstrap surface (V00.73); the JWT, OAuth2 and OIDC
contracts plus their mature implementations (V00.79, extended V00.83);
and the token-propagation surface (V00.83) — `@PropagateToken`,
`TokenCredential`, `TokenCredentialStore`, `OutboundTokenStrategy`,
`PropagatingProxy` and the token-exchange strategies.

**Experimental** means one of two things, and the difference matters:

- *Still soaking* — expected to stabilise after three minor releases and
  a real integration. Currently the V00.79.20 hardening group (mutual
  TLS, PAR, JAR, JWE), the DPoP types, the back-channel-logout receiver,
  the V00.75 event surface, the V00.70 persistence-store SPIs and
  `Store*`-backed services, and the V00.80 operations modules.
- *A design position* — the permission-based access API is marked not
  because it is new but because role-based access is the recommended
  path for production. Its marker text says so.

Promotion only removes an annotation and never changes behaviour, so it
cannot break a compiling caller. Each release notes what was promoted
and what was deliberately kept; see `RELEASE-NOTES-00.83.00.md`.

## Project-Specific Permissions Live in Applications

Library modules contain no concrete business permissions. Examples like
`document:read` belong in `demo-rest`. Real applications define their own
catalog (e.g. `shortlink:create`, `audit:read`) inside the consuming project.

See [`docs/security-modules.md`](docs/v00.50.00/security-modules.md) for the full
extension model.

## First-run bootstrap

Both demos ship without any administrator account. The first administrator
is created via a one-time **bootstrap token** in either `PERSISTENT_FILE`
or `TRANSIENT_CONSOLE` mode. The same library powers the REST endpoint,
the CLI `init-admin` command, and the Vaadin `/setup` view. Token values
are never written to logs, never echoed in responses, and the mechanism
turns itself off once an administrator exists.

Configurable via system properties (preferred) or environment variables —
both read centrally by `BootstrapConfigurationLoader`:

| System property | Environment variable | Default (demos) |
|---|---|---|
| `security.bootstrap.mode` | `SECURITY_BOOTSTRAP_MODE` | `TRANSIENT_CONSOLE` |
| `security.bootstrap.token.file` | `SECURITY_BOOTSTRAP_TOKEN_FILE` | `./data/bootstrap.token` |
| `security.bootstrap.token.ttl` | `SECURITY_BOOTSTRAP_TOKEN_TTL` | `PT24H` |

See [`docs/bootstrap.md`](docs/v00.50.00/bootstrap.md) for modes, endpoints, and the
operator workflow.

## Roadmap

**V00.70.00 is feature-complete** — all eight phases of
`Konzept-V00.70.00.md` are merged. See
[`RELEASE-NOTES-00.70.00.md`](RELEASE-NOTES-00.70.00.md) for the
full inventory + migration notes; the phase summary:

1. Tenant + resource model (`TenantId`, `ResourceRef`, `ResourceAccessContext`).
2. Persistence-store SPIs — 11 hash-only / single-use stores in `jCustos-core`.
3. Contract testkit + Eclipse-Store reference impls in their own modules.
4. Store-backed services (`StoreBacked*`) + `JCustosVersion` drift detection end-to-end in Vaadin + REST + standalone, with automatic snapshot capture in `LoginView`.
5. Policy API + method-security annotation processor.
6. Authorization ergonomy — `RoleHierarchy`, `@RequiresAnyPermission`, `@RequiresAllPermissions`, hierarchy-aware permission merge.
7. Account lifecycle (`PasswordResetService`, `EmailVerificationService`), API-key & rotating refresh-token services, sliding-window `RateLimitPolicy`.
8. `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem`, `SessionManagementView`, `OpenApiJCustosMetadataGenerator`.

`Konzept-V00.75.00.md` and `Konzept-V00.80.00.md` outline the next
layers. Demo glue for the new V00.70 building blocks (V00.70-style
session management, API-key parallel-to-Bearer in
`demo-vaadin-rest-client`, the reset-flow demo via
`LoggingNotificationSender`) plus PIT re-runs for
`jCustos-processor` and `jCustos-persistence-eclipsestore` are
the planned 00.71 follow-ups.

### V00.71.00 – Phase 1a–3 on `develop`

`Konzept-V00.71.00.md` introduces a fully new credential-security
stack under `eu.jsentinel.jcustos.credential.password.*`.
Prompts 001–025 are landed on `develop`; see
`Implementierungsplan-V00.71.00.md` §20 for the per-prompt status
table and `docs/v00.71.00/prompts/README.md` for the prompt
inventory.

Headlines:

- **Phase 1a** – JDK-only PBKDF2-HMAC-SHA-256 core with a self-describing
  `$pwh$v=1$…` envelope, sealed `CredentialVerificationResult` /
  `RehashDecision` / `ProviderVerificationResult` types, generic
  perimeter failures backed by differentiated audit classifications,
  dummy verification + concurrency-bounded `KdfExecutionLimiter`,
  bootstrap and demo-rest wired through the new
  `PasswordHashingService`.
- **Phase 1b** – Optional `jCustos-crypto-bc` module adds Argon2id,
  bcrypt and scrypt providers (BouncyCastle 1.78.1, no JCA mutation,
  per-algorithm parameter validators). The modern profile is opt-in
  and fails fast when requested without the module on the classpath.
- **Phase 2** – `SecretValue` (`AutoCloseable`), `PasswordInputPolicy`
  with Unicode normalisation, post-KDF HMAC-SHA-256 pepper with
  rotation (`PepperReference`, `PEPPER_KEY_ROTATED` rehash reason),
  policy-version / format-version rejection lists, operator-driven
  `Pbkdf2ParameterCalibrator` with reproducible persisted profiles,
  four new `AuditEvent` variants flowing through a sink-failure-tolerant
  `CredentialAuditPublisher`.
- **Phase 3** – Persistence-neutral `CredentialStore` with
  compare-and-swap updates, eight-state `CredentialLifecycleService`
  with deterministic transitions, atomic `PasswordChangeService` with
  explicit re-authentication, selector/verifier `TokenDigestService`
  and single-use dual-CAS `PasswordResetService`.

The optional foreign-hash import (Epic T) stays deferred; the
experimental `PasswordHasher` / `Pbkdf2PasswordHasher` / `PasswordHash`
types remain in the tree only so the V00.70 callers
(`StoreBackedRememberMeService`, legacy `accountlifecycle` reset and
email-verification services) keep compiling. No compatibility shim
translates between the old `pbkdf2$…` and the new `$pwh$v=1$…`
envelope — that carve-out matches Konzept-V00.71.00 §1 and §7.

Phase 4 (abuse detection, context-aware policy, optional history,
operational metrics) and Phase 5 (HIBP opt-in, FIPS / supply-chain
docs, emergency playbooks, tenant policies, compliance traceability)
are still pending — prompts 026–035 in
`docs/v00.71.00/prompts/`.

## License

EUPL 1.2