---
name: jcustos-rest-persistence
description: Layer-2 follow-up to the `jcustos-rest` skill — swaps the in-memory stores (audit ring buffer, session store) for the Eclipse-Store-backed persistence module and replaces the in-memory admin/admin seed with the V00.70 first-admin bootstrap flow (`InitialAdminBootstrapService` + `BootstrapStateService` + `POST /api/setup` endpoint). User-directory persistence is **pluggable** — the default `EclipseStoreUserDirectoryPersistence` runs in its own `EmbeddedStorageManager` under `{{STORAGE_DIR}}/users`, independent of the framework storage; swap for JDBC / LDAP / IAM by implementing `UserDirectoryPersistence`. **Additive via the layer-1 `BootstrapExtension` SPI** — no overwrite of `RestServer.java`'s bootstrap; the persistence layer ships a `PersistenceBootstrapExtension` that gets picked up by `BootstrapBuilder.apply(...)` alongside any other layer's contributions. Order is therefore irrelevant. Prerequisite: a project that already ran `jcustos-rest`. Use PROACTIVELY when the user mentions persistent REST stores, eclipse-store REST, "REST users survive restart", "audit log persistence REST", token-based first-admin bootstrap for REST, `InitialAdminBootstrapService`, `BootstrapStateService`, `/api/setup`, `BootstrapWiring`, `PERSISTENT_FILE` mode, "remove the plaintext admin seed from my REST API". Adds 1 new dependency (`jCustos-persistence-eclipsestore`), 9 new templates (`AppStoragePaths`, `JCustosStorageProvider`, `AdministratorAccountStoreImpl`, `BootstrapWiring`, `BootstrapHandler`, `StoredUser`, `UserDirectoryPersistence`, `EclipseStoreUserDirectoryPersistence`, `InMemoryUserDirectoryPersistence`) and replacement templates (`InMemoryUserDirectory` becomes `PersistentUserDirectory`, `SessionStoreProvider` returns the storage's session store, `UserDirectoryProvider` becomes IODH-lazy via `AppStoragePaths`). Surefire-`<systemPropertyVariables>` block in `pom-snippet.xml.tmpl` redirects test runs to `target/test-data`. Plus 1 META-INF/services file (`BootstrapExtension`) — append-safe. Does NOT cover modern crypto, HIBP, drift detection — those are `jcustos-rest-hardening`.
---

# jCustos REST persistence — layer 2

Same shape as `jcustos-vaadin-persistence` but the Vaadin-specific
parts (`SetupView`, `BeforeEnterObserver`, `VaadinServiceInitListener`)
are replaced by REST equivalents:

- `BootstrapHandler` exposing `POST /api/setup` for the token-based
  first-admin creation
- A 503 guard in the `Router` that rejects every other endpoint while
  `bootstrapRequired()` is true
- `RestServer` calls `BootstrapWiring.instance()` at startup so the
  console banner / token file is generated before the first request

## Slots (in addition to layer-1)

| Slot | Default |
|---|---|
| `{{STORAGE_DIR}}` | `./data/jcustos-rest` |
| `{{BOOTSTRAP_TOKEN_FILE}}` | `./data/jcustos-rest/bootstrap.token` |

The `{{STORAGE_DIR}}` slot only seeds `AppStoragePaths.DEFAULT`. At
runtime the path is the value of the system property
`app.storage.dir` (defaulting to that slot). To redirect storage in
a production deployment:

```bash
java -Dapp.storage.dir=/var/lib/myapp -jar myapp.jar
```

Tests automatically get `${project.build.directory}/test-data` via
the Surefire block shipped in `pom-snippet.xml.tmpl`.

## Templates

| Template | Target | Source |
|---|---|---|
| `pom-snippet.xml.tmpl` | merge | NEW (dependency + Surefire `<systemPropertyVariables>` block) |
| `AppStoragePaths.java.tmpl` | `security/storage/` | NEW (single source of truth for storage paths; reads `app.storage.dir` system property) |
| `JCustosStorageProvider.java.tmpl` | `security/bootstrap/` | shared (resolves base via `AppStoragePaths.frameworkStorageDir()`) |
| `AdministratorAccountStoreImpl.java.tmpl` | `security/bootstrap/` | shared (logs at INFO/ERROR via `HasLogger`; no swallowed exceptions) |
| `BootstrapWiring.java.tmpl` | `security/bootstrap/` | shared (token file via `AppStoragePaths.bootstrapTokenFile()`) |
| `StoredUser.java.tmpl` | `security/model/` | shared (top-level record, no Serializable) |
| `UserDirectoryPersistence.java.tmpl` | `security/model/` | shared (pluggable persistence SPI) |
| `EclipseStoreUserDirectoryPersistence.java.tmpl` | `security/model/` | shared (default impl; uses the `JCustosStoragePair`'s app-side `EmbeddedStorageManager`; lifecycle owned by the pair, V00.74.20+) |
| `InMemoryUserDirectoryPersistence.java.tmpl` | `security/model/` | shared (test seam) |
| `PersistentUserDirectory.java.tmpl` | `security/model/` (REPLACES `InMemoryUserDirectory`) | shared (takes `UserDirectoryPersistence` + `PasswordHasher` via ctor) |
| `UserDirectoryProvider.java.tmpl` | OVERWRITE | shared (IODH-lazy; resolves dir via `AppStoragePaths.userDirectoryDir()`) |
| `SessionStoreProvider.java.tmpl` | OVERWRITE | NEW (delegates to storage) |
| `BootstrapHandler.java.tmpl` | `handlers/` | NEW |
| `RestServer.java.tmpl` | OVERWRITE | NEW (adds `.audit/.sessions storeBacked` + setup route + bootstrap guard) |

## Pitfalls

### Setup endpoint must precede the auth-protected ones in the Router

The 503 bootstrap-required guard kicks in for every route *except*
`POST /api/setup`. The template orders the routes so the setup
endpoint is registered first; do not reorder.

### Token file permissions

`{{BOOTSTRAP_TOKEN_FILE}}` is a plaintext file containing a
one-time admin grant. Restrict its permissions to the server user
(`chmod 600` on Unix). The skill does NOT chmod for you.

### Eager Eclipse-Store init at classload time

The pre-IODH version of `UserDirectoryProvider` had this shape:

```java
private static volatile UserDirectory directory = buildDefault();
```

The field initialiser runs at classload. Anything that touches the
class — static analysis (SpotBugs, PMD), code-coverage
instrumentation, a PIT mutation worker scanning class metadata, or
a unit test that imports the package — opens Eclipse-Store and
writes the `{{STORAGE_DIR}}` directory tree. Tests that intend to
install a substitute via `setDirectory(...)` are too late: the
production directory was already constructed.

The rendered template uses the
[Initialization-on-Demand Holder](https://en.wikipedia.org/wiki/Initialization-on-demand_holder_idiom)
idiom — Eclipse-Store opens only on the first call to `directory()`
that finds no test override installed. If a test calls
`setDirectory(...)` before any production code reaches `directory()`,
the holder is never initialised and Eclipse-Store is never touched.

### Tests writing to repo-root `{{STORAGE_DIR}}` corrupt themselves

Symptoms when storage paths are hard-coded under the repo root:

- `git status` shows `{{STORAGE_DIR}}` dirty unless gitignored.
- `mvn clean` does NOT wipe it — manual `rm -rf` required.
- Sequential test runs share state: a "create admin" test leaks
  into the next "no admin yet" assertion.
- PIT forks many JVMs that all race for the same Eclipse-Store
  directory → "Unknown transactions entry type: -106" checksum
  errors that look like flaky test failures.

Fix: the rendered `AppStoragePaths` helper reads the
`app.storage.dir` system property; the rendered
`pom-snippet.xml.tmpl` sets that property in Surefire to
`${project.build.directory}/test-data`. Every test fork writes
under `target/`. `mvn clean` is now the only state-reset command
needed.

## First administrator (JS-SEC-134)

- `BootstrapWiring` hashes the first administrator with the user
  directory's own pipeline (`UserDirectory.hashingService()`, i.e.
  `JCustosServiceResolver.credentialHashingService()`), so the account
  the setup creates can log in. Build it after `install()` — the
  server / CLI calls `BootstrapWiring.instance()` right after the
  bootstrap; `PersistenceBootstrapExtension` no longer triggers it from
  a static initialiser.
- The password must pass `MinimumLengthPasswordPolicy(12)` plus every
  `BootstrapExtension.initialAdminPasswordPolicy(...)` contribution
  (the hardening layer adds its `PasswordPreflight`).
- Test seam: `BootstrapWiring.setInstance(BootstrapWiring.create(config,
  new InMemoryBootstrapTokenStore(), capturingOutput))` before the
  server starts, together with `JCustosStorageProvider.setPair(...)`
  and `UserDirectoryProvider.setDirectory(...)`.
