---
name: jcustos-standalone-persistence
description: Layer-2 follow-up to the `jcustos-standalone` skill — swaps the in-memory stores for Eclipse-Store + replaces the plaintext admin/admin seed with the token-based first-admin bootstrap. The CLI gets a new "setup" command that prompts for the bootstrap token + admin credentials when `bootstrapRequired()` is true; the regular login command is blocked until then. User-directory persistence is **pluggable** — the default `EclipseStoreUserDirectoryPersistence` runs in its own `EmbeddedStorageManager` under `{{STORAGE_DIR}}/users`, independent of the framework storage; swap for JDBC / LDAP by implementing `UserDirectoryPersistence`. **Additive via the layer-1 `BootstrapExtension` SPI** — no overwrite of `Main`'s bootstrap; persistence ships a `PersistenceBootstrapExtension` picked up by `BootstrapBuilder.apply(...)`. Prerequisite: a project that already ran `jcustos-standalone`. Adds 1 dependency (`jCustos-persistence-eclipsestore`), 9 templates (`JCustosStorageProvider`, `AdministratorAccountStoreImpl`, `BootstrapWiring`, `PersistentUserDirectory`, `Main` delta, `StoredUser`, `UserDirectoryPersistence`, `EclipseStoreUserDirectoryPersistence`, `InMemoryUserDirectoryPersistence`).
---

# jCustos Standalone persistence — layer 2

Same shape as `jcustos-rest-persistence` / `jcustos-vaadin-persistence`,
but the entry point that triggers `BootstrapWiring.instance()` is
`Main.main()` itself.

## Templates

| Template | Source |
|---|---|
| `pom-snippet.xml.tmpl` | NEW (dependency + Surefire `<systemPropertyVariables>` block) |
| `AppStoragePaths.java.tmpl` | NEW (single source of truth for storage paths; reads `app.storage.dir` system property) |
| `JCustosStorageProvider.java.tmpl` | shared |
| `AdministratorAccountStoreImpl.java.tmpl` | shared (logs at INFO/ERROR via `HasLogger`; no swallowed exceptions) |
| `BootstrapWiring.java.tmpl` | shared (from rest-persistence) |
| `StoredUser.java.tmpl` | shared (top-level record, no Serializable) |
| `UserDirectoryPersistence.java.tmpl` | shared (pluggable persistence SPI) |
| `EclipseStoreUserDirectoryPersistence.java.tmpl` | shared (default impl; uses the `JCustosStoragePair`'s app-side `EmbeddedStorageManager`; lifecycle owned by the pair, V00.74.20+) |
| `InMemoryUserDirectoryPersistence.java.tmpl` | shared (test seam) |
| `PersistentUserDirectory.java.tmpl` | shared (takes `UserDirectoryPersistence` + `PasswordHasher` via ctor) |
| `UserDirectoryProvider.java.tmpl` | shared (wires `EclipseStoreUserDirectoryPersistence` + shutdown hook) |
| `Main.java.tmpl` | OVERWRITE — adds the setup-token prompt path |

## Slots

| Slot | Default |
|---|---|
| `{{STORAGE_DIR}}` | `./data/jcustos-standalone` |
| `{{BOOTSTRAP_TOKEN_FILE}}` | `./data/jcustos-standalone/bootstrap.token` |

The `{{STORAGE_DIR}}` slot only seeds `AppStoragePaths.DEFAULT`. At
runtime the path is the value of the system property
`app.storage.dir` (defaulting to that slot). To redirect storage in
a production deployment:

```bash
java -Dapp.storage.dir=$HOME/.myapp -jar myapp.jar
```

Tests automatically get `target/test-data` via the Surefire block
shipped in `pom-snippet.xml.tmpl`.

## Pitfalls

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
- Sequential CLI test runs share state: a "create admin" test leaks
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
