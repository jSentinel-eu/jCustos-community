# 5-Minute Setup — Standalone (CLI / desktop / batch)

V00.73 fluent bootstrap for the Standalone adapter.
`.audit(...)`, `.policies(...)`, `.roles(...)` and `.credentials(...)`
are real. `.sessions(...)` is recorded but the install path emits the
INFO code `standalone/sessions-not-applicable` — Standalone has no
session concept (`StandaloneLoginFlow` binds straight into the
thread-local `SubjectStore`).

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-standalone</artifactId>
  <version>${jcustos.version}</version>
</dependency>
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-dx-standalone</artifactId>
  <version>${jcustos.version}</version>
</dependency>
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-autoservice-annotations</artifactId>
  <version>${jcustos.version}</version>
</dependency>
```

```xml
<annotationProcessorPaths>
  <path>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-autoservice-processor</artifactId>
    <version>${jcustos.version}</version>
  </path>
  <path>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-autoservice-annotations</artifactId>
    <version>${jcustos.version}</version>
  </path>
</annotationProcessorPaths>
```

```java
@JCustosAutoService(AuthenticationService.class)
public final class DemoAuthenticationService
    implements AuthenticationService<Credentials, User> { /* ... */ }

@JCustosAutoService(AuthorizationService.class)
public final class DemoAuthorizationService
    implements AuthorizationService<User> { /* ... */ }
```

```java
import eu.jsentinel.jcustos.dx.standalone.bootstrap.StandaloneSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;

var runtime = StandaloneSecurity.bootstrap()
    .mode(JCustosBootstrapMode.DEVELOPMENT)
    .audit(a -> a.logging().ringBuffer(128))
    .install();
System.out.println(runtime.log());
```

The default `SubjectStore` is `ThreadLocalSubjectStore` — set a custom
one with `.subjectStore(...)` if you have background workers.

## Login outcomes (00.84.00)

`StandaloneLoginFlow.login(...)` has three results and one exception,
and a CLI has to handle all four:

```java
StandaloneLoginFlow.LoginResult<User> result;
try {
  result = loginFlow.login(new Credentials(username, password), username);
} catch (CredentialVerificationUnavailableException shed) {
  // JS-SEC-126: the KDF limiter shed the check - nothing was counted.
  out.println("Login temporarily unavailable. Try again later.");
  return null;
}
return switch (result) {
  case StandaloneLoginFlow.LoginResult.Success<User> s -> s.subject();
  case StandaloneLoginFlow.LoginResult.Rejected<User> r -> null;
  // Also the answer when the account was locked while the password was
  // being checked (JS-SEC-123): no subject is bound.
  case StandaloneLoginFlow.LoginResult.LockedOut<User> l -> null;
};
```

Login throttling is on without configuration (JS-SEC-124): the
resolver falls back to an `InMemoryLoginAttemptPolicy`. Hash passwords
through `JCustosServiceResolver.credentialHashingService()` — the
pipeline `.credentials(c -> c.hashing(...))` sets — and run
`verifyAgainstNothing` for an unknown name. `demo-jcustos-standalone`
and `demo-standalone` show the pattern.

## Method-level security and the wrapper index

Method-level security on a concrete class without an interface uses the
compile-time `<Type>Secured` wrapper (`@Secured` + `jCustos-processor`).
Since 00.84.00 the wrapper enforces every restriction annotation and
deny-by-default, and a restriction on a method it cannot override
(`final`, `static`, `private`, `protected`, package-private) is the
compile error `processing/unenforceable-security-annotation`
(JS-SEC-156).
V00.73 completes the wrapper-index pipeline: `jCustos-processor` now
writes `META-INF/jcustos/generated-wrappers.idx` after each
compile (the V00.72 reader path was already in place). One line per
generated wrapper, format
`sourceFqn:generatedFqn:processor:proxyBuilderVer:method1,method2,...`.

`JCustosDiagnostics.inspect()` reports every generated wrapper visible
through that file. Running `./mvnw -pl :demo-standalone -am compile`
produces an entry for `MemberDirectorySecured`.

## STRICT mode

`mode(STRICT)` breaks on the three V00.72-to-V00.73 promotions and the
new V00.73 sub-builder validation codes (`audit/missing-service`,
`credentials/modern-without-bc`, …). Since 00.84.00 it also refuses to
boot without `.denyByDefault(true)` (`authorization/allow-by-omission`),
without an audit service (`audit/noop-fallback`) and without a
`LogoutService` (`logout/missing-service`); an `AuthenticationService`
or `AuthorizationService` registered through `META-INF/services` (as
`@JCustosAutoService` does) counts and is listed as `spi-registered`.
`.sessions(...)` on Standalone records INFO only and never blocks the
bootstrap.

## Programmatic health (V00.74.10)

For CLI boot banners and machine-readable status, use the V00.74.10
tooling methods on the `runtime` returned by `install()`:

```java
System.out.println(runtime.summary());
// → "OK | 8 services | 0 errors | 0 warnings | 2 INFO"

var health = runtime.healthCheck();
if (health.hasErrors()) {
  System.err.println("Refusing to start: " + runtime.toJson());
  System.exit(1);
}
```

`healthCheck()` classifies any `ERROR` finding as `FAILED`, any
`WARNING` (without errors) as `DEGRADED`, and `INFO`-only or empty as
`HEALTHY` — `INFO` findings intentionally do not degrade. The
`toJson()` encoder is internal — no Jackson, Gson or `org.json`
dependency lands on the standalone classpath. All four methods are
marked `@ExperimentalJCustosApi` until V00.76.

## Persistence pair (V00.74.20)

When the CLI / desktop app needs Eclipse-Store persistence (audit log
+ sessions + application data), open a `JCustosStoragePair` once
and feed its framework half into the bootstrap:

```java
JCustosStoragePair pair = JCustosStorageFactory.openAt(Path.of("data"));
Runtime.getRuntime().addShutdownHook(new Thread(pair::close, "jcustos-pair-close"));

StandaloneSecurity.bootstrap()
    .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
    .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
    .install();

// pair.app() is your domain-data EmbeddedStorageManager — use it via
// pair.app().root() / setRoot(…) / store(…).
```

The pair's two-phase `close()` shuts the app storage down first and
the framework storage second; the framework close-attempt always
runs so its lock file is released even if app shutdown throws.
