# 5-Minute Setup — Vaadin

Goal: a Vaadin Flow application that uses `jCustos` V00.73 with
the fluent bootstrap, `@JCustosAutoService` and the Vaadin starter.
V00.73 closes the two V00.72 carve-outs — the `.audit(...)` /
`.sessions(...)` / `.policies(...)` / `.roles(...)` / `.credentials(...)`
sub-builders are real, and `SecuredUi.requiresPolicy(...)` /
`@SecureRoute(policy = ...)` evaluate registered policies through
`PolicyRegistry`.

## 1. Add dependencies

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-vaadin</artifactId>
  <version>${jcustos.version}</version>
</dependency>
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-vaadin-starter</artifactId>
  <version>${jcustos.version}</version>
</dependency>
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-autoservice-annotations</artifactId>
  <version>${jcustos.version}</version>
</dependency>
```

```xml
<plugin>
  <artifactId>maven-compiler-plugin</artifactId>
  <configuration>
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
  </configuration>
</plugin>
```

## 2. Annotate your SPI implementations

```java
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;

@JCustosAutoService(AuthenticationService.class)
public final class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser> { /* ... */ }

@JCustosAutoService(AuthorizationService.class)
public final class MyAuthorizationService
    implements AuthorizationService<MyUser> { /* ... */ }
```

## 3. Bootstrap the app

```java
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.SubjectPredicates;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;

public final class JCustosInit {
  public static void install() {
    var runtime = VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.developmentDefaults())
        .subjectType(MyUser.class)
        .policies(p -> p
            .register(Policy.named("documents.editor-or-admin")
                .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
                .deny("must be ADMIN or EDITOR")
                .build()))
        .install();
    System.out.println(runtime.log());
  }
}
```

The full V00.73 sub-builder set is `.audit(...)`, `.sessions(...)`,
`.policies(...)`, `.roles(...)`, `.credentials(...)`. Each method's
JavaDoc lists the validation codes (e.g. `audit/missing-service`,
`sessions/missing-store`, `credentials/modern-without-bc`).

## 4. Guard a route

```java
@SecureRoute(roles = "ADMIN")
@Route("admin")
public final class AdminView extends VerticalLayout { /* ... */ }

@SecureRoute(policy = "documents.editor-or-admin")
@Route("editor")
public final class EditorView extends VerticalLayout { /* ... */ }
```

V00.73 evaluates the named policy through `PolicyRegistry`. An unknown
policy returns `Forbidden` at runtime; in `STRICT` mode with
`.discoverSecureRoutes(true)` the mismatch becomes a deterministic boot
failure (`secure-route/unknown-policy`).

## 5. Done

`runtime.log()` prints every registered service and any diagnostic
warning. Switch to `VaadinJCustosStarter.productionDefaults()` (or
`.strictDefaults()`) when going to production. STRICT now breaks on the
three V00.72-to-V00.73 promoted codes
(`secure-route/unknown-policy`,
`session-management-view-without-session-store`,
`security-version-without-subject-id-resolver`) — clean those up before
flipping the mode.

Since 00.84.00 the session-management route also needs an access
requirement: call `.sessionManagementView(SecuredVisibility.Requirement
.permission(new PermissionName("admin:sessions")))` (or `.role(...)`).
The parameterless `.sessionManagementView()` is deprecated; it leaves the
route closed to everyone and reports
`session-management-view-without-requirement` (an error in PRODUCTION and
STRICT, JS-SEC-068).

## 6. Programmatic health (V00.74.10)

For `/health` endpoints, monitoring dashboards or boot banners use the
V00.74.10 tooling methods on the same `runtime` instance — they expose a
structured view of the snapshot without parsing `log()`:

```java
runtime.summary();
// "OK | 8 services | 0 errors | 1 warnings | 2 INFO"

runtime.healthCheck();
// HealthStatus(overall=DEGRADED, findings=[...],
//              registeredServices=8, inspectedAt=...)

runtime.toJson();
// {"mode":"PRODUCTION","serviceCount":8,"services":[...],
//  "warningCount":3,"warnings":[...]}
```

`healthCheck()` classifies any `ERROR` finding as `FAILED`, any
`WARNING` (without errors) as `DEGRADED`, and `INFO`-only or empty as
`HEALTHY` — `INFO` findings intentionally do not degrade. The
`toJson()` encoder is jCustos's own — Maven Enforcer on
`jCustos-dx` blocks Jackson, Gson and `org.json` on compile/runtime
scope so consumer projects do not inherit a JSON library through the
DX classpath. All four methods are marked
`@ExperimentalJCustosApi` until V00.76 confirms the shape.

## 7. Persistence pair (V00.74.20)

When you also want Eclipse-Store persistence (audit log + sessions +
your own domain data), open a `JCustosStoragePair` at process start
and feed its framework half into the bootstrap. The pair manages both
storages — framework + app — under one parent directory with a single
two-phase shutdown:

```java
try (JCustosStoragePair pair = JCustosStorageFactory.openAt(Path.of("data"))) {
  VaadinSecurity.bootstrap()
      .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
      .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
      .install();
  // pair.app() is your application's own EmbeddedStorageManager —
  // use pair.app().root() / setRoot(…) / store(…) for domain data.
}
```

The pair's `close()` shuts the app storage down first, the framework
storage second, and the framework close-attempt always runs (so a
buggy app shutdown cannot leave the framework's lock file held).