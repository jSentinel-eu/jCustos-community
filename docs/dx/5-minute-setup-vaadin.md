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
        .loginRoute("login")
        .denyByDefault(true)                       // unannotated routes are denied
        .logout(new VaadinLogoutService<>(SubjectStores.subjectStore(), MyUser.class))
        .sessions(s -> s.storeBacked(sessionStore)) // also the per-request revocation check
        .policies(p -> p
            .register(Policy.named("documents.editor-or-admin")
                .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
                .deny("must be ADMIN or EDITOR")
                .build()))
        .install();
    HasLogger.staticLogger().info("{}", runtime.log());
  }
}
```

Fail-closed wiring, as the demos and skills ship it since 00.84.00:

- **Deny-by-default.** `.denyByDefault(true)` denies every route without a security
  annotation; mark the public ones — home, login, setup, step-up — with `@PublicRoute`
  (JS-SEC-085). Public views, the login view and a step-up view must not live inside a
  restricted router layout: a layout's restriction applies to every view in it
  (JS-SEC-154).
- **Login and step-up routes need views.** Configure `.stepUpRoute(...)` only together with
  a registered step-up view; an unresolved login route, or a configured step-up route
  without a view, is an error in PRODUCTION and STRICT (JS-SEC-152).
- **Logout service.** Without `.logout(...)` PRODUCTION and STRICT report
  `logout/missing-service` (JS-SEC-124).
- **Throttling.** The library `LoginView` runs the `LoginAttemptPolicy` protocol itself; do
  not call the policy from your `AuthenticationService` (every attempt would count twice).
- **Session inventory.** Record sessions in `LoginView.onSessionRotated(...)` under
  `SessionRef.of(sessionId)`, so neither the store nor the session-management grid holds the
  session cookie (JS-SEC-117); no decorating store is needed. Revoke with
  `VaadinSessionRevocation::revoke`: it matches the live session by its reference and ends it
  at the click on this node. The store registered through `.sessions(s -> s.storeBacked(...))`
  is checked on every request, so a removed record, or one another node marks `REVOKED`, ends
  the session on its next request there (JS-SEC-131).
- **Denials point elsewhere.** An `AccessEvaluator` that denies must name a route the denied
  visitor may see, never the denied view and never a view in the same restricted layout:
  Vaadin skips a reroute or forward to the navigation in progress, and since 00.84.00 such a
  denial ends in the error view (JS-SEC-158).
- **Version drift.** Register `JCustosVersionEnforcerListener` with
  `listener.register(serviceInitEvent)` — it also covers WebSocket-only push messages
  (JS-SEC-155).
- **Session cookie.** Give the application its own cookie name in `web.xml`
  (`<cookie-config><name>MYAPP_SESSION</name><http-only>true</http-only><secure>true</secure>`),
  never the shared `JSESSIONID`.

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
`security-version-without-subject-id-resolver`) and, since 00.84.00, on
`authorization/allow-by-omission` (no `.denyByDefault(true)`),
`audit/noop-fallback` (no `.audit(...)` and no registered audit
service), `logout/missing-service` and `vaadin/login-route-unresolved` —
clean those up before flipping the mode.

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