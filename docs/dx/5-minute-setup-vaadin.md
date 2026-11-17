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
- **Version drift.** `VaadinJCustosStarter.serviceInit(event, MyLoginView.class)` registers
  `JCustosVersionEnforcerListener` on every request path - navigation, UIDL, WebSocket-only
  push messages, downloads (JS-SEC-155) - as soon as a `JCustosVersionStore` is registered.
  Register the store as an `ObservableJCustosVersionStore` and the open session of a user whose
  roles change ends at once instead of on the next click (R8, see below).
- **Session cookie.** Give the application its own cookie name in `web.xml`
  (`<cookie-config><name>MYAPP_SESSION</name><http-only>true</http-only><secure>true</secure>`),
  never the shared `JSESSIONID`.
- **Unhandled errors.** The starter's `JCustosErrorHandler` (experimental, see below; installed
  by `VaadinJCustosStarter.serviceInit(...)`): an exception that escapes a listener shows the
  user a reference instead of its message, and the log keeps the stack trace under that
  reference (JS-SEC-067).

### One call at service init (00.84.00)

What needs the Vaadin service - the security-version check, its proactive reaction, the error
handler - is wired by one call from the application's `VaadinServiceInitListener` (registered in
`META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener`), after the bootstrap:

```java
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;

public final class AppServiceInitListener implements VaadinServiceInitListener {
  @Override
  public void serviceInit(ServiceInitEvent event) {
    JCustosInit.install();                                       // the bootstrap above, once per JVM
    VaadinJCustosStarter.serviceInit(event, MyLoginView.class);  // per service
  }
}
```

| Part | Installed when |
|---|---|
| `JCustosVersionEnforcerListener` - drift refused on navigation, UIDL, push and download | a `JCustosVersionStore` is registered (`.sessions(s -> s.securityVersion(...))`, `META-INF/services`) |
| `VaadinJCustosVersionChangeBridge` - drift acted on at once (R8) | that store is an `ObservableJCustosVersionStore` |
| `JCustosErrorHandler` on every new session | always, unless `Options.defaults().withoutErrorHandler()` |
| `VaadinSessionRegistryCleanup` of the OIDC module | `Options.defaults().withOidcSessionRegistry(registry)` and `jCustos-identity-oidc-vaadin` on the class path |

`serviceInit(...)` returns the installed parts and logs them (`starter/service-init: installed
[...]`); a part whose prerequisite is missing is skipped with an INFO line. Hand-written init
listeners for these parts are no longer needed - remove them, or the parts are registered twice.

### Open sessions after a role change (R8, 00.84.00)

The security-version check refuses a session whose subject's version moved on - but only with
the session's next request. To act at once, register the version store wrapped in the observable
decorator and change versions through the registered instance:

```java
var versions = new ObservableJCustosVersionStore(new InMemoryJCustosVersionStore());
VaadinSecurity.bootstrap()
    // ...
    .sessions(s -> s.securityVersion(versions).subjectIdResolver(new MySubjectIdResolver()))
    .install();
// later, after a role change of a user:
versions.increment(new JCustosVersionKey(TenantId.DEFAULT, SubjectId.of(userId)));
```

`VaadinJCustosStarter.serviceInit(...)` then installs `VaadinJCustosVersionChangeBridge`: every
open UI of that user is ended as the per-request check ends it - subject dropped, `SessionStale`
audited, the browser sent to the login view, the session closed. With `@Push` that happens without
a click; without push the session is ended on the server at once and the browser learns of it with
its next request. The decorator is node-local: other nodes that share the backing store react on
their next request.

For a role change that does not bump the version - a role granted, an impersonation started -
re-evaluate the secured components of a UI yourself:

```java
ui.access(() -> SecuredVisibility.refreshAll(ui));
```

`refreshAll(UI)` covers `SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem` and every
`SecuredUi` binding of that UI; the bindings are held weakly, so a removed component is dropped.

### Guard the click, not only the button (00.84.00)

`SecuredUi.button(...)` decides what the user sees. `SecuredUi.action(...)` also decides what a
click does: it evaluates the requirement again when the click arrives and refuses it - the
listener does not run, the button is disabled (or hidden), `ActionDenied` is audited - when the
permission was withdrawn after the page was rendered:

```java
Button delete = SecuredUi.action(new Button("Delete"), click -> documents.delete(id))
    .requiresPermission("doc:delete")
    .bind();
```

The full V00.73 sub-builder set is `.audit(...)`, `.sessions(...)`,
`.policies(...)`, `.roles(...)`, `.credentials(...)`. Each method's
JavaDoc lists the validation codes (e.g. `audit/missing-service`,
`sessions/missing-store`, `credentials/modern-without-bc`).

### Unhandled errors: a reference for the user, the stack trace for the log (00.84.00)

An exception thrown in a click listener, a value-change listener or a `UI.access` command
reaches the session's `ErrorHandler`. A home-grown handler that puts the exception message into
a notification shows the browser SQL, file paths and account data (CWE-209). The starter ships
one that does not. `VaadinJCustosStarter.serviceInit(...)` installs it; to install it on its own,
call it from the application's `VaadinServiceInitListener` (registered in
`META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener`):

```java
import eu.jsentinel.jcustos.starter.errors.JCustosErrorHandler;

public final class AppServiceInitListener implements VaadinServiceInitListener {
  @Override
  public void serviceInit(ServiceInitEvent event) {
    JCustosErrorHandler.install(event);   // every new session gets the handler
  }
}
```

What it does with an error:

1. A `HasErrorParameter` view registered for exactly the class of the exception is shown, as
   Vaadin's default handler does - `HasErrorParameter<AccessDeniedException>` for the denial of a
   secured service, for example. Nothing else happens.
2. Otherwise the log receives `Unhandled error, reference K7Q2MZ4XB3TAW5CD` at ERROR with the
   stack trace - 16 Base32 characters from `SecureRandom`, nothing from the request.
3. The user sees a notification with that reference only: *An unexpected error occurred. Please
   quote reference K7Q2MZ4XB3TAW5CD when you report it.* Translate it with the key
   `jcustos.error.reference` in the application's `vaadin-i18n/translations_*.properties`; `{0}`
   is the reference, and a translation without it is ignored.

A client that went away (`SocketException`, Jetty's `EofException`, ...) is not reported, as with
Vaadin's default. A failure inside the handler, and an error raised while it is running, is
logged and never shown, so the handler cannot recurse. To show the reference differently - in a
dialog, with a support address - subclass it, override `showReference(UI, String)` and set the
subclass with `event.getSource().addSessionInitListener(e -> e.getSession().setErrorHandler(new
MyErrorHandler()))`.

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
`.strictDefaults()`) when going to production. Since 00.84.00 both
profiles also set `.denyByDefault(true)` and, when exactly one
`LoginView` route is registered (or the registered `LoginListener` names
one), `.loginRoute(...)` - an unannotated route is then denied, so mark
the public ones `@PublicRoute`. Apply the profile first; later builder
calls override it. `developmentDefaults()` sets the mode only. STRICT now breaks on the
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