package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.vaadin.VaadinLogoutService;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the V00.73 fluent {@link VaadinSecurity#bootstrap()} chain
 * once per JVM at Vaadin service init, and then - for every service -
 * the starter's one-call service initialisation
 * {@link VaadinJCustosStarter#serviceInit(ServiceInitEvent, Class)}.
 *
 * <p>This listener is layer-1 — it stays untouched when persistence,
 * hardening or any other layer is applied later. Sub-aspect
 * configuration (audit, sessions, credentials) flows through
 * {@link BootstrapBuilder#apply(eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap)},
 * which loads every registered {@link BootstrapExtension} via
 * {@link ServiceLoader}. New layers add a new extension; the entry
 * point here never has to change.
 *
 * <p>The hardening layer runs the {@code productionDefaults()} profile
 * (JS-SEC-137): PRODUCTION reports an incomplete security configuration
 * as errors instead of suppressing it. Since 00.84.00 the profile also sets
 * deny-by-default and the login route of {@code MyLoginView} (JS-SEC-168);
 * the chain keeps both explicit. Three settings keep the chain
 * fail-closed:
 * <ul>
 *   <li>{@code denyByDefault(true)} — a route without a security annotation
 *       is denied unless it is marked {@code @PublicRoute} (JS-SEC-085,
 *       CWE-1188). The public home, the login view and the setup view carry
 *       {@code @PublicRoute}.</li>
 *   <li>{@code logout(...)} — the logout service the layout's Sign-out button
 *       uses. Without one, PRODUCTION and STRICT report
 *       {@code logout/missing-service} (JS-SEC-124).</li>
 *   <li>No {@code stepUpRoute(...)}: the application uses no step-up policy and
 *       has no step-up view, and a configured step-up route without a view is
 *       an error in PRODUCTION and STRICT (JS-SEC-152).</li>
 * </ul>
 */
public class JCustosBootstrapInitListener implements VaadinServiceInitListener, HasLogger {

  private static final AtomicBoolean DONE = new AtomicBoolean();

  private static volatile JCustosRuntime runtime;

  /**
   * Returns the {@link JCustosRuntime} captured at the most recent
   * successful {@code serviceInit(...)}, or {@code null} if the
   * bootstrap has not yet run (e.g. the first Vaadin request is still
   * in flight). The {@code HealthView} reads this on every render so a
   * runtime swap during V00.75-style hot-reload remains observable.
   *
   * @return the active runtime snapshot, or {@code null}
   */
  public static JCustosRuntime currentRuntime() {
    return runtime;
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    bootstrapOnce();
    // JS-SEC-168: one call instead of hand-written init listeners. The hardening layer
    // registers an ObservableJCustosVersionStore (HardeningBootstrapExtension), so this
    // installs the security-version check on every request path, its proactive reaction -
    // an open session of a user whose roles change ends at once, over @Push (R8) - and the
    // reference error handler (JS-SEC-067). Per service, after the bootstrap.
    VaadinJCustosStarter.serviceInit(event, MyLoginView.class);
  }

  /**
   * Runs the bootstrap chain once per JVM; a second service reuses the configuration.
   */
  public static void bootstrapOnce() {
    if (!DONE.compareAndSet(false, true)) {
      return;
    }
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElse(null);
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElse(null);
    if (authn == null || authz == null) {
      return;
    }
    JCustosRuntime bootstrapped = BootstrapBuilder.apply(
        VaadinSecurity.bootstrap()
            .use(VaadinJCustosStarter.productionDefaults())
            .authentication(authn)
            .authorization(authz)
            .loginRoute("login")
            .denyByDefault(true)
            .logout(logoutService(authn))
    ).install();
    runtime = bootstrapped;
    HasLogger.staticLogger().info("{}", bootstrapped.log());
  }

  /**
   * Full logout: subject cleared, Vaadin session closed, HTTP session
   * invalidated, redirect to the configured login route.
   */
  private static <U> LogoutService logoutService(AuthenticationService<?, U> authn) {
    return new VaadinLogoutService<>(SubjectStores.subjectStore(), authn.subjectType());
  }
}
