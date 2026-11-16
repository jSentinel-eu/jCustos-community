package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.propagation.vaadin.VaadinSessionTokenCredentialStore;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.SessionStoreProvider;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.vaadin.VaadinLogoutService;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the V00.73 fluent {@link VaadinSecurity#bootstrap()} chain once
 * per JVM at Vaadin service init, then logs
 * {@link JCustosRuntime#log()} so the operator sees which services
 * activated.
 *
 * <p>Registered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 *
 * <p>The chain pulls {@code @JCustosAutoService}-annotated services
 * through {@link ServiceLoader} so this listener doesn't need to know
 * the application's concrete implementations.
 *
 * <p>Fail-closed settings: {@code denyByDefault(true)} denies a route
 * without a security annotation unless it is {@code @PublicRoute}
 * (JS-SEC-085); {@code logout(...)} registers the logout service the
 * layout uses (JS-SEC-124); the session store is registered for the
 * per-request revocation check (JS-SEC-131). There is no
 * {@code stepUpRoute(...)}: the application uses no step-up policy and
 * has no step-up view (JS-SEC-152).
 */
public class JCustosBootstrapInitListener implements VaadinServiceInitListener, HasLogger {

  private static final AtomicBoolean DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    if (!DONE.compareAndSet(false, true)) {
      return;
    }
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElse(null);
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElse(null);
    if (authn == null || authz == null) {
      // No registered SPIs — let the framework fall back to its
      // legacy ServiceLoader path. The fluent bootstrap is additive.
      return;
    }
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .denyByDefault(true)
        .logout(logoutService(authn))
        .audit(a -> a.ringBuffer(256).logging())
        .sessions(s -> s.storeBacked(SessionStoreProvider.sessionStore()))
        .credentials(c -> c.hashing(PasswordHashingServices.defaults()))
        // Token propagation: the session-backed store holds the token the
        // login established, and pass-through forwards it as a Bearer header
        // on every @PropagateToken call. Switching to token exchange would
        // be a change here, not in the calling code.
        .propagation(p -> p
            .credentialStore(new VaadinSessionTokenCredentialStore())
            .passThrough())
        .install();
    logger().info("{}", runtime.log());
  }

  /**
   * Full logout: subject cleared, Vaadin session closed, HTTP session
   * invalidated, redirect to the configured login route.
   */
  private static <U> LogoutService logoutService(AuthenticationService<?, U> authn) {
    return new VaadinLogoutService<>(SubjectStores.subjectStore(), authn.subjectType());
  }
}
