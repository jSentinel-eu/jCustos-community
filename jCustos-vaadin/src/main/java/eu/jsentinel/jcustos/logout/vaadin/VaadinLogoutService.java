/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.logout.vaadin;

import eu.jsentinel.jcustos.logout.InMemorySubjectSessionRegistry;
import eu.jsentinel.jcustos.logout.LogoutListener;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.logout.SubjectSessionRegistry;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Vaadin-aware {@link LogoutService}. Wraps a core
 * {@link SubjectClearingLogoutService} and adds Vaadin-side cleanup:
 * browser redirect, HTTP-session invalidation, VaadinSession close.
 * <p>
 * Order of operations on {@link LogoutScope#CurrentSession}:
 * <ol>
 *   <li>{@link SessionPolicy#onLogout(SessionContext) SessionPolicy.onLogout}
 *       notification — emits {@code SESSION_INVALIDATED} audit when the
 *       configured policy wants it.</li>
 *   <li>Core {@link SubjectClearingLogoutService#logout(SubjectId, LogoutScope)
 *       SubjectClearingLogoutService.logout} — drops the cached subject
 *       from the {@link SubjectStore} and fans out the
 *       {@link LogoutListener} chain.</li>
 *   <li>Browser redirect scheduled via {@code Page.setLocation(...)} —
 *       the response carries the redirect, so the next request creates a
 *       fresh session even if invalidation happens below.</li>
 *   <li>HTTP session invalidated (when configured).</li>
 *   <li>Vaadin session closed (when configured).</li>
 * </ol>
 *
 * <p>The Vaadin static APIs are isolated behind {@link VaadinLogoutGateway}
 * so this service can be unit-tested without a Vaadin runtime.
 *
 * @param <U> subject type
 */
public final class VaadinLogoutService<U> implements LogoutService {

  private final SubjectStore subjectStore;
  private final Class<U> subjectType;
  private final VaadinLogoutGateway gateway;
  private final SubjectClearingLogoutService<U> coreService;
  private final Supplier<String> targetRoute;
  private final boolean closeVaadinSessionOnLogout;
  private final boolean invalidateHttpSessionOnLogout;

  /**
   * Convenience: full-invalidate logout (close VaadinSession + invalidate
   * HttpSession) targeting {@code "/" + JCustosServiceResolver.loginRouteName()}
   * (JS-SEC-084; was a hard-coded {@code "/login"}).
   */
  public VaadinLogoutService(SubjectStore subjectStore, Class<U> subjectType) {
    this(subjectStore, subjectType, new DefaultVaadinLogoutGateway());
  }

  /**
   * Convenience constructor with a custom gateway: closes the Vaadin session,
   * invalidates the HTTP session and redirects to {@code "/" +
   * JCustosServiceResolver.loginRouteName()}, resolved at logout time
   * (JS-SEC-084, CWE-684) - an application that configured
   * {@code .loginRoute("signin")} is sent there, not to a hard-coded
   * {@code /login}.
   *
   * @param subjectStore subject store to clear
   * @param subjectType  subject type
   * @param gateway      Vaadin gateway (redirect / session handling)
   * @since 00.84.00
   */
  public VaadinLogoutService(SubjectStore subjectStore, Class<U> subjectType,
                             VaadinLogoutGateway gateway) {
    this(subjectStore, subjectType, gateway,
        () -> "/" + JCustosServiceResolver.loginRouteName(), true, true,
        new InMemorySubjectSessionRegistry());
  }

  /**
   * Full constructor.
   *
   * @param subjectStore                  subject store to clear on
   *                                      {@link LogoutScope#CurrentSession}
   * @param subjectType                   subject type token
   * @param gateway                       Vaadin gateway (redirect /
   *                                      session-invalidate seam)
   * @param targetRoute                   route to redirect to after
   *                                      logout
   * @param closeVaadinSessionOnLogout    if {@code true},
   *                                      {@link VaadinLogoutGateway#closeVaadinSession()}
   *                                      runs after subject removal
   * @param invalidateHttpSessionOnLogout if {@code true},
   *                                      {@link VaadinLogoutGateway#invalidateHttpSession()}
   *                                      runs after subject removal
   */
  public VaadinLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      VaadinLogoutGateway gateway,
      String targetRoute,
      boolean closeVaadinSessionOnLogout,
      boolean invalidateHttpSessionOnLogout) {
    this(subjectStore, subjectType, gateway, targetRoute,
        closeVaadinSessionOnLogout, invalidateHttpSessionOnLogout,
        new InMemorySubjectSessionRegistry());
  }

  /**
   * Full constructor with explicit {@link SubjectSessionRegistry}.
   *
   * @param subjectStore                  subject store to clear on
   *                                      {@link LogoutScope#CurrentSession}
   * @param subjectType                   subject type token
   * @param gateway                       Vaadin gateway
   * @param targetRoute                   route to redirect to after logout
   * @param closeVaadinSessionOnLogout    close VaadinSession flag
   * @param invalidateHttpSessionOnLogout invalidate HttpSession flag
   * @param registry                      session registry used for
   *                                      {@link LogoutScope#AllSessionsOfSubject}
   */
  public VaadinLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      VaadinLogoutGateway gateway,
      String targetRoute,
      boolean closeVaadinSessionOnLogout,
      boolean invalidateHttpSessionOnLogout,
      SubjectSessionRegistry registry) {
    this(subjectStore, subjectType, gateway, fixedRoute(targetRoute),
        closeVaadinSessionOnLogout, invalidateHttpSessionOnLogout, registry);
  }

  private static Supplier<String> fixedRoute(String targetRoute) {
    Objects.requireNonNull(targetRoute, "targetRoute");
    return () -> targetRoute;
  }

  private VaadinLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      VaadinLogoutGateway gateway,
      Supplier<String> targetRoute,
      boolean closeVaadinSessionOnLogout,
      boolean invalidateHttpSessionOnLogout,
      SubjectSessionRegistry registry) {
    this.subjectStore = Objects.requireNonNull(subjectStore, "subjectStore");
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
    this.gateway = Objects.requireNonNull(gateway, "gateway");
    this.targetRoute = Objects.requireNonNull(targetRoute, "targetRoute");
    this.closeVaadinSessionOnLogout = closeVaadinSessionOnLogout;
    this.invalidateHttpSessionOnLogout = invalidateHttpSessionOnLogout;
    this.coreService = new SubjectClearingLogoutService<>(
        subjectStore, subjectType,
        Objects.requireNonNull(registry, "registry"),
        null);
  }

  @Override
  public void logout(SubjectId subjectId, LogoutScope scope) {
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(scope, "scope");

    if (scope == LogoutScope.CurrentSession) {
      notifySessionPolicyOnLogout();
    }

    coreService.logout(subjectId, scope);

    if (scope == LogoutScope.CurrentSession) {
      clearBoundTokenCredential();
      gateway.redirectTo(targetRoute.get());
      if (invalidateHttpSessionOnLogout) {
        gateway.invalidateHttpSession();
      }
      if (closeVaadinSessionOnLogout) {
        gateway.closeVaadinSession();
      }
    }
  }

  @Override
  public void addListener(LogoutListener listener) {
    coreService.addListener(listener);
  }

  @Override
  public void removeListener(LogoutListener listener) {
    coreService.removeListener(listener);
  }

  /**
   * Best-effort notification of
   * {@link SessionPolicy#onLogout(SessionContext)} before the subject
   * is removed from the {@link SubjectStore}. The hook is purely
   * additive — it gives the policy a chance to emit a
   * {@code SESSION_INVALIDATED} audit event next to the core
   * {@code LOGOUT} audit. Failures are swallowed: a logout must never
   * be blocked because the policy or audit subsystem failed.
   */
  /**
   * R026: a {@link LogoutScope#CurrentSession} logout must also drop the bound
   * {@link TokenCredentialStore} credential (remember-me / propagation token).
   * Clearing the {@link SubjectStore} alone leaves a token credential in the
   * session that could silently re-authenticate the "logged-out" user on the
   * next request. Best-effort: a logout must never be blocked because the token
   * store is absent or its {@code clear()} failed.
   */
  private void clearBoundTokenCredential() {
    try {
      JCustosServiceResolver.findTokenCredentialStore()
          .ifPresent(TokenCredentialStore::clear);
    } catch (RuntimeException cleanupFailure) {
      // never block the logout flow
    }
  }

  private void notifySessionPolicyOnLogout() {
    try {
      Optional<U> currentSubject = subjectStore.currentSubject(subjectType);
      SessionPolicy<Object> policy = JCustosServiceResolver.sessionPolicy();
      Instant now = Instant.now();
      // JS-SEC-084: carry the HTTP session id so SessionInvalidated correlates with the login.
      SessionContext<Object> sessionContext = new SessionContext<>(
          currentSubject.orElse(null), gateway.currentSessionId(), now, now, null, Map.of());
      policy.onLogout(sessionContext);
    } catch (RuntimeException notifyFailure) {
      // never block the logout flow
    }
  }
}
