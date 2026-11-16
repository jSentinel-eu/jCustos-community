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
package eu.jsentinel.jcustos.demo.app.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.demo.app.security.permissions.DemoPermission;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.security.services.DemoSessionStoreProvider;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.policy.api.JCustosPolicies;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Eagerly initializes {@link BootstrapWiring} on Vaadin service start so the
 * setup banner (transient mode) or the file path message (persistent mode)
 * is shown immediately — without having to first navigate to {@code /login}.
 * <p>
 * <strong>V00.72:</strong> the listener also runs the new fluent bootstrap
 * once per JVM ({@link VaadinSecurity#bootstrap()} with the
 * {@link VaadinJCustosStarter#developmentDefaults()} profile), pulling the
 * {@code @JCustosAutoService}-registered SPIs through {@code ServiceLoader}
 * and printing the resulting {@link JCustosRuntime#log()} so the operator
 * sees which services are active at startup.
 */
public class BootstrapServiceInitListener implements VaadinServiceInitListener, HasLogger {

  /**
   * Name of the demo policy registered through the V00.73 sub-builder so
   * the {@code PermissionDemoCard}'s Pattern D
   * {@code SecuredUi.button(...).requiresPolicy(...)} entry has a real
   * policy to evaluate against. Exposed as a constant so the card can
   * reference it instead of duplicating the string literal.
   */
  public static final String POLICY_ADMIN_OR_EDIT = "demo.admin-or-edit";

  private static final AtomicBoolean DX_BOOTSTRAP_DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    BootstrapWiring.instance();
    if (DX_BOOTSTRAP_DONE.compareAndSet(false, true)) {
      runDxBootstrap();
    }
  }

  private static void runDxBootstrap() {
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElse(null);
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElse(null);
    if (authn == null || authz == null) {
      // Falls back to the legacy ServiceLoader path; the V00.72 bootstrap is
      // additive and not required for the demo to function.
      return;
    }
    // V00.73: typed sub-builders. .audit(...) surfaces a logging sink
    // and an in-memory ring buffer in JCustosDiagnostics; .credentials(...)
    // exposes the V00.71 password-hashing pipeline that BootstrapWiring
    // already uses internally so it shows up in JCustosRuntime.services().
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        // JS-SEC-085 (CWE-1188): a route without a security annotation is
        // denied unless it is @PublicRoute (PublicView, MyLoginView, SetupView).
        .denyByDefault(true)
        // JS-SEC-152: no stepUpRoute(...) - the demo uses no step-up policy and
        // has no step-up view; a configured route without a view fails closed.
        .audit(a -> a.ringBuffer(256).logging())
        // JS-SEC-131 (CWE-613): the session inventory is registered for the
        // per-request revocation check, so Revoke in AdminSessionsView ends
        // the session on its next request.
        .sessions(s -> s.storeBacked(DemoSessionStoreProvider.sessionStore()))
        .credentials(c -> c.hashing(PasswordHashingServices.defaults()))
        // V00.73 + V00.74: register a Policy so the PermissionDemoCard's
        // Pattern D "SecuredUi.button(...).requiresPolicy(...)" entry has a
        // real policy to evaluate against. anyRoleOrPermission() is the
        // simplest pre-built shape: allow if ADMIN or holding demo:edit.
        // Role + permission strings are derived from the project's enums
        // so a rename in either AuthorizationRole or DemoPermission lands
        // here as a compile error, not as a silent runtime miss.
        .policies(p -> p.register(JCustosPolicies.anyRoleOrPermission(
            POLICY_ADMIN_OR_EDIT,
            Set.of(AuthorizationRole.ADMIN.name()),
            Set.of(DemoPermission.DEMO_EDIT.permissionName().value()))))
        .install();
    HasLogger.staticLogger().info("{}", runtime.log());
  }
}
