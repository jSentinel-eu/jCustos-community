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
package eu.jsentinel.jcustos.authorization.impl.failclosed.unregistered;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.StepUpChallenged;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.impl.StubAuthorizationService;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-152 (CWE-636, CWE-285): {@code BeforeEvent.rerouteTo(String)} with a route that is
 * not registered is a no-op in Vaadin. A denied navigation - {@code Unauthenticated} to the
 * login route, {@code StepUpRequired} to the step-up route - used to fall through to the
 * protected view, which was instantiated and rendered while the audit trail said
 * {@code AccessDenied}.
 * <p>
 * {@link ViewPackages} restricts the route registry to the fixtures of this package, so
 * neither {@code "login"} nor {@code "step-up"} is registered, and no {@code LoginListener}
 * is on the class path of this module.
 */
@DisplayName("JS-SEC-152 - a denial whose reroute target is not registered ends in the error view")
@ViewPackages
class UnregisteredRerouteTargetBrowserlessTest extends BrowserlessTest {

  private static final String STEP_UP_POLICY = "fc-unregistered.step-up";

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    LoginListeners.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);

    StubAuthorizationService.clear();
    StubAuthorizationService.put("admin", Set.of(new RoleName("ADMIN")), Set.of());
    StubAuthorizationService.put("user", Set.of(new RoleName("USER")), Set.of());

    InMemoryPolicyRegistry policies = new InMemoryPolicyRegistry();
    policies.register(Policy.named(STEP_UP_POLICY)
        .stepUpRequiredIf(c -> true, PolicyDecision.StepUpMethod.MFA, "needs mfa")
        .build());
    JCustosServiceResolver.setPolicyRegistry(policies);

    AdminView.INSTANCES.set(0);
    MfaView.INSTANCES.set(0);
    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    LoginListeners.reset();
    StubAuthorizationService.clear();
  }

  private static HasElement activeView() {
    List<HasElement> chain = UI.getCurrent().getInternals().getActiveRouterTargetsChain();
    assertFalse(chain.isEmpty(), "a view must be active after the navigation");
    return chain.get(0);
  }

  @Test
  @DisplayName("precondition: neither the login route nor the step-up route is registered, no LoginListener")
  void precondition_noRerouteTargets() {
    RouteConfiguration routes = RouteConfiguration.forApplicationScope();
    assertTrue(routes.getRoute(JCustosServiceResolver.loginRouteName()).isEmpty());
    assertTrue(routes.getRoute(JCustosServiceResolver.stepUpRouteName()).isEmpty());
    assertTrue(LoginListeners.findLoginListener().isEmpty());
  }

  @Test
  @DisplayName("anonymous navigation to a @RequiresRole view ends in the error view; the view is never instantiated")
  void anonymous_withoutLoginRoute_endsInErrorView() {
    UI.getCurrent().navigate("fc-unregistered/admin");

    assertEquals(0, AdminView.INSTANCES.get(),
        "the protected view must never be instantiated for a denied visitor");
    assertInstanceOf(InternalServerError.class, activeView(),
        "a denial that cannot be rerouted must end in the error view");
    AccessDenied denied = audit.single(AccessDenied.class);
    assertEquals("AdminView", denied.route());
  }

  @Test
  @DisplayName("a StepUpRequired policy without a step-up route ends in the error view; the view is never instantiated")
  void stepUpRequired_withoutStepUpRoute_endsInErrorView() {
    SubjectStores.subjectStore().setCurrentSubject("user", String.class);

    UI.getCurrent().navigate("fc-unregistered/mfa");

    assertEquals(0, MfaView.INSTANCES.get(),
        "a subject that still owes the step-up must never get the view instantiated");
    assertInstanceOf(InternalServerError.class, activeView());
    assertEquals("MfaView", audit.single(StepUpChallenged.class).route());
  }

  @Test
  @DisplayName("control: a subject with the role still reaches the view")
  void admin_reachesTheView() {
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);

    UI.getCurrent().navigate("fc-unregistered/admin");

    assertEquals(1, AdminView.INSTANCES.get());
    assertInstanceOf(AdminView.class, activeView());
  }

  @Route("fc-unregistered/admin")
  @RequiresRole("ADMIN")
  public static class AdminView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public AdminView() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route("fc-unregistered/mfa")
  @RequiresPolicy(STEP_UP_POLICY)
  public static class MfaView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public MfaView() {
      INSTANCES.incrementAndGet();
    }
  }
}
