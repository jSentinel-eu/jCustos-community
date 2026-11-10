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
package eu.jsentinel.jcustos.authorization.impl.failclosed.registered;

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
 * Control for JS-SEC-152: with the login route and the step-up route registered, a denied
 * navigation is rerouted there exactly as before the fail-closed post-condition.
 * <p>
 * The two routes carry names of their own instead of {@code "login"} / {@code "step-up"}:
 * the sibling tests of this module scan the whole class path, and a second route under
 * {@code "step-up"} would collide with theirs.
 */
@DisplayName("JS-SEC-152 - with registered routes a denial is rerouted as before")
@ViewPackages
class RegisteredRerouteTargetBrowserlessTest extends BrowserlessTest {

  private static final String STEP_UP_POLICY = "fc-registered.step-up";

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
    JCustosServiceResolver.setLoginRouteName("fc-registered/signin");
    JCustosServiceResolver.setStepUpRouteName("fc-registered/verify");

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
  @DisplayName("anonymous navigation to a @RequiresRole view is rerouted to the login route")
  void anonymous_isReroutedToTheLoginRoute() {
    UI.getCurrent().navigate("fc-registered/admin");

    assertEquals(0, AdminView.INSTANCES.get());
    assertInstanceOf(SigninView.class, activeView());
    assertEquals("AdminView", audit.single(AccessDenied.class).route());
  }

  @Test
  @DisplayName("a StepUpRequired policy is rerouted to the step-up route")
  void stepUpRequired_isReroutedToTheStepUpRoute() {
    SubjectStores.subjectStore().setCurrentSubject("user", String.class);

    UI.getCurrent().navigate("fc-registered/mfa");

    assertEquals(0, MfaView.INSTANCES.get());
    assertInstanceOf(VerifyView.class, activeView());
    assertEquals("MfaView", audit.single(StepUpChallenged.class).route());
  }

  @Test
  @DisplayName("an authenticated subject without the role is sent to the error view (Forbidden, unchanged)")
  void forbidden_endsInErrorView() {
    SubjectStores.subjectStore().setCurrentSubject("user", String.class);

    UI.getCurrent().navigate("fc-registered/admin");

    assertEquals(0, AdminView.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeView());
    assertTrue(audit.single(AccessDenied.class).reason().startsWith("Forbidden"));
  }

  @Test
  @DisplayName("a subject with the role reaches the view")
  void admin_reachesTheView() {
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);

    UI.getCurrent().navigate("fc-registered/admin");

    assertEquals(1, AdminView.INSTANCES.get());
    assertInstanceOf(AdminView.class, activeView());
    assertTrue(RouteConfiguration.forApplicationScope().getRoute("fc-registered/signin").isPresent());
  }

  @Route("fc-registered/signin")
  public static class SigninView extends Div {
  }

  @Route("fc-registered/verify")
  public static class VerifyView extends Div {
  }

  @Route("fc-registered/admin")
  @RequiresRole("ADMIN")
  public static class AdminView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public AdminView() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route("fc-registered/mfa")
  @RequiresPolicy(STEP_UP_POLICY)
  public static class MfaView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public MfaView() {
      INSTANCES.incrementAndGet();
    }
  }
}
