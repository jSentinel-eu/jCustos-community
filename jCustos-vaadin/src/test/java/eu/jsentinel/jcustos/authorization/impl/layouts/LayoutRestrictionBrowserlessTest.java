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
package eu.jsentinel.jcustos.authorization.impl.layouts;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.impl.StubAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.ParentLayout;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouterLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-154 (CWE-862): a restriction declared on a {@link RouterLayout} or as a composed
 * annotation used to be ignored - the listener scanned only the navigation target, and the
 * scanner only annotations that carry {@code @JCustosAnnotation} directly. An anonymous
 * visitor who opened a child route of {@code @RequiresRole("ADMIN") AdminLayout} got the
 * layout and the view.
 * <p>
 * Drives the real {@code AuthorizationListener} through Browserless navigation; the route
 * registry holds only the fixtures of this package.
 */
@DisplayName("JS-SEC-154 - restrictions on router layouts and composed annotations are enforced")
@ViewPackages
class LayoutRestrictionBrowserlessTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    LoginListeners.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setLoginRouteName("lr/signin");

    StubAuthorizationService.clear();
    StubAuthorizationService.put("user", Set.of(new RoleName("USER")), Set.of());
    StubAuthorizationService.put("reader",
        Set.of(new RoleName("USER")), Set.of(new PermissionName("report:read")));
    StubAuthorizationService.put("admin", Set.of(new RoleName("ADMIN")), Set.of());
    StubAuthorizationService.put("auditor",
        Set.of(new RoleName("ADMIN")), Set.of(new PermissionName("report:read")));

    AdminLayout.INSTANCES.set(0);
    ChildView.INSTANCES.set(0);
    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    LoginListeners.reset();
    StubAuthorizationService.clear();
  }

  private static List<HasElement> activeChain() {
    List<HasElement> chain = UI.getCurrent().getInternals().getActiveRouterTargetsChain();
    assertFalse(chain.isEmpty(), "a view must be active after the navigation");
    return chain;
  }

  private static void signIn(String subject) {
    SubjectStores.subjectStore().setCurrentSubject(subject, String.class);
  }

  // ── restriction on the layout ──────────────────────────────────

  @Test
  @DisplayName("route with an annotated layout: an anonymous visitor is denied - neither layout nor view is instantiated")
  void annotatedLayout_anonymousIsDenied() {
    UI.getCurrent().navigate("lr/child");

    assertEquals(0, ChildView.INSTANCES.get(), "the child view must never be instantiated");
    assertEquals(0, AdminLayout.INSTANCES.get(), "the restricted layout must never be instantiated");
    assertInstanceOf(SigninView.class, activeChain().get(0),
        "Unauthenticated from the layout restriction is rerouted to the login route");
    assertEquals("ChildView", audit.single(AccessDenied.class).route());
  }

  @Test
  @DisplayName("route with an annotated layout: an authenticated subject without the role is denied")
  void annotatedLayout_wrongRoleIsDenied() {
    signIn("user");

    UI.getCurrent().navigate("lr/child");

    assertEquals(0, ChildView.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeChain().get(0));
    assertTrue(audit.single(AccessDenied.class).reason().startsWith("Forbidden"));
  }

  @Test
  @DisplayName("route with an annotated layout: a subject with the role is granted - one AccessGranted")
  void annotatedLayout_roleIsGranted() {
    signIn("admin");

    UI.getCurrent().navigate("lr/child");

    List<HasElement> chain = activeChain();
    assertInstanceOf(ChildView.class, chain.get(0));
    assertInstanceOf(AdminLayout.class, chain.get(1), "the view is rendered inside its layout");
    assertEquals("ChildView", audit.single(AccessGranted.class).route());
    assertTrue(audit.events().stream().noneMatch(AccessDenied.class::isInstance));
  }

  @Test
  @DisplayName("a restriction on an outer layout reaches a route nested through @ParentLayout")
  void outerLayout_restrictionReachesNestedRoute() {
    UI.getCurrent().navigate("lr/nested");
    assertInstanceOf(SigninView.class, activeChain().get(0));

    signIn("admin");
    UI.getCurrent().navigate("lr/nested");
    assertInstanceOf(NestedView.class, activeChain().get(0));
  }

  @Test
  @DisplayName("@PublicRoute on the target does not lift the restriction of its layout")
  void publicRouteOnTarget_doesNotLiftLayoutRestriction() {
    UI.getCurrent().navigate("lr/public-child");
    assertInstanceOf(SigninView.class, activeChain().get(0),
        "@PublicRoute only opts an unrestricted target out of deny-by-default");

    signIn("admin");
    UI.getCurrent().navigate("lr/public-child");
    assertInstanceOf(PublicChildView.class, activeChain().get(0));
  }

  // ── layout AND target ──────────────────────────────────────────

  @Test
  @DisplayName("layout and target restricted: the layout grants, the target denies - denied")
  void layoutAndTarget_targetDenies() {
    signIn("admin"); // has ADMIN for the layout, lacks report:read for the view

    UI.getCurrent().navigate("lr/report");

    assertInstanceOf(InternalServerError.class, activeChain().get(0));
    assertEquals(1, audit.events().stream().filter(AccessDenied.class::isInstance).count());
    assertTrue(audit.events().stream().noneMatch(AccessGranted.class::isInstance),
        "a granting layout restriction must not be audited as a granted navigation");
  }

  @Test
  @DisplayName("layout and target restricted: the target would grant, the layout denies - denied")
  void layoutAndTarget_layoutDenies() {
    signIn("reader"); // has report:read for the view, lacks ADMIN for the layout

    UI.getCurrent().navigate("lr/report");

    assertInstanceOf(InternalServerError.class, activeChain().get(0));
    assertTrue(audit.events().stream().noneMatch(AccessGranted.class::isInstance));
  }

  @Test
  @DisplayName("layout and target restricted: both grant - granted with a single AccessGranted")
  void layoutAndTarget_bothGrant() {
    signIn("auditor");

    UI.getCurrent().navigate("lr/report");

    assertInstanceOf(ReportView.class, activeChain().get(0));
    assertEquals("ReportView", audit.single(AccessGranted.class).route());
  }

  // ── composed annotation ────────────────────────────────────────

  @Test
  @DisplayName("composed @AdminOnly on a route: anonymous is denied, a subject with the role is granted")
  void composedAnnotation_isEnforced() {
    UI.getCurrent().navigate("lr/composed");
    assertInstanceOf(SigninView.class, activeChain().get(0));

    signIn("user");
    UI.getCurrent().navigate("lr/composed");
    assertInstanceOf(InternalServerError.class, activeChain().get(0));

    signIn("admin");
    UI.getCurrent().navigate("lr/composed");
    assertInstanceOf(ComposedView.class, activeChain().get(0));
  }

  // ── unchanged behaviour ────────────────────────────────────────

  @Test
  @DisplayName("a route in an unrestricted layout stays open by omission - no audit event")
  void unrestrictedLayout_staysOpen() {
    UI.getCurrent().navigate("lr/open");

    assertInstanceOf(OpenView.class, activeChain().get(0));
    assertEquals(0, audit.events().size());
  }

  @Test
  @DisplayName("deny-by-default: a route protected only by its layout is not 'un-annotated'")
  void denyByDefault_layoutRestrictionCountsAsAnnotated() {
    JCustosServiceResolver.setDenyByDefault(true);
    signIn("admin");

    UI.getCurrent().navigate("lr/child");

    assertInstanceOf(ChildView.class, activeChain().get(0),
        "deny-by-default must not deny a route whose layout restriction granted");
  }

  @Test
  @DisplayName("deny-by-default: a route in an unrestricted layout is denied")
  void denyByDefault_unrestrictedLayoutIsDenied() {
    JCustosServiceResolver.setDenyByDefault(true);

    UI.getCurrent().navigate("lr/open");

    assertInstanceOf(InternalServerError.class, activeChain().get(0));
    assertEquals("OpenView", audit.single(AccessDenied.class).route());
  }

  // ── Fixtures ───────────────────────────────────────────────────

  @RequiresRole("ADMIN")
  public static class AdminLayout extends Div implements RouterLayout {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public AdminLayout() {
      INSTANCES.incrementAndGet();
    }
  }

  /** No restriction of its own; nested in the restricted layout. */
  @ParentLayout(AdminLayout.class)
  public static class InnerLayout extends Div implements RouterLayout {
  }

  public static class OpenLayout extends Div implements RouterLayout {
  }

  @Route(value = "lr/child", layout = AdminLayout.class)
  public static class ChildView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public ChildView() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route(value = "lr/nested", layout = InnerLayout.class)
  public static class NestedView extends Div {
  }

  @PublicRoute
  @Route(value = "lr/public-child", layout = AdminLayout.class)
  public static class PublicChildView extends Div {
  }

  @RequiresPermission("report:read")
  @Route(value = "lr/report", layout = AdminLayout.class)
  public static class ReportView extends Div {
  }

  @RequiresRole("ADMIN")
  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  public @interface AdminOnly {
  }

  @AdminOnly
  @Route("lr/composed")
  public static class ComposedView extends Div {
  }

  @Route(value = "lr/open", layout = OpenLayout.class)
  public static class OpenView extends Div {
  }

  @Route("lr/signin")
  public static class SigninView extends Div {
  }
}
