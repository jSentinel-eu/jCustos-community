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
package eu.jsentinel.jcustos.starter.routes;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Tag;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.router.RouterLayout;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-154 (CWE-862): the start-up discovery has to classify a route the way the
 * authorisation listener treats it at run time. It used to look at the navigation target
 * only, so a route protected through its {@code RouterLayout} was reported as
 * un-annotated (and denied by deny-by-default), while a policy referenced from a layout
 * or a composed annotation escaped the cross-check.
 * <p>
 * Runs against a real route registry filled through {@code setRoute(...)}; no
 * {@code VaadinService} is needed.
 */
@DisplayName("JS-SEC-154 - the start-up discovery uses the listener's decision")
class VaadinRouterSecureRouteDiscoveryLayoutTest {

  private TestRouteRegistry registry;
  private VaadinRouterSecureRouteDiscovery discovery;

  @BeforeEach
  void registerRoutes() {
    registry = new TestRouteRegistry();
    registry.setRoute("open", OpenView.class, List.of());
    registry.setRoute("open-in-layout", OpenInLayoutView.class, List.of(PlainLayout.class));
    registry.setRoute("public", PublicView.class, List.of());
    registry.setRoute("admin/users", UsersView.class, List.of(AdminLayout.class));
    registry.setRoute("admin/nested", NestedView.class, List.of(PlainLayout.class, AdminLayout.class));
    registry.setRoute("composed", ComposedView.class, List.of());
    registry.setRoute("direct", DirectView.class, List.of());
    registry.setRoute("reports", ReportsView.class, List.of(AdminLayout.class));
    registry.setRoute("public/reports", ReportsView.class, List.of());
    registry.setRoute("dual", DualView.class, List.of());
    registry.setRoute("area/a", AreaAView.class, List.of(PolicyLayout.class));
    registry.setRoute("area/b", AreaBView.class, List.of(PolicyLayout.class));
    registry.setRoute("composed-policy", ComposedPolicyView.class, List.of());
    registry.setRoute("direct-policy", DirectPolicyView.class, List.of());
    registry.setRoute("authenticated", AuthenticatedAreaView.class, List.of(AuthenticatedLayout.class));
    discovery = new VaadinRouterSecureRouteDiscovery(() -> registry);
  }

  @Test
  @DisplayName("un-annotated routes: exactly the routes the listener lets pass by omission")
  void unannotatedRoutes() {
    Set<String> unannotated = discovery.discoverUnannotatedRouteNames().collect(Collectors.toSet());

    assertEquals(Set.of("OpenView", "OpenInLayoutView", "ReportsView"), unannotated);
  }

  @Test
  @DisplayName("a route protected through its layout is not reported as un-annotated")
  void layoutProtectedRoute_isAnnotated() {
    List<String> unannotated = discovery.discoverUnannotatedRouteNames().toList();

    assertFalse(unannotated.contains("UsersView"),
        "@RequiresRole on AdminLayout protects the child route at run time");
    assertFalse(unannotated.contains("NestedView"),
        "a restriction on an outer layout protects the route as well");
  }

  @Test
  @DisplayName("a route protected through a composed annotation is not reported as un-annotated")
  void composedAnnotationRoute_isAnnotated() {
    assertFalse(discovery.discoverUnannotatedRouteNames().toList().contains("ComposedView"));
  }

  @Test
  @DisplayName("a route with an alias outside the restricted layout is reported: one path is open")
  void aliasOutsideTheRestrictedLayout_isReported() {
    assertTrue(discovery.discoverUnannotatedRouteNames().toList().contains("ReportsView"),
        "'public/reports' reaches the same view without AdminLayout");
  }

  @Test
  @DisplayName("@PublicRoute and a doubly restricted route are not reported; discovery is not aborted")
  void publicAndMisconfiguredRoutes() {
    List<String> unannotated = discovery.discoverUnannotatedRouteNames().toList();

    assertFalse(unannotated.contains("PublicView"));
    assertFalse(unannotated.contains("DualView"),
        "two restrictions fail at navigation time - annotated, not a deny-by-default finding");
  }

  @Test
  @DisplayName("every classification equals RouteRestrictionResolver.isOpenByOmission over the route's paths")
  void sameDecisionAsTheListener() {
    RouteRestrictionResolver resolver = new RouteRestrictionResolver();
    Set<String> unannotated = discovery.discoverUnannotatedRouteNames().collect(Collectors.toSet());

    for (RouteData route : registry.getRegisteredRoutes()) {
      Class<?> target = route.getNavigationTarget();
      if (target == DualView.class) {
        continue; // raises at navigation time, see publicAndMisconfiguredRoutes
      }
      boolean open = RouteRestrictionResolver.layoutChains(registry, route).stream()
          .anyMatch(chain -> resolver.isOpenByOmission(target, chain));
      assertEquals(open, unannotated.contains(target.getSimpleName()),
          "start-up classification of " + target.getSimpleName()
              + " must equal the decision the listener enforces");
    }
  }

  @Test
  @DisplayName("policy names: @SecureRoute on the target, on a layout and as a composed annotation - each once")
  void policyNames() {
    List<String> policies = discovery.discoverPolicyNames().toList();

    assertEquals(Set.of("direct.policy", "layout.policy", "composed.policy"), Set.copyOf(policies));
    assertEquals(3, policies.size(),
        "the policy of a layout shared by two routes is reported once");
  }

  @Test
  @DisplayName("constraint-less @SecureRoute on a layout is reported with the layout's name")
  void constraintlessSecureRouteOnLayout() {
    assertEquals(List.of("AuthenticatedLayout"),
        discovery.discoverConstraintlessRouteNames().toList());
  }

  @Test
  @DisplayName("an unreadable registry: routesAvailable() is false and every discovery is empty")
  void unreadableRegistry() {
    VaadinRouterSecureRouteDiscovery unavailable = new VaadinRouterSecureRouteDiscovery(() -> {
      throw new IllegalStateException("no VaadinService");
    });

    assertFalse(unavailable.routesAvailable());
    assertTrue(unavailable.discoverUnannotatedRouteNames().toList().isEmpty());
    assertTrue(unavailable.discoverPolicyNames().toList().isEmpty());
    assertTrue(unavailable.discoverConstraintlessRouteNames().toList().isEmpty());
    assertTrue(discovery.routesAvailable());
  }

  // ── Fixtures ───────────────────────────────────────────────────

  @Tag("div") static class OpenView extends Component { }

  @Tag("div") static class OpenInLayoutView extends Component { }

  @Tag("div") @PublicRoute static class PublicView extends Component { }

  @Tag("div") static class UsersView extends Component { }

  @Tag("div") static class NestedView extends Component { }

  @Tag("div") static class ReportsView extends Component { }

  @Tag("div") @RequiresRole("ADMIN") static class DirectView extends Component { }

  @RequiresRole("ADMIN")
  @Retention(RetentionPolicy.RUNTIME)
  @interface AdminOnly { }

  @Tag("div") @AdminOnly static class ComposedView extends Component { }

  @Tag("div") @RequiresRole("ADMIN") @RequiresPermission("x:y") static class DualView extends Component { }

  @Tag("div") static class AreaAView extends Component { }

  @Tag("div") static class AreaBView extends Component { }

  @SecureRoute(policy = "composed.policy")
  @Retention(RetentionPolicy.RUNTIME)
  @interface PolicyArea { }

  @Tag("div") @PolicyArea static class ComposedPolicyView extends Component { }

  @Tag("div") @SecureRoute(policy = "direct.policy") static class DirectPolicyView extends Component { }

  @Tag("div") static class AuthenticatedAreaView extends Component { }

  @Tag("div") static class PlainLayout extends Component implements RouterLayout { }

  @Tag("div") @RequiresRole("ADMIN") static class AdminLayout extends Component implements RouterLayout { }

  @Tag("div") @SecureRoute(policy = "layout.policy") static class PolicyLayout extends Component implements RouterLayout { }

  @Tag("div") @SecureRoute static class AuthenticatedLayout extends Component implements RouterLayout { }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override public VaadinContext getContext() { return null; }
  }
}
