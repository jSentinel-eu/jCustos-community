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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver.Restriction;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Tag;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.router.RouterLayout;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-154 (CWE-862): the one decision the authorisation listener and the start-up
 * discovery share - which restrictions apply to a navigation, and whether it is open by
 * omission.
 * <p>
 * Error views are represented by Vaadin's built-in {@link InternalServerError}: a bespoke
 * {@code HasErrorParameter} fixture would be picked up by the class-path scan of the
 * sibling Browserless tests and change their error handling.
 */
@DisplayName("RouteRestrictionResolver")
class RouteRestrictionResolverTest {

  private final RouteRestrictionResolver resolver = new RouteRestrictionResolver();

  @Test
  @DisplayName("no restriction on target or layouts: empty")
  void nothingRestricted_isEmpty() {
    assertTrue(resolver.resolve(PlainView.class, List.of(PlainLayout.class)).isEmpty());
    assertTrue(resolver.resolve(PlainView.class, List.of()).isEmpty());
    assertTrue(resolver.resolve(PlainView.class, null).isEmpty(), "null layouts count as empty");
  }

  @Test
  @DisplayName("restriction on the target only")
  void targetRestriction() {
    List<Restriction> restrictions = resolver.resolve(PermissionView.class, List.of());

    assertEquals(1, restrictions.size());
    assertSame(PermissionView.class, restrictions.get(0).source());
    assertInstanceOf(RequiresPermission.class, restrictions.get(0).annotation());
  }

  @Test
  @DisplayName("restriction on a layout applies to an unannotated target")
  void layoutRestriction() {
    List<Restriction> restrictions = resolver.resolve(PlainView.class, List.of(AdminLayout.class));

    assertEquals(1, restrictions.size());
    assertSame(AdminLayout.class, restrictions.get(0).source());
    assertInstanceOf(RequiresRole.class, restrictions.get(0).annotation());
  }

  @Test
  @DisplayName("all restrictions are returned - outermost layout first, the target last")
  void evaluationOrder_outermostFirst() {
    // Vaadin reports the chain starting with the layout that immediately wraps the target.
    List<Restriction> restrictions = resolver.resolve(
        PermissionView.class, List.of(InnerLayout.class, PlainLayout.class, AdminLayout.class));

    assertEquals(List.of(AdminLayout.class, InnerLayout.class, PermissionView.class),
        restrictions.stream().map(Restriction::source).toList());
  }

  @Test
  @DisplayName("more than one restriction on a layout raises IllegalStateException")
  void doublyRestrictedLayout_throws() {
    assertThrows(IllegalStateException.class,
        () -> resolver.resolve(PlainView.class, List.of(DoublyRestrictedLayout.class)));
  }

  @Test
  @DisplayName("open by omission: neither restricted, nor @PublicRoute, nor an error view")
  void openByOmission() {
    assertTrue(resolver.isOpenByOmission(PlainView.class, List.of()));
    assertTrue(resolver.isOpenByOmission(PlainView.class, List.of(PlainLayout.class)));

    assertFalse(resolver.isOpenByOmission(PermissionView.class, List.of()),
        "a restricted target is not open");
    assertFalse(resolver.isOpenByOmission(PlainView.class, List.of(AdminLayout.class)),
        "a target inside a restricted layout is not open");
    assertFalse(resolver.isOpenByOmission(PublicView.class, List.of()),
        "@PublicRoute is the explicit decision");
    assertFalse(resolver.isOpenByOmission(InternalServerError.class, List.of()),
        "error views are exempt from deny-by-default");
  }

  @Test
  @DisplayName("@PublicRoute on the target does not remove the restriction of a layout")
  void publicRoute_doesNotLiftLayoutRestriction() {
    List<Restriction> restrictions = resolver.resolve(PublicView.class, List.of(AdminLayout.class));

    assertEquals(1, restrictions.size(), "the layout restriction still applies");
    assertSame(AdminLayout.class, restrictions.get(0).source());
  }

  @Test
  @DisplayName("an error view is exempt from deny-by-default, a restriction on it still applies")
  void errorViewExemption() {
    assertTrue(RouteRestrictionResolver.isDenyByDefaultExempt(InternalServerError.class));
    assertFalse(RouteRestrictionResolver.isDenyByDefaultExempt(PlainView.class));
    assertEquals(1, resolver.resolve(InternalServerError.class, List.of(AdminLayout.class)).size());
  }

  @Test
  @DisplayName("layoutChains: one chain per path - the route and each alias")
  void layoutChains_perPath() {
    TestRouteRegistry registry = new TestRouteRegistry();
    registry.setRoute("reports", PlainView.class, List.of(AdminLayout.class));
    registry.setRoute("public/reports", PlainView.class, List.of());

    RouteData route = registry.getRegisteredRoutes().stream()
        .filter(r -> r.getNavigationTarget() == PlainView.class)
        .findFirst().orElseThrow();
    List<List<Class<? extends RouterLayout>>> chains =
        RouteRestrictionResolver.layoutChains(registry, route);

    assertEquals(2, chains.size(), "the route path and its alias");
    assertTrue(chains.contains(List.of(AdminLayout.class)));
    assertTrue(chains.contains(List.of()),
        "the alias without a layout is a second, unprotected way to the same view");
    assertTrue(chains.stream().anyMatch(chain -> resolver.isOpenByOmission(PlainView.class, chain)),
        "a route class is open as soon as one of its paths is");
  }

  // ── Fixtures ───────────────────────────────────────────────────

  @Tag("div")
  static class PlainView extends Component {
  }

  @Tag("div")
  @RequiresPermission("report:read")
  static class PermissionView extends Component {
  }

  @Tag("div")
  @PublicRoute
  static class PublicView extends Component {
  }

  @Tag("div")
  static class PlainLayout extends Component implements RouterLayout {
  }

  @Tag("div")
  @RequiresRole("ADMIN")
  static class AdminLayout extends Component implements RouterLayout {
  }

  @Tag("div")
  @RequiresRole("USER")
  static class InnerLayout extends Component implements RouterLayout {
  }

  @Tag("div")
  @RequiresRole("ADMIN")
  @RequiresPermission("report:read")
  static class DoublyRestrictedLayout extends Component implements RouterLayout {
  }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override public VaadinContext getContext() { return null; }
  }
}
