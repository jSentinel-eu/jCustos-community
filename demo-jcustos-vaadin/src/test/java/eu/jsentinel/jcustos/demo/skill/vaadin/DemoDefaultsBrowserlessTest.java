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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.DashboardView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.PublicHomeView;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.vaadin.VaadinLogoutService;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1188, CWE-798) and JS-SEC-152 / JS-SEC-124: the reference defaults the
 * demo ships with. Deny-by-default is on and every route is either restricted or
 * declared public; anonymous visitors still reach the public pages; a logout service is
 * registered; no account with a publicly known password exists unless the development
 * switch is set.
 */
@DisplayName("JS-SEC-137 — the demo's reference defaults are fail-closed")
class DemoDefaultsBrowserlessTest extends BrowserlessTest {

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() {
    System.clearProperty(InMemoryUserDirectory.INSECURE_DEMO_ACCOUNTS_PROPERTY);
    SkillDemoTestSupport.runDemoBootstrap();
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
  }

  @AfterEach
  void tearDown() {
    System.clearProperty(InMemoryUserDirectory.INSECURE_DEMO_ACCOUNTS_PROPERTY);
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the bootstrap turns deny-by-default on and registers a logout service")
  void bootstrapIsFailClosed() {
    assertTrue(JCustosServiceResolver.isDenyByDefault(),
        "a route without a security annotation must be denied (JS-SEC-085)");
    LogoutService logout = JCustosServiceResolver.logoutService();
    assertInstanceOf(VaadinLogoutService.class, logout,
        "the layout's Sign-out button needs the registered service (JS-SEC-124)");
  }

  @Test
  @DisplayName("every route of the demo is restricted or declared @PublicRoute - none is open by omission")
  void noRouteIsOpenByOmission() {
    RouteRestrictionResolver resolver = new RouteRestrictionResolver();
    List<RouteData> routes = RouteConfiguration.forApplicationScope().getAvailableRoutes().stream()
        .filter(r -> r.getNavigationTarget().getPackageName().startsWith(getClass().getPackageName()))
        .toList();
    assertFalse(routes.isEmpty(), "the demo's routes must be registered");
    List<String> open = routes.stream()
        .filter(r -> resolver.isOpenByOmission(r.getNavigationTarget(), r.getParentLayouts()))
        .map(r -> r.getNavigationTarget().getSimpleName())
        .toList();
    assertEquals(List.of(), open);
  }

  @Test
  @DisplayName("under deny-by-default an anonymous visitor reaches the public home and the login view")
  void publicPagesStayReachable() {
    assertTrue(navigate(PublicHomeView.class) instanceof PublicHomeView);
    assertTrue(navigate(MyLoginView.class) instanceof MyLoginView);
  }

  @Test
  @DisplayName("JS-SEC-158: a signed-in subject without USER is sent from the dashboard to the public home, not to the error view")
  void dashboardWithoutUserRoleLandsOnThePublicHome() {
    navigate(PublicHomeView.class);
    SubjectStores.subjectStore().setCurrentSubject(
        new User(5L, "Admin only", EnumSet.of(AuthorizationRole.ADMIN)), User.class);

    UI.getCurrent().navigate(DashboardView.class);

    assertInstanceOf(PublicHomeView.class, getCurrentView(),
        "the denial must name a view the subject may see, never the dashboard itself");
  }

  @Test
  @DisplayName("an anonymous visit to the dashboard ends on the login view")
  void dashboardNeedsLogin() {
    try {
      navigate(DashboardView.class);
    } catch (IllegalArgumentException | AssertionError rerouted) {
      // the harness reports the reroute away from the requested target
    }
    assertInstanceOf(MyLoginView.class, getCurrentView());
    assertTrue(SubjectStores.subjectStore().currentSubject(User.class).isEmpty());
  }

  @Test
  @DisplayName("no account with a publicly known password exists by default")
  void noDemoAccountsByDefault() {
    InMemoryUserDirectory shipped = new InMemoryUserDirectory();

    assertEquals(0L, shipped.all().count());
    assertTrue(shipped.findByCredentials(new Credentials("admin", "admin")).isEmpty());
    assertTrue(shipped.findByCredentials(new Credentials("user", "user")).isEmpty());
  }

  @Test
  @DisplayName("the development switch creates the demo accounts, hashed through the configured pipeline")
  void developmentSwitchSeedsTheAccounts() {
    System.setProperty(InMemoryUserDirectory.INSECURE_DEMO_ACCOUNTS_PROPERTY, "true");
    InMemoryUserDirectory seeded = new InMemoryUserDirectory();

    assertTrue(seeded.findByCredentials(new Credentials("admin", "admin")).isPresent());
    assertTrue(seeded.hashingService() instanceof ConfiguredHashingService);
  }
}
