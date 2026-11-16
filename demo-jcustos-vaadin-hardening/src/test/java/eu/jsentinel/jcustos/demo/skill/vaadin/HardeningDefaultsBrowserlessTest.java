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
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JCustosBootstrapInitListener;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.PublicHomeView;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerListener;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.server.VaadinService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1188), JS-SEC-124, JS-SEC-152 and JS-SEC-155: the hardening layer
 * boots in PRODUCTION with deny-by-default, its configuration produces no error finding
 * - a logout service is registered, the login route resolves, no step-up route without a
 * view is configured - and the version-drift check covers WebSocket-only push messages.
 */
@DisplayName("JS-SEC-137 — hardening: PRODUCTION, deny-by-default, no error finding, drift checked on push")
class HardeningDefaultsBrowserlessTest extends BrowserlessTest {

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() {
    SkillDemoTestSupport.runDemoBootstrap();
  }

  @AfterEach
  void tearDown() {
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the bootstrap runs the PRODUCTION profile with deny-by-default and reports no error")
  void productionWithoutErrors() {
    JCustosRuntime runtime = JCustosBootstrapInitListener.currentRuntime();
    assertNotNull(runtime, "the bootstrap must have run");

    assertEquals(JCustosBootstrapMode.PRODUCTION, runtime.mode());
    assertTrue(JCustosServiceResolver.isDenyByDefault());
    List<String> errors = runtime.warnings().stream()
        .filter(w -> w.severity() == Severity.ERROR)
        .map(JCustosBootstrapWarning::code)
        .toList();
    assertEquals(List.of(), errors, "PRODUCTION reports these as errors: " + runtime.warnings());
    List<String> codes = runtime.warnings().stream().map(JCustosBootstrapWarning::code).toList();
    assertFalse(codes.contains("logout/missing-service"), codes.toString());
    assertFalse(codes.contains("authorization/allow-by-omission"), codes.toString());
    assertFalse(codes.contains("vaadin/login-route-unresolved"), codes.toString());
  }

  @Test
  @DisplayName("every route is restricted or @PublicRoute, and the public pages stay reachable")
  void routesUnderDenyByDefault() {
    RouteRestrictionResolver resolver = new RouteRestrictionResolver();
    List<RouteData> routes = RouteConfiguration.forApplicationScope().getAvailableRoutes().stream()
        .filter(r -> r.getNavigationTarget().getPackageName().startsWith(getClass().getPackageName()))
        .toList();
    assertFalse(routes.isEmpty());
    assertEquals(List.of(), routes.stream()
        .filter(r -> resolver.isOpenByOmission(r.getNavigationTarget(), r.getParentLayouts()))
        .map(r -> r.getNavigationTarget().getSimpleName())
        .toList());

    assertTrue(navigate(PublicHomeView.class) instanceof PublicHomeView);
  }

  @Test
  @DisplayName("the version-drift listener is registered as request handler and as request interceptor (push)")
  void driftCheckCoversPush() {
    VaadinService service = VaadinService.getCurrent();
    assertTrue(StreamSupport.stream(service.getVaadinRequestInterceptors().spliterator(), false)
            .anyMatch(JCustosVersionEnforcerListener.class::isInstance),
        "without the interceptor a WebSocket-only push message bypasses the drift check (JS-SEC-155)");
    assertTrue(StreamSupport.stream(service.getRequestHandlers().spliterator(), false)
            .anyMatch(JCustosVersionEnforcerListener.class::isInstance),
        "the UIDL request handler (JS-SEC-082)");
  }
}
