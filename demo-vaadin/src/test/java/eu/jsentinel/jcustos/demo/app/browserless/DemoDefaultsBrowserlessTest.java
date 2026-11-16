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
package eu.jsentinel.jcustos.demo.app.browserless;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapServiceInitListener;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.services.DemoSessionStoreProvider;
import eu.jsentinel.jcustos.demo.app.views.PublicView;
import eu.jsentinel.jcustos.demo.app.views.SetupView;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerListener;
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.server.VaadinService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1188), JS-SEC-131 and JS-SEC-155: the demo's own bootstrap - run as
 * shipped - turns deny-by-default on and registers the session inventory for the
 * per-request revocation check; every route is restricted or {@code @PublicRoute}; the
 * version-drift listener also covers WebSocket-only push messages.
 */
@DisplayName("JS-SEC-137 / JS-SEC-131 / JS-SEC-155 — the demo's bootstrap defaults")
class DemoDefaultsBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void runTheDemoBootstrap() throws Exception {
    System.setProperty("security.bootstrap.mode", "TRANSIENT_CONSOLE");
    var wiring = BootstrapWiring.class.getDeclaredField("current");
    wiring.setAccessible(true);
    wiring.set(null, null);
    var done = BootstrapServiceInitListener.class.getDeclaredField("DX_BOOTSTRAP_DONE");
    done.setAccessible(true);
    ((AtomicBoolean) done.get(null)).set(false);
    JCustosServiceResolver.resetAll();
    new BootstrapServiceInitListener().serviceInit(null);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    System.clearProperty("security.bootstrap.mode");
  }

  @Test
  @DisplayName("the bootstrap turns deny-by-default on and registers the session inventory")
  void bootstrapIsFailClosed() {
    assertTrue(JCustosServiceResolver.isDenyByDefault(), "JS-SEC-085");
    assertSame(DemoSessionStoreProvider.sessionStore(),
        VaadinSessionRevocation.findSessionStore().orElseThrow(), "JS-SEC-131");
  }

  @Test
  @DisplayName("every route of the demo is restricted or @PublicRoute; the public pages stay reachable")
  void noRouteIsOpenByOmission() {
    RouteRestrictionResolver resolver = new RouteRestrictionResolver();
    List<RouteData> routes = RouteConfiguration.forApplicationScope().getAvailableRoutes().stream()
        .filter(r -> r.getNavigationTarget().getPackageName().startsWith("eu.jsentinel.jcustos.demo.app"))
        // the application's routes, not the fixtures other tests register
        .filter(r -> !r.getNavigationTarget().getProtectionDomain().getCodeSource()
            .getLocation().getPath().contains("test-classes"))
        .toList();
    assertFalse(routes.isEmpty());
    assertEquals(List.of(), routes.stream()
        .filter(r -> resolver.isOpenByOmission(r.getNavigationTarget(), r.getParentLayouts()))
        .map(r -> r.getNavigationTarget().getSimpleName())
        .toList());

    assertTrue(navigate(PublicView.class) instanceof PublicView);
    // without an administrator the login view forwards to the setup - both are public
    assertTrue(navigate(SetupView.class) instanceof SetupView);
  }

  @Test
  @DisplayName("the version-drift listener is registered as request handler and as request interceptor (push)")
  void driftCheckCoversPush() {
    VaadinService service = VaadinService.getCurrent();
    assertTrue(StreamSupport.stream(service.getVaadinRequestInterceptors().spliterator(), false)
            .anyMatch(JCustosVersionEnforcerListener.class::isInstance),
        "without the interceptor a WebSocket-only push message bypasses the drift check");
    assertTrue(StreamSupport.stream(service.getRequestHandlers().spliterator(), false)
        .anyMatch(JCustosVersionEnforcerListener.class::isInstance));
  }
}
