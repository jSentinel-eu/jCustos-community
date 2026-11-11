/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.diagnostics.RouteNameCheck;
import eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockService;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.di.Instantiator;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.server.RouteRegistry;
import com.vaadin.flow.server.ServiceException;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.VaadinServletService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-152 (CWE-636) and JS-SEC-024 (CWE-862): what the route checks of
 * {@code VaadinSecurity.bootstrap().install()} see when the bootstrap runs where
 * applications run it - inside {@link VaadinServiceInitListener#serviceInit}.
 *
 * <p>The question this test answers: is a {@link VaadinService} current during
 * {@code serviceInit}? If it were not, {@code RouteConfiguration.forApplicationScope()} would
 * fail, {@link RouteNameCheck} would answer {@code UNAVAILABLE} and the deny-by-default
 * discovery would report {@code discovery-unavailable} in every real deployment. It is
 * current: {@code VaadinService.init()} calls its init listeners inside
 * {@code runWithServiceContext}, "to allow service init listeners and DI to use thread
 * local access to e.g. application scoped route registry".
 *
 * <p>Nothing is simulated around the service: {@code VaadinServlet.init} creates a real
 * {@code VaadinServletService}, {@code VaadinService.init()} creates the real
 * {@code ServiceInitEvent} and calls the listener. The servlet registers the routes before
 * it initialises the service, which is the order of a servlet container - Vaadin's
 * {@code RouteRegistryInitializer} runs at context start-up, before any servlet is
 * initialised. Only the servlet context and configuration are the browserless stand-ins.
 */
@DisplayName("JS-SEC-152 / JS-SEC-024 — the route checks of install() work inside serviceInit")
class BootstrapAtServiceInitTest {

  private static final String LOGIN = "sa52-init/login";

  private MockVaadinServlet servlet;

  @BeforeEach
  @AfterEach
  void reset() {
    if (servlet != null) {
      servlet.destroy();
      servlet = null;
    }
    CurrentInstance.clearAll();
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  /** What the init listener saw and what the bootstrap it ran reported. */
  private record Observed(VaadinService currentDuringInit, VaadinService eventSource,
                          RouteNameCheck.Result loginCheckDuringInit, JCustosRuntime runtime) {

    List<String> codes() {
      return runtime.warnings().stream().map(JCustosBootstrapWarning::code).toList();
    }
  }

  /**
   * Starts a service whose init listener runs the bootstrap, and returns what happened
   * inside {@code serviceInit}.
   */
  @SafeVarargs
  private Observed startService(UnaryOperator<VaadinJCustosBootstrap> configuration,
                                Class<? extends Component>... routes) {
    AtomicReference<Observed> observed = new AtomicReference<>();
    VaadinServiceInitListener bootstrapListener = event -> {
      VaadinService current = VaadinService.getCurrent();
      RouteNameCheck.Result loginCheck = RouteNameCheck.check(LOGIN);
      JCustosRuntime runtime = configuration.apply(VaadinSecurity.bootstrap()
              .authentication(FakeAuthenticationService.forType(String.class))
              .authorization(new FakeAuthorizationService<String>()))
          .install();
      observed.set(new Observed(current, event.getSource(), loginCheck, runtime));
    };
    Routes routeSet = new Routes();
    routeSet.getRoutes().addAll(List.of(routes));
    servlet = new ContainerOrderServlet(routeSet, bootstrapListener);
    assertNull(VaadinService.getCurrent(), "the thread starts without a current service");

    VaadinServletService service = MockVaadin.setupServlet(servlet, Set.of());

    assertNotNull(observed.get(), "the init listener must have run during VaadinService.init()");
    assertSame(service, observed.get().eventSource());
    return observed.get();
  }

  @Test
  @DisplayName("during serviceInit the service of the event is the current VaadinService, and afterwards it is not")
  void serviceIsCurrentDuringServiceInit() {
    Observed observed = startService(b -> b.loginRoute(LOGIN), LoginRoute.class);

    assertSame(observed.eventSource(), observed.currentDuringInit(),
        "VaadinService.init() runs its init listeners with the service as current instance");
    assertEquals(RouteNameCheck.Result.REGISTERED, observed.loginCheckDuringInit(),
        "the application-scope registry is readable inside serviceInit");
    assertNull(VaadinService.getCurrent(), "the service context ends with the listeners");
  }

  @Test
  @DisplayName("a registered login route: neither route-check-unavailable nor login-route-unresolved")
  void registeredLoginRouteIsFoundAtServiceInit() {
    Observed observed = startService(b -> b.loginRoute(LOGIN), LoginRoute.class, ProtectedRoute.class);

    assertTrue(observed.codes().stream().noneMatch("vaadin/route-check-unavailable"::equals),
        observed.codes().toString());
    assertTrue(observed.codes().stream().noneMatch("vaadin/login-route-unresolved"::equals),
        observed.codes().toString());
  }

  @Test
  @DisplayName("a login route no view is registered under is reported at start-up, from inside serviceInit")
  void unregisteredLoginRouteIsReportedAtServiceInit() {
    Observed observed = startService(b -> b.loginRoute("sa52-init/no-such-login"),
        LoginRoute.class, ProtectedRoute.class);

    assertTrue(observed.codes().contains("vaadin/login-route-unresolved"),
        "the check must have read the registry, not skipped it: " + observed.codes());
    assertTrue(observed.codes().stream().noneMatch("vaadin/route-check-unavailable"::equals));
  }

  @Test
  @DisplayName("deny-by-default: a discovery over the application scope lists the un-annotated route at serviceInit")
  void denyByDefaultDiscoveryWorksAtServiceInit() {
    Observed observed = startService(
        b -> b.loginRoute(LOGIN).denyByDefault(true).discoverSecureRoutes(new ApplicationScopeDiscovery()),
        LoginRoute.class, ProtectedRoute.class, ForgottenRoute.class);

    assertTrue(observed.codes().stream().noneMatch("deny-by-default/discovery-unavailable"::equals),
        observed.codes().toString());
    List<String> unannotated = observed.runtime().warnings().stream()
        .filter(w -> "deny-by-default/unannotated-route".equals(w.code()))
        .map(JCustosBootstrapWarning::message)
        .toList();
    assertEquals(2, unannotated.size(), "LoginRoute and ForgottenRoute carry no annotation: " + unannotated);
    assertTrue(unannotated.stream().anyMatch(m -> m.contains("ForgottenRoute")), unannotated.toString());
    assertTrue(unannotated.stream().noneMatch(m -> m.contains("ProtectedRoute")), unannotated.toString());
  }

  @Test
  @DisplayName("control: the same bootstrap outside a service - a ServletContextListener, a main method - cannot read the registry")
  void withoutACurrentServiceTheChecksAreUnavailable() {
    assertNull(VaadinService.getCurrent());

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .loginRoute(LOGIN)
        .denyByDefault(true)
        .discoverSecureRoutes(new ApplicationScopeDiscovery())
        .install();

    List<String> codes = runtime.warnings().stream().map(JCustosBootstrapWarning::code).toList();
    assertTrue(codes.contains("vaadin/route-check-unavailable"), codes.toString());
    assertTrue(codes.contains("deny-by-default/discovery-unavailable"), codes.toString());
  }

  // ── routes ──

  /** The login view; un-annotated on purpose. */
  @Route(LOGIN)
  public static class LoginRoute extends Div {
  }

  /** A protected view. */
  @Route("sa52-init/protected")
  @RequiresRole("ROLE_USER")
  public static class ProtectedRoute extends Div {
  }

  /** A view somebody forgot to annotate. */
  @Route("sa52-init/forgotten")
  public static class ForgottenRoute extends Div {
  }

  // ── support ──

  /**
   * Reads the routes the way the starter's default discovery does: through
   * {@code RouteConfiguration.forApplicationScope()}, which needs a current
   * {@link VaadinService}. (The starter module is not on this module's class path.)
   */
  private static final class ApplicationScopeDiscovery implements SecureRouteDiscovery {
    private final RouteRestrictionResolver resolver = new RouteRestrictionResolver();

    private static RouteRegistry registry() {
      return RouteConfiguration.forApplicationScope().getHandledRegistry();
    }

    @Override
    public Stream<String> discoverPolicyNames() {
      return Stream.empty();
    }

    @Override
    public boolean routesAvailable() {
      try {
        registry().getRegisteredRoutes();
        return true;
      } catch (RuntimeException notAvailable) {
        return false;
      }
    }

    @Override
    public Stream<String> discoverUnannotatedRouteNames() {
      RouteRegistry routes = registry();
      return routes.getRegisteredRoutes().stream()
          .filter(route -> resolver.isOpenByOmission(
              route.getNavigationTarget(), route.getParentLayouts()))
          .map(route -> route.getNavigationTarget().getSimpleName())
          .toList()
          .stream();
    }
  }

  /**
   * A servlet that brings its service up in the order of a servlet container: the routes
   * are in the application-scope registry before {@code VaadinService.init()} runs the
   * init listeners. (The stock browserless servlet registers them afterwards.)
   */
  private static final class ContainerOrderServlet extends MockVaadinServlet {
    private final transient VaadinServiceInitListener listener;

    ContainerOrderServlet(Routes routes, VaadinServiceInitListener listener) {
      super(routes, MockedUI::new);
      this.listener = listener;
    }

    @Override
    protected VaadinServletService createServletService(DeploymentConfiguration configuration) {
      VaadinServletService service = new MockService(this, configuration, MockedUI::new) {
        @Override
        protected Instantiator createInstantiator() throws ServiceException {
          return withListener(super.createInstantiator(), listener);
        }
      };
      getRoutes().register((VaadinServletContext) service.getContext());
      try {
        service.init();
      } catch (ServiceException e) {
        throw new IllegalStateException(e);
      }
      return service;
    }
  }

  /** Adds one init listener to those the service loader finds. */
  private static Instantiator withListener(Instantiator delegate, VaadinServiceInitListener listener) {
    return (Instantiator) Proxy.newProxyInstance(
        Instantiator.class.getClassLoader(), new Class<?>[] {Instantiator.class},
        (proxy, method, args) -> {
          if ("getServiceInitListeners".equals(method.getName()) && method.getParameterCount() == 0) {
            return Stream.concat(delegate.getServiceInitListeners(), Stream.of(listener));
          }
          try {
            return method.invoke(delegate, args);
          } catch (InvocationTargetException e) {
            throw e.getCause();
          }
        });
  }
}
