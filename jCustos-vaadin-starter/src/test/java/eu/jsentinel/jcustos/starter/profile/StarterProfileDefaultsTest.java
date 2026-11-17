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
package eu.jsentinel.jcustos.starter.profile;

import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RoutePrefix;
import com.vaadin.flow.router.RouterLayout;
import com.vaadin.flow.server.VaadinService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-168 (CWE-1188): the production and strict profiles do what their Javadoc says -
 * deny-by-default and the login route of the application's {@code LoginView} - instead of
 * setting the bootstrap mode only. The real bootstrap, a real Vaadin service with the routes
 * of each test.
 */
@DisplayName("JS-SEC-168 - production and strict profiles set deny-by-default and the login route")
class StarterProfileDefaultsTest {

  private static final String ALLOW_BY_OMISSION = "authorization/allow-by-omission";

  @BeforeEach
  @AfterEach
  void reset() {
    if (VaadinService.getCurrent() != null) {
      MockVaadin.tearDown();
    }
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    LoginListeners.reset();
  }

  @SafeVarargs
  private static void startService(Class<? extends Component>... routes) {
    Routes routeSet = new Routes();
    routeSet.getRoutes().addAll(List.of(routes));
    MockVaadin.setup(routeSet);
  }

  private static VaadinJCustosBootstrap bootstrap(VaadinJCustosStarter profile) {
    return VaadinSecurity.bootstrap()
        .use(profile)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>());
  }

  private static List<String> findings(UnaryOperator<VaadinJCustosBootstrap> configuration,
                                       VaadinJCustosStarter profile) {
    try {
      return configuration.apply(bootstrap(profile)).install().warnings().stream()
          .map(JCustosBootstrapWarning::code).toList();
    } catch (JCustosBootstrapException strictFailure) {
      return strictFailure.warnings().stream().map(JCustosBootstrapWarning::code).toList();
    }
  }

  @Test
  @DisplayName("productionDefaults(): deny-by-default and the route of the one registered LoginView")
  void production_setsDenyByDefaultAndLoginRoute() {
    startService(SignInView.class, HomeView.class);

    bootstrap(VaadinJCustosStarter.productionDefaults()).install();

    assertTrue(JCustosServiceResolver.isDenyByDefault(), "an unannotated route is denied");
    assertEquals(Optional.of("r8-profile/sign-in"), JCustosServiceResolver.findLoginRouteName());
  }

  @Test
  @DisplayName("strictDefaults(): STRICT no longer reports allow-by-omission - the profile turned deny-by-default on")
  void strict_setsDenyByDefault() {
    startService(SignInView.class, HomeView.class);

    List<String> withProfile = findings(b -> b, VaadinJCustosStarter.strictDefaults());

    assertFalse(withProfile.contains(ALLOW_BY_OMISSION), withProfile.toString());
    assertTrue(JCustosServiceResolver.isDenyByDefault());
    assertEquals(Optional.of("r8-profile/sign-in"), JCustosServiceResolver.findLoginRouteName());
  }

  @Test
  @DisplayName("counter-check: the STRICT mode alone, without the profile, still reports allow-by-omission")
  void strictModeWithoutProfile_reportsAllowByOmission() {
    startService(SignInView.class, HomeView.class);

    List<String> modeOnly = findings(
        b -> b.mode(eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode.STRICT),
        VaadinJCustosStarter.developmentDefaults());

    assertTrue(modeOnly.contains(ALLOW_BY_OMISSION), modeOnly.toString());
  }

  @Test
  @DisplayName("developmentDefaults(): mode only - no deny-by-default, no login route")
  void development_setsModeOnly() {
    startService(SignInView.class, HomeView.class);

    bootstrap(VaadinJCustosStarter.developmentDefaults()).install();

    assertFalse(JCustosServiceResolver.isDenyByDefault());
    assertTrue(JCustosServiceResolver.findLoginRouteName().isEmpty());
  }

  @Test
  @DisplayName("later builder calls win over the profile")
  void explicitConfiguration_overridesTheProfile() {
    startService(SignInView.class, HomeView.class);

    bootstrap(VaadinJCustosStarter.productionDefaults())
        .loginRoute("r8-profile/home")
        .denyByDefault(false)
        .install();

    assertFalse(JCustosServiceResolver.isDenyByDefault());
    assertEquals(Optional.of("r8-profile/home"), JCustosServiceResolver.findLoginRouteName());
  }

  @Test
  @DisplayName("two LoginView routes and no LoginListener: ambiguous, the login route is left alone")
  void twoLoginViews_ambiguous() {
    startService(SignInView.class, OtherSignInView.class, HomeView.class);

    assertTrue(ProfileDefaults.loginRoute().isEmpty());
  }

  @Test
  @DisplayName("two LoginView routes: the one the registered LoginListener names wins")
  void twoLoginViews_listenerDecides() {
    startService(SignInView.class, OtherSignInView.class, HomeView.class);
    LoginListeners.setLoginListener(new PointingListener(OtherSignInView.class));

    assertEquals(Optional.of("r8-profile/other-sign-in"), ProfileDefaults.loginRoute());
  }

  @Test
  @DisplayName("no service: the @Route of the LoginListener's view, when it names the whole path")
  void withoutService_annotationOfTheListenersView() {
    assertNull(VaadinService.getCurrent());
    LoginListeners.setLoginListener(new PointingListener(SignInView.class));

    assertEquals(Optional.of("r8-profile/sign-in"), ProfileDefaults.loginRoute());
  }

  @Test
  @DisplayName("no service: a view under a @RoutePrefix layout is not unambiguous")
  void withoutService_prefixedLayoutIsAmbiguous() {
    LoginListeners.setLoginListener(new PointingListener(PrefixedSignInView.class));

    assertTrue(ProfileDefaults.loginRoute().isEmpty());
  }

  @Test
  @DisplayName("no service and no LoginListener: nothing to go by")
  void withoutServiceOrListener_nothing() {
    assertTrue(ProfileDefaults.loginRoute().isEmpty());
  }

  @Test
  @DisplayName("the profile does not throw when the LoginListener lookup fails")
  void failingListener_isIgnored() {
    LoginListeners.setLoginListener(new PointingListener(null) {
      @Override
      public Class<? extends LoginView> loginNavigationTarget() {
        throw new IllegalStateException("broken listener");
      }
    });

    assertTrue(ProfileDefaults.loginRoute().isEmpty());
    assertThrows(IllegalStateException.class,
        () -> LoginListeners.findLoginListener().orElseThrow().loginNavigationTarget(),
        "precondition: the listener really fails");
  }

  // ── fixtures ───────────────────────────────────────────────────

  /** The application's login view. */
  @Route("r8-profile/sign-in")
  @PublicRoute
  public static class SignInView extends TestLoginView {
  }

  /** A second login view - two of them make the choice ambiguous. */
  @Route("r8-profile/other-sign-in")
  @PublicRoute
  public static class OtherSignInView extends TestLoginView {
  }

  /** A login view whose path depends on its layout's prefix. */
  @Route(value = "sign-in", layout = PrefixLayout.class)
  public static class PrefixedSignInView extends TestLoginView {
  }

  /** A layout that adds a prefix to the paths of its views. */
  @RoutePrefix("r8-profile/area")
  public static class PrefixLayout extends Div implements RouterLayout {
  }

  /** A public start page. */
  @Route("r8-profile/home")
  @PublicRoute
  public static class HomeView extends Div {
  }

  /** A login view that never logs anybody in. */
  public abstract static class TestLoginView extends LoginView {
    @Override public boolean checkCredentials() {
      return false;
    }

    @Override public void navigateToApp() {
    }

    @Override public void reactOnFailedLogin() {
    }
  }

  /** A login listener that names a fixed login view. */
  static class PointingListener extends LoginListener<String> {
    private final Class<? extends LoginView> target;

    PointingListener(Class<? extends LoginView> target) {
      this.target = target;
    }

    @Override public void notARestrictedTarget(Class<?> navigationTarget) {
    }

    @Override public Class<? extends LoginView> loginNavigationTarget() {
      return target;
    }

    @Override public Class<? extends Component> defaultNavigationTarget() {
      return HomeView.class;
    }
  }
}
