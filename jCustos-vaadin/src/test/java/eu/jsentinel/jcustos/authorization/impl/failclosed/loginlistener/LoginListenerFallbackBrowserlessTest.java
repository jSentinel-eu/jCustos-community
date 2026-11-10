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
package eu.jsentinel.jcustos.authorization.impl.failclosed.loginlistener;

import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.impl.StubAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.flow.component.Component;
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
 * JS-SEC-152: the fail-closed post-condition must not break a configuration that worked
 * before it. An application whose login view is registered under another name than
 * {@code JCustosServiceResolver.loginRouteName()} was rescued by its {@link LoginListener},
 * which forwards an anonymous visitor to its login view by class. The authorisation
 * listener now ends the navigation itself, so it takes that step on the login listener's
 * behalf - and falls back to the error view when the login listener cannot help.
 */
@DisplayName("JS-SEC-152 - an unresolvable login route falls back to the LoginListener's login view")
@ViewPackages
class LoginListenerFallbackBrowserlessTest extends BrowserlessTest {

  private final FixtureLoginListener loginListener = new FixtureLoginListener();

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    LoginListeners.setLoginListener(loginListener);
    StubAuthorizationService.clear();
    StubAuthorizationService.put("user", Set.of(new RoleName("USER")), Set.of());
    AdminView.INSTANCES.set(0);
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
  @DisplayName("anonymous visitor: forwarded to the LoginListener's login view, the protected view is never instantiated")
  void anonymous_isForwardedToTheLoginListenersLoginView() {
    assertTrue(RouteConfiguration.forApplicationScope()
            .getRoute(JCustosServiceResolver.loginRouteName()).isEmpty(),
        "precondition: no route is registered under the login route name");
    loginListener.loginTarget = SigninView.class;

    UI.getCurrent().navigate("fc-loginlistener/admin");

    assertEquals(0, AdminView.INSTANCES.get());
    assertInstanceOf(SigninView.class, activeView());
  }

  @Test
  @DisplayName("anonymous visitor: a LoginListener whose login view is not a route ends in the error view")
  void anonymous_loginViewNotRegistered_endsInErrorView() {
    loginListener.loginTarget = UnroutedLoginView.class;

    UI.getCurrent().navigate("fc-loginlistener/admin");

    assertEquals(0, AdminView.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeView());
  }

  @Test
  @DisplayName("anonymous visitor: a LoginListener without a login view ends in the error view")
  void anonymous_noLoginView_endsInErrorView() {
    loginListener.loginTarget = null;

    UI.getCurrent().navigate("fc-loginlistener/admin");

    assertEquals(0, AdminView.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeView());
  }

  @Test
  @DisplayName("authenticated subject without the role: error view, never the login view")
  void forbidden_isNotSentToTheLoginView() {
    loginListener.loginTarget = SigninView.class;
    SubjectStores.subjectStore().setCurrentSubject("user", String.class);

    UI.getCurrent().navigate("fc-loginlistener/admin");

    assertEquals(0, AdminView.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeView());
  }

  // ── Fixtures ───────────────────────────────────────────────────

  /** The application's login view, registered under a name the resolver does not know. */
  @Route("fc-loginlistener/signin")
  public static class SigninView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { /* not used */ }
    @Override public void reactOnFailedLogin() { /* not used */ }
  }

  public static class UnroutedLoginView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { /* not used */ }
    @Override public void reactOnFailedLogin() { /* not used */ }
  }

  @Route("fc-loginlistener/home")
  public static class HomeView extends Div {
  }

  @Route("fc-loginlistener/admin")
  @RequiresRole("ADMIN")
  public static class AdminView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public AdminView() {
      INSTANCES.incrementAndGet();
    }
  }

  private static final class FixtureLoginListener extends LoginListener<String> {
    Class<? extends LoginView> loginTarget;

    @Override public void notARestrictedTarget(Class<?> navigationTarget) { /* not used */ }
    @Override public Class<? extends LoginView> loginNavigationTarget() { return loginTarget; }
    @Override public Class<? extends Component> defaultNavigationTarget() { return HomeView.class; }
  }
}
