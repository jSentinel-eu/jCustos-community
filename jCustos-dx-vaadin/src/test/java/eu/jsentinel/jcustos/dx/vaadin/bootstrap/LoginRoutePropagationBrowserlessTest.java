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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * JS-SEC-084 (CWE-684): {@code .loginRoute("signin")} used to be discarded by the Vaadin
 * bootstrap, so an anonymous navigation to a restricted route was still sent to
 * {@code "login"} and ended in {@code RouteNotFoundError}.
 */
@DisplayName("JS-SEC-084 — the bootstrap's login route reaches the authorisation listener")
class LoginRoutePropagationBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void bootstrapSecurity() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .loginRoute("signin")
        .audit(a -> a.logging())
        .install();
  }

  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("anonymous navigation to a @RequiresRole route ends on the configured signin view")
  void anonymousNavigation_endsOnConfiguredLoginRoute() {
    assertEquals("signin", JCustosServiceResolver.loginRouteName());

    UI.getCurrent().navigate("er17-admin");

    List<HasElement> chain = UI.getCurrent().getInternals().getActiveRouterTargetsChain();
    assertFalse(chain.isEmpty(), "a view must be active after the navigation");
    assertInstanceOf(Er17SigninView.class, chain.get(0),
        "Unauthenticated must be sent to the configured login route, not to a hard-coded 'login'");
  }

  @Route("signin")
  public static class Er17SigninView extends Div {
  }

  @Route("er17-admin")
  @RequiresRole("ADMIN")
  public static class Er17AdminView extends Div {
  }
}
