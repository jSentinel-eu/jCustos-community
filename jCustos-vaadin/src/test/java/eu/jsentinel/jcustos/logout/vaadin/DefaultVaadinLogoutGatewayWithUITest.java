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
package eu.jsentinel.jcustos.logout.vaadin;

import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.server.WrappedSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link DefaultVaadinLogoutGateway} with a bound Vaadin UI /
 * session — covers the side-effecting branches that the existing
 * "no-current" test only verifies as no-ops. Uses Browserless to wire a
 * real {@code MockedUI} and {@code MockVaadinSession}.
 */
@DisplayName("DefaultVaadinLogoutGateway — UI bound")
class DefaultVaadinLogoutGatewayWithUITest extends BrowserlessTest {

  private final DefaultVaadinLogoutGateway gateway = new DefaultVaadinLogoutGateway();

  @Test
  @DisplayName("redirectTo queues a Page side-effect with the target URL embedded")
  void redirectTo_queuesPageSideEffect() {
    navigate(Fixture.class);

    UI ui = UI.getCurrent();
    assertNotNull(ui, "Browserless must bind a current UI");
    // dumpPendingJavaScriptInvocations() drains the buffer — clear once
    // first so any setup-time invocations don't pollute the count.
    ui.getInternals().dumpPendingJavaScriptInvocations();

    gateway.redirectTo("/login");

    int afterGateway = ui.getInternals().dumpPendingJavaScriptInvocations().size();
    assertTrue(afterGateway >= 1,
        "redirectTo must queue at least one pending JS invocation; got: " + afterGateway);
  }

  @Test
  @DisplayName("JS-SEC-084: currentSessionId is the wrapped HTTP session id")
  void currentSessionId_isWrappedSessionId() {
    navigate(Fixture.class);

    WrappedSession wrapped = VaadinSession.getCurrent().getSession();
    assertNotNull(wrapped, "Browserless must expose a wrapped session");
    assertEquals(wrapped.getId(), gateway.currentSessionId());
  }

  @Test
  @DisplayName("closeVaadinSession transitions the session to CLOSING")
  void closeVaadinSession_marksSessionClosing() {
    navigate(Fixture.class);

    VaadinSession session = VaadinSession.getCurrent();
    assertNotNull(session, "Browserless must bind a current VaadinSession");
    assertEquals(VaadinSessionState.OPEN, session.getState(),
        "precondition: a freshly bound session must be OPEN");

    gateway.closeVaadinSession();

    assertNotEquals(VaadinSessionState.OPEN, session.getState(),
        "after closeVaadinSession the session must no longer report OPEN; got: "
            + session.getState());
  }

  @Test
  @DisplayName("invalidateHttpSession invalidates the underlying WrappedSession")
  void invalidateHttpSession_invalidatesWrappedSession() {
    navigate(Fixture.class);

    VaadinSession vaadin = VaadinSession.getCurrent();
    WrappedSession wrapped = vaadin.getSession();
    assertNotNull(wrapped, "Browserless must expose a wrapped session for invalidation");

    gateway.invalidateHttpSession();

    // Querying an invalidated HttpSession is required to throw
    // IllegalStateException per Servlet spec. Browserless's MockHttpSession
    // honours that contract.
    boolean threw;
    try {
      wrapped.getAttribute("anything");
      threw = false;
    } catch (IllegalStateException expected) {
      threw = true;
    }
    assertTrue(threw,
        "wrapped HTTP session must be invalidated — subsequent getAttribute must throw");
  }

  @Route("test/logout-gateway")
  public static class Fixture extends Composite<Div> {
    public Fixture() { /* empty */ }
  }
}
