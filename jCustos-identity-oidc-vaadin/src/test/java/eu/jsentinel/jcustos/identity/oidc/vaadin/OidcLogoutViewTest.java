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
package eu.jsentinel.jcustos.identity.oidc.vaadin;

import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.vaadin.VaadinSessionTokenCredentialStore;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.VaadinJCustosVersionContext;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockService;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.internal.PendingJavaScriptInvocation;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.ServiceException;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-147 (CWE-613, CWE-460, CWE-352): the OIDC logout route, entered through the Vaadin
 * router with a real session-backed subject store, token credential store and version
 * snapshot. No mocking framework; the Vaadin service runs on the browserless servlet
 * stand-ins with plain {@link VaadinSession}s (the browserless session re-creates itself
 * when closed, which a servlet container does not do in the middle of a navigation).
 */
@DisplayName("JS-SEC-147 — the OIDC logout route redirects to the provider, always ends the local session, and is not triggered by navigation alone")
class OidcLogoutViewTest {

  private static final URI END_SESSION = URI.create("https://idp.example/oidc/logout");
  private static final URI POST_LOGOUT = URI.create("https://app.example/");

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final VaadinSessionSubjectStore subjects = new VaadinSessionSubjectStore();
  private final VaadinSessionTokenCredentialStore tokens = new VaadinSessionTokenCredentialStore();
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private UI ui;
  private String sessionId;
  private final List<PendingJavaScriptInvocation> sentToBrowser = new ArrayList<>();

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.<String, String>forType(String.class));
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    JCustosServiceResolver.setTokenCredentialStore(tokens);
    JCustosServiceResolver.setSessionPolicy(
        new TimeoutSessionPolicy<>(TimeoutSessionPolicy.Config.defaults(), Clock.systemUTC(), audit));
    SubjectStores.setSubjectStore(subjects);
    LogoutView.endSessionEndpoint = () -> END_SESSION;
    LogoutView.logoutRequest = () -> new LogoutRequest("ID-TOKEN", Optional.of(POST_LOGOUT), Optional.empty());
    LogoutView.beforeLogout = () -> { };
    LogoutView.localTarget = null;

    Routes routes = new Routes();
    routes.getRoutes().addAll(List.of(LogoutView.class, HomeView.class));
    MockVaadin.setup(MockedUI::new, new PlainSessionServlet(routes));
    session = VaadinSession.getCurrent();
    ui = UI.getCurrent();
    sessionId = session.getSession().getId();

    // a logged-in user with everything a session can carry
    subjects.setCurrentSubject("alice", String.class);
    tokens.bind(new BearerToken("access-token", Optional.empty(), Optional.empty(), Optional.empty()));
    VaadinJCustosVersionContext.record(session, SubjectId.of("alice"), TenantId.DEFAULT,
        JCustosVersion.INITIAL, sessionId);
    audit.clear();
  }

  @AfterEach
  void stop() {
    try {
      MockVaadin.tearDown();
    } finally {
      JCustosServiceResolver.resetAll();
      SubjectStores.reset();
    }
  }

  // ── (a) the redirect reaches the provider ───────────────────────

  @Test
  @DisplayName("(a) with a valid token the browser is sent to the provider's end-session URL")
  void validToken_redirectsToTheProvider() {
    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    String location = redirectLocation();
    assertNotNull(location, "the navigation must schedule a browser redirect (window.open) - "
        + "getUI() is empty while the view is entered, the event's UI is not");
    assertTrue(location.startsWith(END_SESSION + "?"), location);
    assertTrue(location.contains("id_token_hint=ID-TOKEN"), location);
    assertTrue(location.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example%2F"), location);
  }

  // ── (b) the local teardown is complete and guaranteed ───────────

  @Test
  @DisplayName("(b) the local teardown is complete: subject, token credential, snapshot, policy, audit, session")
  void validToken_tearsTheWholeLocalSessionDown() {
    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    assertLoggedOutLocally();
    LogoutPerformed logout = audit.single(LogoutPerformed.class);
    assertEquals("alice", logout.subjectId());
    assertEquals(SessionRef.of(sessionId), logout.sessionId(),
        "LogoutPerformed carries the reference, never the session id (JS-SEC-117)");
    assertEquals(LogoutScope.CurrentSession, logout.scope());
    SessionInvalidated policyEvent = audit.single(SessionInvalidated.class);
    assertEquals("Logout", policyEvent.reason(), "SessionPolicy.onLogout was notified");
    assertEquals(SessionRef.of(sessionId), policyEvent.sessionId());
  }

  @Test
  @DisplayName("(b) a provider without end_session_endpoint: logged out locally, sent to the local target")
  void throwingEndSessionEndpoint_stillLogsOut() {
    LogoutView.endSessionEndpoint = () -> {
      throw new IllegalStateException("the provider publishes no end_session_endpoint");
    };

    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    assertLoggedOutLocally();
    assertEquals("/login", redirectLocation(), "the default local target is the login route");
    assertEquals("alice", audit.single(LogoutPerformed.class).subjectId());
  }

  @Test
  @DisplayName("(b) a throwing logoutRequest(): logged out locally, sent to the configured local target")
  void throwingLogoutRequest_stillLogsOut() {
    LogoutView.logoutRequest = () -> {
      throw new IllegalArgumentException("no id token in this session");
    };
    LogoutView.localTarget = "/signed-out";

    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    assertLoggedOutLocally();
    assertEquals("/signed-out", redirectLocation(), "localLogoutTarget() decides where the user lands");
  }

  @Test
  @DisplayName("(b) a throwing onBeforeLogout(): logged out locally and still redirected to the provider")
  void throwingHook_stillLogsOut() {
    LogoutView.beforeLogout = () -> {
      throw new IllegalStateException("application teardown failed");
    };

    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    assertLoggedOutLocally();
    assertTrue(redirectLocation().startsWith(END_SESSION + "?"), redirectLocation());
  }

  @Test
  @DisplayName("(b) the hook runs after the subject was cleared and before the session is closed")
  void hook_runsBetweenSubjectClearAndSessionClose() {
    boolean[] observed = new boolean[2];
    LogoutView.beforeLogout = () -> {
      observed[0] = subjects.currentSubject(String.class).isEmpty();
      observed[1] = VaadinSession.getCurrent().getState() == VaadinSessionState.OPEN;
    };

    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    assertTrue(observed[0], "the subject is already cleared when the hook runs");
    assertTrue(observed[1], "the session is still open when the hook runs");
  }

  // ── (c) logout CSRF ─────────────────────────────────────────────

  @Test
  @DisplayName("(c) navigating to the route without a token logs nobody out and offers a confirmation")
  void noToken_nothingHappens() {
    ui.navigate(LogoutView.class);

    assertStillLoggedIn();
    assertNull(redirectLocation(), "no redirect to the provider - a foreign page must not end the SSO session");
    assertTrue(audit.events().isEmpty());
    assertTrue(confirmButton().isPresent(), "the view asks instead");
  }

  @Test
  @DisplayName("(c) a token that was never minted for this session is refused")
  void foreignToken_nothingHappens() {
    AbstractOidcLogoutView.mintLogoutToken();

    ui.navigate("sa47/logout?" + AbstractOidcLogoutView.LOGOUT_TOKEN_PARAMETER + "=guessed-or-stolen-elsewhere");

    assertStillLoggedIn();
    assertNull(redirectLocation());
    assertTrue(confirmButton().isPresent());
  }

  @Test
  @DisplayName("(c) a token is single-use: the second navigation with it logs nobody out")
  void token_isSingleUse() {
    String location = AbstractOidcLogoutView.logoutLocation(LogoutView.class);
    String token = location.substring(location.indexOf('=') + 1);
    AbstractOidcLogoutView.PendingLogoutTokens pending =
        session.getAttribute(AbstractOidcLogoutView.PendingLogoutTokens.class);
    assertEquals(1, pending.size());

    assertTrue(pending.consume(token), "first use");
    assertFalse(pending.consume(token), "second use");
    assertEquals(0, pending.size());

    ui.navigate(location);
    assertStillLoggedIn();
    assertNull(redirectLocation(), "a replayed logout link does nothing");
  }

  @Test
  @DisplayName("(c) a token of another session is worthless here")
  void tokenOfAnotherSession_isRefused() {
    String location = AbstractOidcLogoutView.logoutLocation(LogoutView.class);
    // the attacker's own session minted a token; the victim's session never saw it
    session.setAttribute(AbstractOidcLogoutView.PendingLogoutTokens.class, null);

    ui.navigate(location);

    assertStillLoggedIn();
    assertNull(redirectLocation());
  }

  @Test
  @DisplayName("(c) the confirmation button performs the full logout")
  void confirmationClick_logsOut() {
    ui.navigate(LogoutView.class);
    Button confirm = confirmButton().orElseThrow();

    confirm.click();

    assertLoggedOutLocally();
    assertTrue(redirectLocation().startsWith(END_SESSION + "?"), redirectLocation());
    assertEquals("alice", audit.single(LogoutPerformed.class).subjectId());
  }

  @Test
  @DisplayName("(c) a session keeps a bounded number of unused tokens and a token needs a session")
  void tokens_areBoundedAndSessionBound() {
    String first = AbstractOidcLogoutView.mintLogoutToken();
    for (int i = 0; i < AbstractOidcLogoutView.MAX_PENDING_TOKENS; i++) {
      AbstractOidcLogoutView.mintLogoutToken();
    }
    AbstractOidcLogoutView.PendingLogoutTokens pending =
        session.getAttribute(AbstractOidcLogoutView.PendingLogoutTokens.class);
    assertEquals(AbstractOidcLogoutView.MAX_PENDING_TOKENS, pending.size());
    assertFalse(pending.consume(first), "the oldest token was dropped");

    VaadinSession.setCurrent(null);
    try {
      assertThrows(IllegalStateException.class, AbstractOidcLogoutView::mintLogoutToken);
    } finally {
      VaadinSession.setCurrent(session);
    }
  }

  // ── helpers ────────────────────────────────────────────────────

  private void assertLoggedOutLocally() {
    assertNull(session.getAttribute(String.class), "the subject must be gone");
    assertTrue(tokens.current().isEmpty(), "the bound token credential must be cleared");
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(), "the version snapshot must be cleared");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the Vaadin session must be closed");
  }

  private void assertStillLoggedIn() {
    assertEquals("alice", session.getAttribute(String.class));
    assertTrue(tokens.current().isPresent());
    assertTrue(VaadinJCustosVersionContext.current(session).isPresent());
    assertEquals(VaadinSessionState.OPEN, session.getState());
  }

  /**
   * The URL of the {@code Page.setLocation} call ({@code window.open(url, "_self")}) the UI
   * would send to the browser with its next response.
   */
  private String redirectLocation() {
    sentToBrowser.addAll(ui.getInternals().dumpPendingJavaScriptInvocations());
    for (PendingJavaScriptInvocation pending : sentToBrowser) {
      if (pending.getInvocation().getExpression().contains("window.open")) {
        return String.valueOf(pending.getInvocation().getParameters().get(0));
      }
    }
    return null;
  }

  private Optional<Button> confirmButton() {
    return ui.getInternals().getActiveRouterTargetsChain().get(0).getElement().getChildren()
        .map(element -> element.getComponent().orElse(null))
        .filter(Button.class::isInstance)
        .map(Button.class::cast)
        .filter(button -> AbstractOidcLogoutView.CONFIRM_BUTTON_ID.equals(button.getId().orElse(null)))
        .findFirst();
  }

  /** The application's logout route; its collaborators are swapped per test. */
  @Route("sa47/logout")
  public static class LogoutView extends AbstractOidcLogoutView {
    static Supplier<URI> endSessionEndpoint;
    static Supplier<LogoutRequest> logoutRequest;
    static Runnable beforeLogout;
    static String localTarget;

    @Override protected URI endSessionEndpoint() {
      return endSessionEndpoint.get();
    }

    @Override protected LogoutRequest logoutRequest() {
      return logoutRequest.get();
    }

    @Override protected void onBeforeLogout() {
      beforeLogout.run();
    }

    @Override protected String localLogoutTarget() {
      return localTarget != null ? localTarget : super.localLogoutTarget();
    }
  }

  @Route("sa47/home")
  public static class HomeView extends Div {
  }

  /** The real servlet service, creating plain sessions instead of self-recreating ones. */
  private static final class PlainSessionServlet extends MockVaadinServlet {
    PlainSessionServlet(Routes routes) {
      super(routes, MockedUI::new);
    }

    @Override
    protected VaadinServletService createServletService(DeploymentConfiguration configuration) {
      VaadinServletService service = new MockService(this, configuration, MockedUI::new) {
        @Override
        protected VaadinSession createVaadinSession(VaadinRequest request) {
          return new VaadinSession(this);
        }
      };
      try {
        service.init();
      } catch (ServiceException e) {
        throw new IllegalStateException(e);
      }
      getRoutes().register((VaadinServletContext) service.getContext());
      return service;
    }
  }
}
