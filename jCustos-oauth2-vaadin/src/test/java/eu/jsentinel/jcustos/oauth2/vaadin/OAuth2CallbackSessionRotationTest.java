package eu.jsentinel.jcustos.oauth2.vaadin;

/*-
 * #%L
 * jCustos OAuth2 — Vaadin callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.audit.SessionCreated;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.oauth2.HttpAuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.HttpTokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.VaadinJCustosVersionContext;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import eu.jsentinel.jcustos.test.oidc.StubIdentityProvider;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockService;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.server.ServiceException;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-146 (CWE-384): the federated login rotates the HTTP session id. The view is entered
 * through the Vaadin router with the query string the identity provider redirects back with;
 * the flow is the real {@link HttpAuthorizationCodeFlow} with the session-bound
 * {@link VaadinSessionStateStore}, and its code exchange goes over loopback HTTP to the
 * {@link StubIdentityProvider}. No mocking framework.
 *
 * <p>The Vaadin service is the real one on the browserless servlet stand-ins, but with plain
 * {@link VaadinSession}s: the browserless session re-creates itself and its UI the moment it
 * is closed, which a servlet container does not do in the middle of a navigation.
 */
@DisplayName("JS-SEC-146 — the OAuth2 callback rotates the session id like every other login")
class OAuth2CallbackSessionRotationTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private StubIdentityProvider idp;
  private static HttpAuthorizationCodeFlow flow;
  private OAuth2ClientConfig config;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;

  @BeforeEach
  void wire() {
    System.setProperty("jcustos.dev", "true");
    idp = StubIdentityProvider.start("rp", Instant::now)
        .withIdTokenClaims(Map.of("sub", "alice"));
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.<String, String>forType(String.class));
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    JCustosServiceResolver.setSessionPolicy(
        new TimeoutSessionPolicy<>(TimeoutSessionPolicy.Config.defaults(), Clock.systemUTC(), audit));
    SubjectStores.setSubjectStore(new VaadinSessionSubjectStore());

    config = new OAuth2ClientConfig(
        new ClientAuthentication.NoneAuthentication("rp"),
        Optional.of(URI.create(idp.issuer() + "/authorize")),
        idp.tokenEndpoint(),
        Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.of(URI.create("https://app.example/oauth2/callback")),
        Set.of("openid"), true, true, Duration.ofMinutes(10));
    flow = flowFor(config);
    CallbackView.rotatedFrom = null;
    CallbackView.rotatedTo = null;
    CallbackView.tokensSeen = false;

    Routes routes = new Routes();
    routes.getRoutes().addAll(List.of(CallbackView.class, LandingView.class, ErrorLandingView.class));
    MockVaadin.setup(MockedUI::new, new PlainSessionServlet(routes));
    session = VaadinSession.getCurrent();
  }

  private HttpAuthorizationCodeFlow flowFor(OAuth2ClientConfig clientConfig) {
    return new HttpAuthorizationCodeFlow(clientConfig,
        new HttpTokenEndpointClient(idp.tokenEndpoint(), new ClientAuthentication.NoneAuthentication("rp"),
            HttpClient.newHttpClient(), Instant::now),
        new VaadinSessionStateStore());
  }

  @AfterEach
  void cleanUp() {
    try {
      MockVaadin.tearDown();
    } finally {
      idp.close();
      System.clearProperty("jcustos.dev");
      JCustosServiceResolver.resetAll();
      SubjectStores.reset();
      flow = null;
    }
  }

  @Test
  @DisplayName("a successful callback rotates the id, keeps the subject, audits the rotation and reaches the success target")
  void successfulCallback_rotatesTheSessionId() {
    // the id the browser arrived with - the one an attacker may have planted
    String fixatedId = session.getSession().getId();
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state);

    String currentId = session.getSession().getId();
    assertNotEquals(fixatedId, currentId, "the session id the login started with must not survive the login");
    assertTrue(CallbackView.tokensSeen, "the tokens were handed to the application");
    assertEquals(Optional.of("alice"), SubjectStores.subjectStore().currentSubject(String.class),
        "the subject bound in onTokens survives the rotation");
    assertInstanceOf(LandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0),
        "the user proceeds to the success target");

    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(fixatedId, invalidated.sessionId(), "the retired id is audited");
    assertEquals("alice", invalidated.subjectId());
    SessionCreated created = audit.single(SessionCreated.class);
    assertEquals(currentId, created.sessionId(), "SessionPolicy.onLogin observed the surviving id");

    assertEquals(fixatedId, CallbackView.rotatedFrom, "the hook sees the retired id");
    assertEquals(currentId, CallbackView.rotatedTo, "the hook sees the surviving id");
  }

  @Test
  @DisplayName("the callback records the security-version snapshot under the rotated id")
  void successfulCallback_recordsTheVersionSnapshot() {
    InMemoryJCustosVersionStore versions = new InMemoryJCustosVersionStore();
    versions.increment(new JCustosVersionKey(TenantId.DEFAULT, SubjectId.of("alice")));
    JCustosServiceResolver.setJCustosVersionStore(versions);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state);

    VaadinJCustosVersionContext.Snapshot snapshot =
        VaadinJCustosVersionContext.current(session).orElseThrow(() -> new AssertionError("no snapshot"));
    assertEquals("alice", snapshot.subjectId().value());
    assertEquals(session.getSession().getId(), snapshot.sessionId(), "the snapshot names the surviving id");
    assertEquals(1L, snapshot.snapshot().value());
  }

  @Test
  @DisplayName("fail closed: when the id cannot be rotated the login is undone and the error target is reached")
  void rotationImpossible_loginIsAborted() {
    String sessionId = session.getSession().getId();
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    // no request is bound: there is nothing whose session id could be changed
    VaadinRequest request = VaadinRequest.getCurrent();
    CurrentInstance.set(VaadinRequest.class, null);
    try {
      UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state);
    } finally {
      CurrentInstance.set(VaadinRequest.class, request);
    }

    assertTrue(CallbackView.tokensSeen, "the code exchange itself succeeded");
    assertNull(session.getAttribute(String.class), "the subject bound in onTokens must be dropped again");
    assertNull(CallbackView.rotatedTo, "no rotation, no hook");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the fixated session is closed");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(AbstractOAuth2CallbackView.REASON_ROTATION_FAILED, invalidated.reason());
    assertEquals(sessionId, invalidated.sessionId());
    assertEquals("alice", invalidated.subjectId());
    assertInstanceOf(ErrorLandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0),
        "the user lands on the error target, not in the application");
  }

  @Test
  @DisplayName("a failed callback neither binds a subject nor rotates")
  void failedCallback_changesNothing() {
    String before = session.getSession().getId();

    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=unknown-state");

    assertEquals(before, session.getSession().getId());
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty());
    assertTrue(audit.events().isEmpty());
    assertNotNull(UI.getCurrent());
    assertInstanceOf(ErrorLandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0));
  }

  // ── JS-SEC-150 (CWE-346, RFC 9207): the view passes the response issuer to the flow ──

  @Test
  @DisplayName("JS-SEC-150: a callback naming a foreign issuer is rejected, the honest one still completes")
  void foreignIssuer_isRejectedBeforeTheCodeExchange() {
    String issuer = String.valueOf(idp.issuer());
    flow = flowFor(config.withExpectedIssuer(issuer, true));
    String before = session.getSession().getId();
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state
        + "&iss=" + URLEncoder.encode("https://attacker.example", StandardCharsets.UTF_8));

    assertFalse(CallbackView.tokensSeen, "the code must not be exchanged for a mixed-up response");
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty());
    assertEquals(before, session.getSession().getId());
    assertInstanceOf(ErrorLandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0));

    // The state was not consumed: the response of the expected issuer completes the login.
    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state
        + "&iss=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8));

    assertTrue(CallbackView.tokensSeen);
    assertInstanceOf(LandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0));
  }

  @Test
  @DisplayName("JS-SEC-150: a callback without iss is rejected when the issuer announces the parameter")
  void missingIssuer_isRejectedWhenRequired() {
    flow = flowFor(config.withExpectedIssuer(String.valueOf(idp.issuer()), true));
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state);

    assertFalse(CallbackView.tokensSeen);
    assertInstanceOf(ErrorLandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0));
  }

  @Test
  @DisplayName("JS-SEC-150: a callback naming two issuers is rejected without touching the flow")
  void duplicatedIssuer_isRejected() {
    String issuer = URLEncoder.encode(String.valueOf(idp.issuer()), StandardCharsets.UTF_8);
    flow = flowFor(config.withExpectedIssuer(String.valueOf(idp.issuer()), true));
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state + "&iss=" + issuer + "&iss=" + issuer);

    assertFalse(CallbackView.tokensSeen);
    assertInstanceOf(ErrorLandingView.class, UI.getCurrent().getInternals().getActiveRouterTargetsChain().get(0));

    // The state is still there for the well-formed response.
    UI.getCurrent().navigate("sa46/callback?code=auth-code&state=" + state + "&iss=" + issuer);
    assertTrue(CallbackView.tokensSeen);
  }

  /** The application's callback route: binds the subject, as the documented recipe does. */
  @Route("sa46/callback")
  public static class CallbackView extends AbstractOAuth2CallbackView {
    static String rotatedFrom;
    static String rotatedTo;
    static boolean tokensSeen;

    @Override protected AuthorizationCodeFlow flow() {
      return flow;
    }

    @Override protected void onTokens(CallbackResult result) {
      tokensSeen = result.tokens().accessToken() != null;
      SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    }

    @Override protected String successTarget() {
      return "sa46/landing";
    }

    @Override protected String errorTarget() {
      return "sa46/error";
    }

    @Override protected void onSessionRotated(String previousSessionId, String currentSessionId) {
      rotatedFrom = previousSessionId;
      rotatedTo = currentSessionId;
    }
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

  @Route("sa46/landing")
  public static class LandingView extends Div {
  }

  @Route("sa46/error")
  public static class ErrorLandingView extends Div {
  }
}
