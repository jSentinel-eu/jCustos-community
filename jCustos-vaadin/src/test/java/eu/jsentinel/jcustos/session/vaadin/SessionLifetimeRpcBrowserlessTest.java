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
package eu.jsentinel.jcustos.session.vaadin;

import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.mocks.MockRequest;
import com.vaadin.browserless.mocks.MockResponse;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinServletResponse;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.server.WrappedHttpSession;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-082 (CWE-613): the lifetime listener is also a {@code RequestHandler}.
 * Browserless component events do not travel through the request pipeline, so the
 * tests drive {@code handleRequest} with the mock request the servlet would hand
 * over - a UIDL request for the current UI.
 */
@DisplayName("JS-SEC-082 — session lifetime is enforced per UIDL request, not only on navigation")
class SessionLifetimeRpcBrowserlessTest extends BrowserlessTest {

  private static final Instant FAR_FUTURE = Instant.parse("2030-01-01T00:00:00Z");

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("resolved-" + s));
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("an RPC after the absolute lifetime drops the subject, audits SessionExpired and closes the session")
  void expiredSession_rpcIsEnforced() throws IOException {
    navigate(Er15FixtureView.class);
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    JCustosServiceResolver.setSessionPolicy(policy(Duration.ofSeconds(1), FAR_FUTURE));
    VaadinSession session = VaadinSession.getCurrent();

    boolean consumed = new SessionLifetimeListener().handleRequest(session, uidlRequest(session), response());

    assertFalse(consumed, "the handler must never consume the request");
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty(),
        "the subject must be dropped without any navigation");
    assertEquals(1, audit.events().size());
    SessionExpired expired = (SessionExpired) audit.events().get(0);
    assertEquals(SessionExpired.REASON_ABSOLUTE_LIFETIME, expired.reason());
    assertEquals("resolved-alice", expired.subjectId());
    // close() marks the session CLOSING during a request; browserless has no ongoing request
    // and discards it right away, hence CLOSED here.
    assertNotEquals(VaadinSessionState.OPEN, session.getState(),
        "the session is discarded at the end of the request");
  }

  @Test
  @DisplayName("an RPC before expiry keeps the subject and records the activity")
  void liveSession_rpcKeepsSubject() throws IOException {
    navigate(Er15FixtureView.class);
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    JCustosServiceResolver.setSessionPolicy(policy(Duration.ofHours(12), Instant.now()));
    VaadinSession session = VaadinSession.getCurrent();
    assertNull(session.getAttribute(SessionLifetimeListener.LAST_ACTIVITY_ATTRIBUTE));

    new SessionLifetimeListener().handleRequest(session, uidlRequest(session), response());

    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isPresent());
    assertTrue(audit.events().isEmpty());
    assertNotNull(session.getAttribute(SessionLifetimeListener.LAST_ACTIVITY_ATTRIBUTE),
        "the RPC counts as activity");
    assertEquals(VaadinSessionState.OPEN, session.getState());
  }

  @Test
  @DisplayName("a heartbeat is neither an activity signal nor enforced")
  void heartbeat_isIgnored() throws IOException {
    navigate(Er15FixtureView.class);
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    JCustosServiceResolver.setSessionPolicy(policy(Duration.ofSeconds(1), FAR_FUTURE));
    VaadinSession session = VaadinSession.getCurrent();
    MockRequest raw = rawRequest(session);
    raw.setParameter("v-r", "heartbeat");

    new SessionLifetimeListener().handleRequest(session, wrap(raw), response());

    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isPresent());
    assertTrue(audit.events().isEmpty());
    assertNull(session.getAttribute(SessionLifetimeListener.LAST_ACTIVITY_ATTRIBUTE));
  }

  // ── helpers ────────────────────────────────────────────────────

  private TimeoutSessionPolicy<Object> policy(Duration absoluteLifetime, Instant policyNow) {
    return new TimeoutSessionPolicy<>(
        new TimeoutSessionPolicy.Config(Duration.ofMinutes(30), absoluteLifetime, false, "/login"),
        Clock.fixed(policyNow, ZoneOffset.UTC), audit);
  }

  private static MockRequest rawRequest(VaadinSession session) {
    HttpSession http = ((WrappedHttpSession) session.getSession()).getHttpSession();
    MockRequest raw = new MockRequest(http);
    raw.setParameter("v-uiId", String.valueOf(UI.getCurrent().getUIId()));
    return raw;
  }

  private static VaadinRequest uidlRequest(VaadinSession session) {
    MockRequest raw = rawRequest(session);
    raw.setParameter("v-r", "uidl");
    return wrap(raw);
  }

  private static VaadinRequest wrap(MockRequest raw) {
    return new VaadinServletRequest(raw, (VaadinServletService) VaadinService.getCurrent());
  }

  private static VaadinResponse response() {
    return new VaadinServletResponse(new MockResponse(), (VaadinServletService) VaadinService.getCurrent());
  }

  /** A view with one button - the kind of single-view application the finding is about. */
  @Route("er15-fixture")
  public static class Er15FixtureView extends Div {
    public Er15FixtureView() {
      add(new Button("work"));
    }
  }
}
