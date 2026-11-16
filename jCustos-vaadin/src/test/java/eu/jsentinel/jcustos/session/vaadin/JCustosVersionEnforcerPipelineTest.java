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

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.Exchange;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.PushOutcome;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimePipelineTest.LockRecordingSubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-155 (CWE-667, CWE-613): the security-version check per client message, through
 * {@code VaadinService.handleRequest} on a thread without the session lock and with the
 * strict lock check. The listener is wired the way an application wires it:
 * {@link JCustosVersionEnforcerListener#register}.
 */
@DisplayName("JS-SEC-155 — security-version drift on the real request path")
class JCustosVersionEnforcerPipelineTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY = new JCustosVersionKey(TenantId.DEFAULT, ALICE);

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final LockRecordingSubjectStore subjects = new LockRecordingSubjectStore();
  private InMemoryJCustosVersionStore versionStore;

  private RequestPipeline pipeline;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private DriftWorkView view;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    SubjectStores.setSubjectStore(subjects);
    versionStore = new InMemoryJCustosVersionStore();
    DriftWorkView.ACTIONS.set(0);

    JCustosVersionEnforcerListener listener = new JCustosVersionEnforcerListener(
        new JCustosVersionEnforcer(versionStore, audit), DriftLoginView.class);
    pipeline = RequestPipeline.start(Clock.systemUTC(), List.of(listener::register),
        DriftWorkView.class, DriftLoginView.class);
    session = pipeline.session();
    view = pipeline.navigate(DriftWorkView.class);

    subjects.setCurrentSubject("alice", String.class);
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-155");
    audit.clear();
  }

  @AfterEach
  void stop() {
    try {
      pipeline.close();
    } finally {
      JCustosServiceResolver.resetAll();
      LoginListeners.reset();
      SubjectStores.reset();
      VaadinSessionRevocation.reset();
    }
  }

  @Test
  @DisplayName("a matching snapshot leaves the request, the subject and the session untouched")
  void matchingSnapshot_requestIsExecuted() {
    Exchange exchange = pipeline.fire(view, "privileged");

    assertNull(exchange.failure());
    assertFalse(exchange.internalError(), exchange.body());
    assertFalse(exchange.sessionExpired(), exchange.body());
    assertEquals(1, DriftWorkView.ACTIONS.get());
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));
    assertTrue(VaadinJCustosVersionContext.current(session).isPresent());
    assertTrue(audit.events().isEmpty());
    assertEquals(VaadinSessionState.OPEN, session.getState());
  }

  @Test
  @DisplayName("a drifted snapshot consumes the request: no RPC, session-expired response, SessionStale audited")
  void drift_requestIsConsumed() {
    versionStore.increment(ALICE_KEY);

    Exchange exchange = pipeline.fire(view, "privileged");

    assertNull(exchange.failure(), "the request must not fail");
    assertFalse(exchange.internalError(),
        "with the strict lock check an unlocked session access answers 'Internal error': " + exchange.body());
    assertTrue(exchange.sessionExpired(), exchange.body());
    assertEquals(0, DriftWorkView.ACTIONS.get(), "the RPC of a session with revoked rights must not run");
    assertTrue(subjects.currentSubject(String.class).isEmpty(), "the subject is dropped");
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(), "the stale snapshot is cleared");
    SessionStale stale = audit.single(SessionStale.class);
    assertEquals("alice", stale.subjectId());
    assertEquals(SessionRef.of("sid-155"), stale.sessionId(), "never the session id (JS-SEC-117)");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the session is closed");
    assertNull(session.getSession(), "the HTTP session is invalidated");
  }

  @Test
  @DisplayName("a drifted snapshot ends the session for a message over the push channel as well")
  void drift_pushMessage_isEnded() {
    assertTrue(pipeline.pushMessage().sessionFound(), "no drift yet");
    versionStore.increment(ALICE_KEY);

    PushOutcome outcome = pipeline.pushMessage();

    assertNull(outcome.failure());
    assertFalse(outcome.sessionFound(), "the push handler must find no session to run the RPC in");
    assertEquals("alice", audit.single(SessionStale.class).subjectId());
    assertTrue(subjects.currentSubject(String.class).isEmpty());
  }

  @Route("sa55-drift-work")
  public static class DriftWorkView extends Div {
    static final AtomicInteger ACTIONS = new AtomicInteger();

    public DriftWorkView() {
      getElement().addEventListener("privileged", event -> ACTIONS.incrementAndGet());
    }
  }

  @Route("sa55-drift-login")
  public static class DriftLoginView extends LoginView {
    @Override public boolean checkCredentials() {
      return false;
    }

    @Override public void navigateToApp() {
    }

    @Override public void reactOnFailedLogin() {
    }
  }
}
