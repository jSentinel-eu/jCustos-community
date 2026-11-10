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
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.Exchange;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.PushOutcome;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.flow.component.PushConfiguration;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.shared.communication.PushMode;
import com.vaadin.flow.shared.ui.Transport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-155 (CWE-667, CWE-362, CWE-613): the per-request lifetime check, exercised through
 * {@code VaadinService.handleRequest} on a thread that does not hold the session lock and
 * with the strict lock check Vaadin applies outside production mode.
 */
@DisplayName("JS-SEC-155 — the session lifetime check on the real request path")
class SessionLifetimePipelineTest {

  private static final Duration IDLE = Duration.ofMinutes(30);
  private static final Duration ABSOLUTE = Duration.ofHours(12);

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final MovableClock clock = new MovableClock(Instant.now());
  private final LockRecordingSubjectStore subjects = new LockRecordingSubjectStore();

  private RequestPipeline pipeline;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private WorkView view;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("resolved-" + s));
    JCustosServiceResolver.setSessionPolicy(new TimeoutSessionPolicy<>(
        new TimeoutSessionPolicy.Config(IDLE, ABSOLUTE, true, "/login"), clock, audit));
    SubjectStores.setSubjectStore(subjects);
    WorkView.ACTIONS.set(0);

    pipeline = RequestPipeline.start(clock, WorkView.class);
    session = pipeline.session();
    view = pipeline.navigate(WorkView.class);
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
  @DisplayName("(a) a UIDL request of a live session runs under the session lock and is executed")
  void liveSession_checkHoldsTheSessionLock() {
    login("alice");
    subjects.lockHeldOnAccess.clear();

    Exchange exchange = pipeline.fire(view, "privileged");

    assertNull(exchange.failure(), "the request must not fail");
    assertFalse(exchange.internalError(),
        "with the strict lock check an unlocked session access answers 'Internal error': " + exchange.body());
    assertFalse(exchange.sessionExpired(), exchange.body());
    assertEquals(1, WorkView.ACTIONS.get(), "the RPC of a live session is executed");
    assertFalse(subjects.lockHeldOnAccess.isEmpty(), "the check must have consulted the subject store");
    assertFalse(subjects.lockHeldOnAccess.contains(Boolean.FALSE),
        "every subject-store access of the request must happen under the session lock");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));
    assertEquals(VaadinSessionState.OPEN, session.getState());
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("(b) the request that trips the idle timeout is consumed: the RPC does not run")
  void expiredSession_requestIsConsumed() {
    login("alice");
    assertFalse(pipeline.fire(view, "privileged").sessionExpired());
    assertEquals(1, WorkView.ACTIONS.get());

    clock.advance(IDLE.plusMinutes(1));
    Exchange exchange = pipeline.fire(view, "privileged");

    assertNull(exchange.failure(), "the request must not fail");
    assertTrue(exchange.sessionExpired(), "the response must be Vaadin's session-expired message: " + exchange.body());
    assertEquals(1, WorkView.ACTIONS.get(), "the RPC that triggered the expiry must not be executed");
    assertTrue(subjects.currentSubject(String.class).isEmpty(), "the subject is dropped");
    SessionExpired expired = audit.single(SessionExpired.class);
    assertEquals(SessionExpired.REASON_IDLE_TIMEOUT, expired.reason());
    assertEquals("resolved-alice", expired.subjectId());
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the Vaadin session is closed");
    assertNull(session.getSession(), "the HTTP session is invalidated");

    Exchange next = pipeline.fire(view, "privileged");
    assertTrue(next.sessionExpired(), "the old session id is of no further use: " + next.body());
    assertEquals(1, WorkView.ACTIONS.get());
  }

  @Test
  @DisplayName("(b) the absolute lifetime is enforced the same way")
  void absoluteLifetime_requestIsConsumed() {
    login("alice");
    // stay active until just before the cap, then cross it
    for (int i = 0; i < 28; i++) {
      clock.advance(Duration.ofMinutes(25));
      assertFalse(pipeline.fire(view, "privileged").sessionExpired());
    }
    clock.advance(Duration.ofMinutes(25));

    Exchange exchange = pipeline.fire(view, "privileged");

    assertTrue(exchange.sessionExpired(), exchange.body());
    assertEquals(28, WorkView.ACTIONS.get(), "the request that crosses the cap is not executed");
    assertEquals(SessionExpired.REASON_ABSOLUTE_LIFETIME, audit.single(SessionExpired.class).reason());
  }

  @Test
  @DisplayName("(c) automatic poll round-trips are no activity: a polling view runs into the idle timeout")
  void polls_doNotKeepTheSessionAlive() {
    login("alice");
    assertFalse(pipeline.fire(view, "privileged").sessionExpired());

    // five polls, six minutes apart: the session stays inside the idle timeout
    for (int i = 0; i < 5; i++) {
      clock.advance(Duration.ofMinutes(6));
      Exchange poll = pipeline.poll();
      assertNull(poll.failure());
      assertFalse(poll.sessionExpired(), "poll " + i + " is still inside the idle timeout: " + poll.body());
    }
    assertTrue(audit.events().isEmpty());

    // 36 minutes after the last user interaction - only polls happened in between
    clock.advance(Duration.ofMinutes(6));
    Exchange late = pipeline.poll();

    assertTrue(late.sessionExpired(), "polls must not have advanced the activity: " + late.body());
    assertEquals(SessionExpired.REASON_IDLE_TIMEOUT, audit.single(SessionExpired.class).reason());
    assertTrue(subjects.currentSubject(String.class).isEmpty());
  }

  @Test
  @DisplayName("(c) user interaction between the polls keeps the session alive")
  void interaction_keepsTheSessionAlive() {
    login("alice");
    for (int i = 0; i < 8; i++) {
      clock.advance(Duration.ofMinutes(6));
      assertFalse(pipeline.poll().sessionExpired());
      assertFalse(pipeline.fire(view, "privileged").sessionExpired(), "interaction " + i);
    }

    assertEquals(8, WorkView.ACTIONS.get());
    assertTrue(audit.events().isEmpty(), "48 minutes with a click every six minutes is no idle session");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));
  }

  @Test
  @DisplayName("(c) anonymous round-trips count: a login after a long anonymous visit is not idle at once")
  void loginAfterAnonymousBrowsing_isNotIdle() {
    clock.advance(Duration.ofMinutes(40));
    assertFalse(pipeline.fire(view, "privileged").sessionExpired(), "anonymous request");
    login("alice");

    Exchange exchange = pipeline.fire(view, "privileged");

    assertFalse(exchange.sessionExpired(), exchange.body());
    assertTrue(audit.events().isEmpty());
    assertEquals(2, WorkView.ACTIONS.get());
  }

  @Test
  @DisplayName("a heartbeat is neither an activity signal nor enforced")
  void heartbeat_isIgnored() {
    login("alice");
    assertFalse(pipeline.fire(view, "privileged").sessionExpired());

    // heartbeats alone do not keep the session alive ...
    for (int i = 0; i < 5; i++) {
      clock.advance(Duration.ofMinutes(6));
      assertNull(pipeline.heartbeat().failure());
    }
    clock.advance(Duration.ofMinutes(6));
    // ... and a heartbeat past the timeout is not what ends it
    assertFalse(pipeline.heartbeat().sessionExpired());
    assertTrue(audit.events().isEmpty(), "a heartbeat is not evaluated");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));

    assertTrue(pipeline.fire(view, "privileged").sessionExpired(), "the next client message is");
    assertEquals(SessionExpired.REASON_IDLE_TIMEOUT, audit.single(SessionExpired.class).reason());
  }

  @Test
  @DisplayName("(d) a message over the push channel ends an expired session before the push handler finds it")
  void pushMessage_expiredSession_isEnded() {
    login("alice");
    PushOutcome live = pipeline.pushMessage();
    assertNull(live.failure());
    assertTrue(live.sessionFound(), "a live session is handed to the push handler");
    assertTrue(audit.events().isEmpty());

    clock.advance(IDLE.plusMinutes(1));
    PushOutcome expired = pipeline.pushMessage();

    assertNull(expired.failure(), "requestStart must not fail");
    assertFalse(expired.sessionFound(),
        "the push handler must find no session, so it sends 'session expired' and drops the RPC");
    assertEquals(SessionExpired.REASON_IDLE_TIMEOUT, audit.single(SessionExpired.class).reason());
    assertTrue(subjects.currentSubject(String.class).isEmpty());
    assertNotEquals(VaadinSessionState.OPEN, session.getState());
    assertFalse(subjects.lockHeldOnAccess.contains(Boolean.FALSE),
        "the interceptor runs without the session lock and must take it itself");
  }

  @Test
  @DisplayName("(d) a push message of a live session counts as activity")
  void pushMessage_liveSession_advancesActivity() {
    login("alice");
    for (int i = 0; i < 8; i++) {
      clock.advance(Duration.ofMinutes(6));
      assertTrue(pipeline.pushMessage().sessionFound(), "message " + i);
    }
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("(d) the WebSocket-only transport is diagnosed, the default transport is not")
  void webSocketOnlyTransport_isDiagnosed() {
    SessionLifetimeListener listener = new SessionLifetimeListener(clock);
    PushConfiguration push = pipeline.ui().getPushConfiguration();

    push.setPushMode(PushMode.AUTOMATIC);
    push.setTransport(Transport.WEBSOCKET);
    assertTrue(listener.warnIfWebSocketOnly(push), "WEBSOCKET cannot rotate a session id");

    push.setTransport(Transport.WEBSOCKET_XHR);
    assertFalse(listener.warnIfWebSocketOnly(push), "the default sends client messages over XHR");

    push.setTransport(Transport.WEBSOCKET);
    push.setPushMode(PushMode.DISABLED);
    assertFalse(listener.warnIfWebSocketOnly(push), "without push there is no push transport");
  }

  // ── helpers ────────────────────────────────────────────────────

  /** Binds the subject on the test thread, which holds the session lock like a login RPC. */
  private void login(String subject) {
    subjects.setCurrentSubject(subject, String.class);
  }

  /** The kind of single-view application the finding is about: one privileged action. */
  @Route("sa55-work")
  public static class WorkView extends Div {
    static final AtomicInteger ACTIONS = new AtomicInteger();

    public WorkView() {
      getElement().addEventListener("privileged", event -> ACTIONS.incrementAndGet());
    }
  }

  /**
   * The real session-backed store, recording for every access whether the calling thread
   * holds the session lock.
   */
  static final class LockRecordingSubjectStore implements SubjectStore {
    final List<Boolean> lockHeldOnAccess = new CopyOnWriteArrayList<>();
    private final VaadinSessionSubjectStore delegate = new VaadinSessionSubjectStore();

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      record();
      return delegate.currentSubject(subjectType);
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      record();
      delegate.setCurrentSubject(subject, subjectType);
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      record();
      delegate.deleteCurrentSubject(subjectType);
    }

    private void record() {
      VaadinSession current = VaadinSession.getCurrent();
      if (current != null) {
        lockHeldOnAccess.add(current.hasLock());
      }
    }
  }

  /** A clock the test moves; shared by the listener and the policy. */
  static final class MovableClock extends Clock {
    private volatile Instant now;

    MovableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    @Override public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override public Instant instant() {
      return now;
    }
  }
}
