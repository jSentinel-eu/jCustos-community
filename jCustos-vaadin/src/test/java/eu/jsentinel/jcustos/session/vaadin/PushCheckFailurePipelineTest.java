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

import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerPipelineTest.DriftLoginView;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.PushOutcome;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimePipelineTest.LockRecordingSubjectStore;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimePipelineTest.WorkView;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review XR05 (CWE-636): on the push channel the per-request checks run in a request
 * interceptor, and Vaadin's push handler executes the message as soon as the interceptor
 * returns. A check that threw was logged and the message ran - fail-open, while the same
 * exception stops an XHR request. Now a failing check ends the session, so the push handler
 * finds none and drops the message. The one documented exception stays: a {@code SessionStore}
 * that cannot be read skips the revocation check (JS-SEC-131).
 */
@DisplayName("XR05 - a check that fails on the push channel ends the session")
class PushCheckFailurePipelineTest {

  private static final SubjectId ALICE = new SubjectId("alice");

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final LockRecordingSubjectStore subjects = new LockRecordingSubjectStore();
  private final AtomicBoolean failing = new AtomicBoolean();

  private RequestPipeline pipeline;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    SubjectStores.setSubjectStore(subjects);
  }

  @AfterEach
  void stop() {
    try {
      if (pipeline != null) {
        pipeline.close();
      }
    } finally {
      JCustosServiceResolver.resetAll();
      LoginListeners.reset();
      SubjectStores.reset();
      VaadinSessionRevocation.reset();
    }
  }

  @Test
  @DisplayName("lifetime check: a session policy that throws ends the session instead of letting the message run")
  void failingLifetimeCheck_endsTheSession() {
    JCustosServiceResolver.setSessionPolicy(new FailingPolicy(failing));
    startPipeline(List.of());
    assertTrue(pipeline.pushMessage().sessionFound(), "precondition: a working check lets the message through");

    failing.set(true);
    PushOutcome outcome = pipeline.pushMessage();

    assertEnded(outcome);
  }

  @Test
  @DisplayName("drift check: a security-version store that throws ends the session instead of letting the message run")
  void failingDriftCheck_endsTheSession() {
    InMemoryJCustosVersionStore versions = new InMemoryJCustosVersionStore();
    JCustosVersionEnforcerListener drift = new JCustosVersionEnforcerListener(
        new JCustosVersionEnforcer(new FailingVersionStore(versions, failing), audit), DriftLoginView.class);
    startPipeline(List.of(drift::register));
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-xr05");
    assertTrue(pipeline.pushMessage().sessionFound(), "precondition: a working check lets the message through");

    failing.set(true);
    PushOutcome outcome = pipeline.pushMessage();

    assertEnded(outcome);
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(), "the snapshot is cleared");
  }

  @Test
  @DisplayName("the documented exception stays: an unreadable SessionStore skips the revocation check only")
  void unreadableSessionStore_messagePasses() {
    VaadinSessionRevocation.useSessionStore(new FailingSessionStore(failing));
    startPipeline(List.of());
    failing.set(true);

    PushOutcome outcome = pipeline.pushMessage();

    assertNull(outcome.failure());
    assertTrue(outcome.sessionFound(), "a failing store must not log every user out (JS-SEC-131)");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));
    assertEquals(VaadinSessionState.OPEN, session.getState());
  }

  private void startPipeline(List<VaadinServiceInitListener> extra) {
    pipeline = RequestPipeline.start(Clock.systemUTC(), extra, WorkView.class, DriftLoginView.class);
    session = pipeline.session();
    pipeline.navigate(WorkView.class);
    subjects.setCurrentSubject("alice", String.class);
    audit.clear();
  }

  private void assertEnded(PushOutcome outcome) {
    assertNull(outcome.failure(), "requestStart must not fail");
    assertFalse(outcome.sessionFound(),
        "the push handler must find no session, so it drops the message instead of executing it");
    assertTrue(subjects.currentSubject(String.class).isEmpty(), "the subject is dropped");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the Vaadin session is closed");
    assertNull(session.getSession(), "the HTTP session is invalidated");
  }

  /** A lifetime policy that fails on demand - the stand-in for a policy whose backend is down. */
  private static final class FailingPolicy implements SessionPolicy<Object> {
    private final AtomicBoolean failing;

    FailingPolicy(AtomicBoolean failing) {
      this.failing = failing;
    }

    @Override public SessionDecision beforeNavigation(SessionContext<Object> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      if (failing.get()) {
        throw new IllegalStateException("policy backend unreachable");
      }
      return SessionPolicyDecision.active();
    }
  }

  /** A real version store that fails on demand. */
  private static final class FailingVersionStore implements JCustosVersionStore {
    private final JCustosVersionStore delegate;
    private final AtomicBoolean failing;

    FailingVersionStore(JCustosVersionStore delegate, AtomicBoolean failing) {
      this.delegate = delegate;
      this.failing = failing;
    }

    @Override public JCustosVersion current(JCustosVersionKey key) {
      if (failing.get()) {
        throw new IllegalStateException("version store unreachable");
      }
      return delegate.current(key);
    }

    @Override public JCustosVersion increment(JCustosVersionKey key) {
      return delegate.increment(key);
    }

    @Override public void reset(JCustosVersionKey key) {
      delegate.reset(key);
    }
  }

  /** A real session store whose reads fail on demand. */
  private static final class FailingSessionStore implements SessionStore {
    private final InMemorySessionStore delegate = new InMemorySessionStore();
    private final AtomicBoolean failing;

    FailingSessionStore(AtomicBoolean failing) {
      this.failing = failing;
    }

    @Override public void save(SessionRecord record) {
      delegate.save(record);
    }

    @Override public Optional<SessionRecord> findById(SessionId sessionId) {
      if (failing.get()) {
        throw new IllegalStateException("session store unreachable");
      }
      return delegate.findById(sessionId);
    }

    @Override public List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId) {
      return delegate.findBySubject(tenant, subjectId);
    }

    @Override public boolean delete(SessionId sessionId) {
      return delegate.delete(sessionId);
    }
  }
}
