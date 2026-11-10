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

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.Exchange;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.internal.SessionObjects;
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

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613): "Revoke" ends the session. Two real sessions of one service - the
 * user's, driven through {@code VaadinService.handleRequest} on a thread without the session
 * lock, and the administrator's, from whose thread the revoke is issued.
 */
@DisplayName("JS-SEC-131 — a revoked session is ended, the administrator's is not")
class VaadinSessionRevocationPipelineTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final InMemorySessionStore store = new InMemorySessionStore();
  private final VaadinSessionSubjectStore subjects = new VaadinSessionSubjectStore();

  private RequestPipeline pipeline;
  /** Strong references: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession bobSession;
  private SessionObjects admin;
  private UserView view;
  private SessionRecord bobRecord;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    SubjectStores.setSubjectStore(subjects);
    VaadinSessionRevocation.useSessionStore(store);
    UserView.ACTIONS.set(0);

    pipeline = RequestPipeline.start(Clock.systemUTC(), UserView.class);
    bobSession = pipeline.session();
    view = pipeline.navigate(UserView.class);

    // bob logs in; the application records the session, as a LoginView does in onSessionRotated
    subjects.setCurrentSubject("bob", String.class);
    bobRecord = record(pipeline.httpSessionId(), "bob");
    store.save(bobRecord);
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
  @DisplayName("revoke on this node: the user's session ends at once, the next RPC is refused, the administrator stays logged in")
  void revoke_endsTheUsersSession_notTheAdministrators() {
    assertFalse(pipeline.fire(view, "work").sessionExpired());
    assertEquals(1, UserView.ACTIONS.get());

    // the administrator works in a second session of the same service
    admin = pipeline.newSession();
    VaadinSession adminSession = admin.getSession();
    pipeline.releaseLock();
    actAs(admin);
    subjects.setCurrentSubject("alice", String.class);
    SessionRecord adminRecord = record(admin.getHttpSession().getId(), "alice");
    store.save(adminRecord);

    boolean live = VaadinSessionRevocation.revoke(bobRecord);

    assertTrue(live, "bob's session lives on this node");
    assertSame(adminSession, VaadinSession.getCurrent(), "the administrator's thread keeps its own session");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class),
        "the administrator must not be logged out by revoking somebody else");
    assertEquals(VaadinSessionState.OPEN, adminSession.getState());
    assertTrue(store.findById(bobRecord.sessionId()).isEmpty(), "the record is removed");
    assertTrue(store.findById(adminRecord.sessionId()).isPresent());

    // bob's session is gone without any request of bob
    CurrentInstance.clearAll();
    pipeline.reacquireLock();
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState(), "the revoked session is closed at once");
    assertNull(bobSession.getSession(), "its HTTP session is invalidated");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals("bob", invalidated.subjectId(), "the audit names the revoked subject");
    assertEquals(bobRecord.sessionId().value(), invalidated.sessionId());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());

    // bob's next RPC and everything after it is refused
    Exchange refused = pipeline.fire(view, "work");
    assertTrue(refused.sessionExpired(), refused.body());
    assertEquals(1, UserView.ACTIONS.get(), "the revoked user's RPC must not run");
    assertNull(bobSession.getAttribute(String.class), "bob's subject is dropped");
  }

  @Test
  @DisplayName("revoke on another node (record removed): the next RPC is consumed and the session ended")
  void recordRemovedElsewhere_nextRequestIsRefused() {
    assertFalse(pipeline.fire(view, "work").sessionExpired(), "the first request finds the record");

    // another node handled the Revoke click: only the shared store changed
    store.delete(bobRecord.sessionId());
    Exchange refused = pipeline.fire(view, "work");

    assertNull(refused.failure());
    assertTrue(refused.sessionExpired(), refused.body());
    assertEquals(1, UserView.ACTIONS.get(), "the RPC of the revoked session must not run");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals("bob", invalidated.subjectId());
    assertEquals(bobRecord.sessionId().value(), invalidated.sessionId());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState());
    assertNull(bobSession.getAttribute(String.class));
  }

  @Test
  @DisplayName("a record marked REVOKED ends the session on its next request, even on its first")
  void recordMarkedRevoked_nextRequestIsRefused() {
    store.save(bobRecord.withStatus(SessionStatus.REVOKED));

    Exchange refused = pipeline.fire(view, "work");

    assertTrue(refused.sessionExpired(), refused.body());
    assertEquals(0, UserView.ACTIONS.get());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, audit.single(SessionInvalidated.class).reason());
  }

  @Test
  @DisplayName("a revoked session is refused on navigation as well")
  void recordMarkedRevoked_navigationDropsTheSubject() {
    store.save(bobRecord.withStatus(SessionStatus.REVOKED));

    pipeline.navigate(UserView.class);

    assertNull(bobSession.getAttribute(String.class), "the subject is dropped before the view is entered");
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, audit.single(SessionInvalidated.class).reason());
  }

  @Test
  @DisplayName("an EXPIRED record is derived data and does not end a session the live policy calls active")
  void recordMarkedExpired_doesNotEndTheSession() {
    store.save(bobRecord.withStatus(SessionStatus.EXPIRED));

    Exchange exchange = pipeline.fire(view, "work");

    assertFalse(exchange.sessionExpired(), exchange.body());
    assertEquals(1, UserView.ACTIONS.get());
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("a session the application never recorded is not affected by the store check")
  void unrecordedSession_isNotAffected() {
    store.delete(bobRecord.sessionId());

    assertFalse(pipeline.fire(view, "work").sessionExpired(), "no record was ever seen for this session");
    assertFalse(pipeline.fire(view, "work").sessionExpired());
    assertEquals(2, UserView.ACTIONS.get());
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("revoking an id no live session carries reports that nothing was found")
  void terminate_unknownSession_findsNothing() {
    pipeline.releaseLock();

    assertFalse(VaadinSessionRevocation.terminate(SessionId.of("no-such-session"), "nobody"));

    pipeline.reacquireLock();
    assertEquals(VaadinSessionState.OPEN, bobSession.getState());
    assertTrue(audit.events().isEmpty());
  }

  // ── helpers ────────────────────────────────────────────────────

  private static SessionRecord record(String sessionId, String subject) {
    Instant now = Instant.now();
    return new SessionRecord(SessionId.of(sessionId), SubjectId.of(subject), TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }

  /** Binds another session to the test thread, as its request thread would have it. */
  private static void actAs(SessionObjects other) {
    CurrentInstance.clearAll();
    VaadinSession.setCurrent(other.getSession());
    CurrentInstance.set(VaadinRequest.class, other.getRequest());
  }

  @Route("sa31-user")
  public static class UserView extends Div {
    static final AtomicInteger ACTIONS = new AtomicInteger();

    public UserView() {
      getElement().addEventListener("work", event -> ACTIONS.incrementAndGet());
    }
  }
}
