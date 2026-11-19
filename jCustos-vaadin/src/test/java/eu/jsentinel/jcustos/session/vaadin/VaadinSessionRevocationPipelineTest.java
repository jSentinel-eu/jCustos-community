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
import eu.jsentinel.jcustos.audit.SessionRef;
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
    assertEquals(SessionStatus.REVOKED, store.findById(bobRecord.sessionId()).orElseThrow().status(),
        "the record is kept as REVOKED, so every other node refuses the session (XR09-1)");
    assertEquals(SessionStatus.ACTIVE, store.findById(adminRecord.sessionId()).orElseThrow().status());

    // bob's session is gone without any request of bob
    CurrentInstance.clearAll();
    pipeline.reacquireLock();
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState(), "the revoked session is closed at once");
    assertNull(bobSession.getSession(), "its HTTP session is invalidated");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals("bob", invalidated.subjectId(), "the audit names the revoked subject");
    assertEquals(SessionRef.of(bobRecord.sessionId().value()), invalidated.sessionId(),
        "the audit carries the reference, never the session id (JS-SEC-117)");
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
    assertEquals(SessionRef.of(bobRecord.sessionId().value()), invalidated.sessionId(),
        "the audit carries the reference, never the session id (JS-SEC-117)");
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
  @DisplayName("F21: a revocation found by the request check audits the record's subject id without a resolver, as the clicking node does")
  void recordMarkedRevoked_withoutResolver_auditsTheRecordId() {
    JCustosServiceResolver.setSubjectIdResolver(null);
    store.save(record(pipeline.httpSessionId(), "inventory-7").withStatus(SessionStatus.REVOKED));

    Exchange refused = pipeline.fire(view, "work");

    assertTrue(refused.sessionExpired(), refused.body());
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals("inventory-7", invalidated.subjectId(),
        "the id the session inventory shows, not the identity handle");
  }

  @Test
  @DisplayName("XR09-1: a session revoked on another node before its first request is refused on that request")
  void revokedElsewhereBeforeTheFirstRequest_firstRequestIsRefused() {
    // bob has logged in and his record exists, but no request has consulted it on this node
    // yet. The administrator works on another node: there the revoke finds no live session.
    VaadinSessionRevocation.untrack(bobSession);
    pipeline.releaseLock();
    try {
      CurrentInstance.clearAll();
      assertFalse(VaadinSessionRevocation.revoke(bobRecord), "bob's session does not live on the other node");
    } finally {
      CurrentInstance.clearAll();
      pipeline.reacquireLock();
      VaadinSession.setCurrent(bobSession);
      VaadinSessionRevocation.track(bobSession);
    }

    Exchange refused = pipeline.fire(view, "work");

    assertTrue(refused.sessionExpired(), "the first request after the revoke must be refused: " + refused.body());
    assertEquals(0, UserView.ACTIONS.get(), "the revoked user's RPC must not run");
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, audit.single(SessionInvalidated.class).reason());
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState());
    assertEquals(Optional.of(SessionStatus.REVOKED),
        store.findById(bobRecord.sessionId()).map(SessionRecord::status));
  }

  @Test
  @DisplayName("XR09-1: revoke keeps a record the store no longer holds as a REVOKED record")
  void revokeOfAMissingRecord_writesTheRevocation() {
    store.delete(bobRecord.sessionId());
    VaadinSessionRevocation.untrack(bobSession);
    pipeline.releaseLock();
    try {
      CurrentInstance.clearAll();
      VaadinSessionRevocation.revoke(bobRecord);
    } finally {
      CurrentInstance.clearAll();
      pipeline.reacquireLock();
      VaadinSession.setCurrent(bobSession);
      VaadinSessionRevocation.track(bobSession);
    }

    assertTrue(pipeline.fire(view, "work").sessionExpired(),
        "a revoke must leave a revocation behind, even for a record the store had lost");
    SessionRecord kept = store.findById(bobRecord.sessionId()).orElseThrow();
    assertEquals(SessionStatus.REVOKED, kept.status());
    assertEquals(bobRecord.subjectId(), kept.subjectId());
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

  // ── records under the session reference (JS-SEC-117) ───────────

  @Test
  @DisplayName("revoke of a record keyed by the reference ends the user's session at once")
  void revokeByReference_endsTheUsersSessionAtOnce() {
    String liveId = pipeline.httpSessionId();
    store.delete(bobRecord.sessionId());
    SessionRecord byReference = record(SessionRef.of(liveId), "bob");
    store.save(byReference);
    assertFalse(pipeline.fire(view, "work").sessionExpired());

    admin = pipeline.newSession();
    pipeline.releaseLock();
    actAs(admin);
    subjects.setCurrentSubject("alice", String.class);

    boolean live = VaadinSessionRevocation.revoke(byReference);

    assertTrue(live, "the session is found by the reference of its live id");
    assertEquals(SessionStatus.REVOKED, store.findById(byReference.sessionId()).orElseThrow().status(),
        "the record is kept as REVOKED (XR09-1)");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));
    CurrentInstance.clearAll();
    pipeline.reacquireLock();
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState(),
        "the revoked session is closed at the click, not on its next request");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(SessionRef.of(liveId), invalidated.sessionId());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertTrue(pipeline.fire(view, "work").sessionExpired());
    assertEquals(1, UserView.ACTIONS.get(), "the revoked user's RPC must not run");
  }

  @Test
  @DisplayName("a record keyed by the reference and marked REVOKED ends the session on its next request")
  void referenceKeyedRecordMarkedRevoked_nextRequestIsRefused() {
    String liveId = pipeline.httpSessionId();
    store.delete(bobRecord.sessionId());
    store.save(record(SessionRef.of(liveId), "bob").withStatus(SessionStatus.REVOKED));

    Exchange refused = pipeline.fire(view, "work");

    assertTrue(refused.sessionExpired(), refused.body());
    assertEquals(0, UserView.ACTIONS.get());
    assertEquals(SessionRef.of(liveId), audit.single(SessionInvalidated.class).sessionId());
  }

  @Test
  @DisplayName("a record keyed by the reference and removed on another node ends the session on its next request")
  void referenceKeyedRecordRemovedElsewhere_nextRequestIsRefused() {
    String liveId = pipeline.httpSessionId();
    store.delete(bobRecord.sessionId());
    SessionRecord byReference = record(SessionRef.of(liveId), "bob");
    store.save(byReference);
    assertFalse(pipeline.fire(view, "work").sessionExpired(), "the first request finds the record");

    store.delete(byReference.sessionId());
    Exchange refused = pipeline.fire(view, "work");

    assertTrue(refused.sessionExpired(), refused.body());
    assertEquals(1, UserView.ACTIONS.get());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, audit.single(SessionInvalidated.class).reason());
  }

  @Test
  @DisplayName("terminate accepts the live id and its reference alike")
  void terminate_matchesIdAndReference() {
    String liveId = pipeline.httpSessionId();
    pipeline.releaseLock();

    assertTrue(VaadinSessionRevocation.terminate(SessionId.of(SessionRef.of(liveId)), "bob"));

    pipeline.reacquireLock();
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState());
    assertEquals(SessionRef.of(liveId), audit.single(SessionInvalidated.class).sessionId());
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
