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
package eu.jsentinel.jcustos.logout;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.InMemorySubjectStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.SessionId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 4c-4 — verifies that
 * {@link LogoutScope#AllSessionsOfSubject} cleanly removes every
 * persisted session of a subject when the registry is the
 * {@link StoreBackedSubjectSessionRegistry} from Phase 4b.
 */
@DisplayName("SubjectClearingLogoutService — AllSessionsOfSubject store-backed")
class SubjectClearingLogoutAllSessionsIntegrationTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("logout(ALICE, AllSessionsOfSubject) drops every persisted alice session and leaves bob's intact")
  void clearsAllAliceSessions() {
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry = new StoreBackedSubjectSessionRegistry(
        sessionStore, TenantId.DEFAULT, Clock.fixed(T0, ZoneOffset.UTC));
    registry.register(ALICE, "sid-alice-1");
    registry.register(ALICE, "sid-alice-2");
    registry.register(ALICE, "sid-alice-3");
    registry.register(BOB, "sid-bob-1");

    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingListener listener = new RecordingListener();
    SubjectClearingLogoutService<String> service = new SubjectClearingLogoutService<>(
        subjectStore, String.class, registry, audit);
    service.addListener(listener);

    service.logout(ALICE, LogoutScope.AllSessionsOfSubject);

    // Registry view: no more alice sessions, bob untouched
    assertTrue(registry.sessionsOf(ALICE).isEmpty());
    assertEquals(1, registry.sessionsOf(BOB).size());

    // Store view: the three alice records are gone, bob's record remains
    assertTrue(sessionStore.findById(new SessionId("sid-alice-1")).isEmpty());
    assertTrue(sessionStore.findById(new SessionId("sid-alice-2")).isEmpty());
    assertTrue(sessionStore.findById(new SessionId("sid-alice-3")).isEmpty());
    assertTrue(sessionStore.findById(new SessionId("sid-bob-1")).isPresent());

    // Audit: one LogoutPerformed per removed session
    List<AuditEvent> events = audit.published;
    assertEquals(3, events.size());
    Set<String> auditedSessions = new HashSet<>();
    for (AuditEvent ev : events) {
      LogoutPerformed lp = (LogoutPerformed) ev;
      assertEquals("alice", lp.subjectId());
      assertEquals(LogoutScope.AllSessionsOfSubject, lp.scope());
      auditedSessions.add(lp.sessionId());
    }
    // JS-SEC-117: the audit event carries the reference of each session id, never the id.
    assertEquals(Set.of(SessionRef.of("sid-alice-1"), SessionRef.of("sid-alice-2"),
        SessionRef.of("sid-alice-3")), auditedSessions);

    // Listener: one callback per removed session
    assertEquals(3, listener.callbacks.size());
    for (RecordingListener.Call c : listener.callbacks) {
      assertEquals(ALICE, c.subjectId);
      assertEquals(LogoutScope.AllSessionsOfSubject, c.scope);
    }
  }

  @Test
  @DisplayName("AllSessionsOfSubject on a subject with no sessions still fans out exactly one event with null sessionId")
  void emptySubjectStillFiresOnce() {
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry = new StoreBackedSubjectSessionRegistry(
        sessionStore, TenantId.DEFAULT, Clock.fixed(T0, ZoneOffset.UTC));

    CollectingAuditService audit = new CollectingAuditService();
    SubjectClearingLogoutService<String> service = new SubjectClearingLogoutService<>(
        new InMemorySubjectStore(), String.class, registry, audit);

    service.logout(ALICE, LogoutScope.AllSessionsOfSubject);

    assertEquals(1, audit.published.size());
    LogoutPerformed lp = (LogoutPerformed) audit.published.get(0);
    assertEquals("alice", lp.subjectId());
    assertEquals(null, lp.sessionId());
    assertEquals(LogoutScope.AllSessionsOfSubject, lp.scope());
  }

  private static final class CollectingAuditService implements JCustosAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }

  private static final class RecordingListener implements LogoutListener {
    record Call(SubjectId subjectId, String sessionId, LogoutScope scope) {}
    final List<Call> callbacks = new ArrayList<>();
    @Override
    public void onLogout(SubjectId subjectId, String sessionId, LogoutScope scope) {
      callbacks.add(new Call(subjectId, sessionId, scope));
    }
  }
}
