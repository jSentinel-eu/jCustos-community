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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.InMemorySubjectSessionRegistry;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SweepingSessionStore;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-117 (CWE-532, CWE-522): the session producers of {@code jCustos-core} put the
 * {@link SessionRef} of a session id into the audit event, never the id. Only the logging
 * sink reduced it; the ring buffer, store-backed audit and the integrity chain kept a live
 * servlet session id or token. Every producer is driven with a real collaborator and a
 * recording audit service, and every event is checked for the raw id in any component.
 */
@DisplayName("JS-SEC-117 — core session producers emit a session reference, never the id")
class SessionRefAtTheProducerTest {

  /** A servlet-cookie-shaped session id; must never show up in an event. */
  private static final String RAW = "node0x7Q2bW9cN4kL1pZ8vT3yR6sD0fG5hJ";
  private static final String REF = SessionRef.of(RAW);
  private static final Instant LOGIN = Instant.parse("2026-11-16T08:00:00Z");

  @Test
  @DisplayName("TimeoutSessionPolicy: SessionCreated, both SessionExpired reasons and SessionInvalidated carry the reference")
  void timeoutSessionPolicy() {
    Recording audit = new Recording();
    TimeoutSessionPolicy.Config config = new TimeoutSessionPolicy.Config(
        Duration.ofMinutes(30), Duration.ofHours(12), false, "/login");

    new TimeoutSessionPolicy<String>(config, clockAt(LOGIN), audit).onLogin(context(LOGIN, LOGIN));
    new TimeoutSessionPolicy<String>(config, clockAt(LOGIN.plus(Duration.ofHours(13))), audit)
        .beforeNavigation(context(LOGIN, LOGIN.plus(Duration.ofHours(12))));
    new TimeoutSessionPolicy<String>(config, clockAt(LOGIN.plus(Duration.ofHours(2))), audit)
        .beforeNavigation(context(LOGIN, LOGIN));
    new TimeoutSessionPolicy<String>(config, clockAt(LOGIN), audit).onLogout(context(LOGIN, LOGIN));

    assertEquals(List.of(SessionCreated.class, SessionExpired.class, SessionExpired.class,
        SessionInvalidated.class), audit.types());
    assertEquals(List.of(SessionExpired.REASON_ABSOLUTE_LIFETIME, SessionExpired.REASON_IDLE_TIMEOUT),
        audit.events.stream().filter(SessionExpired.class::isInstance)
            .map(e -> ((SessionExpired) e).reason()).toList());
    assertEquals(List.of(REF, REF, REF, REF), audit.sessionIds());
    audit.assertRawIdNowhere();
  }

  @Test
  @DisplayName("TimeoutSessionPolicy: a reference passes unchanged, a missing id stays null")
  void timeoutSessionPolicyIdempotentAndNullSafe() {
    Recording audit = new Recording();
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        TimeoutSessionPolicy.Config.defaults(), clockAt(LOGIN), audit);

    policy.onLogin(new SessionContext<>("alice", REF, LOGIN, LOGIN, null, Map.of()));
    policy.onLogin(new SessionContext<>("alice", null, LOGIN, LOGIN, null, Map.of()));

    assertEquals(REF, ((SessionCreated) audit.events.get(0)).sessionId(),
        "a reference must not be hashed a second time");
    assertEquals(null, ((SessionCreated) audit.events.get(1)).sessionId());
  }

  @Test
  @DisplayName("SweepingSessionStore: the expiry of a record keyed by the raw id carries the reference")
  void sweepingSessionStore() {
    Recording audit = new Recording();
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(new SessionRecord(SessionId.of(RAW), SubjectId.of("alice"), TenantId.DEFAULT,
        LOGIN, LOGIN, JCustosVersion.INITIAL, SessionStatus.ACTIVE));
    Instant later = LOGIN.plus(Duration.ofDays(2));
    SweepingSessionStore store = new SweepingSessionStore(inner,
        new TimeoutSessionPolicy<>(TimeoutSessionPolicy.Config.defaults(), clockAt(later), null),
        Duration.ofDays(30), clockAt(later), audit);

    assertEquals(SessionStatus.EXPIRED, store.findAll().getFirst().status());

    assertEquals(List.of(SessionExpired.class), audit.types());
    assertEquals(List.of(REF), audit.sessionIds());
    assertEquals(RAW, inner.findAll().getFirst().sessionId().value(),
        "the store keeps its key; only the event is reduced");
    audit.assertRawIdNowhere();
  }

  @Test
  @DisplayName("SubjectClearingLogoutService: listeners get the session id, LogoutPerformed its reference")
  void subjectClearingLogoutService() {
    Recording audit = new Recording();
    InMemorySubjectSessionRegistry registry = new InMemorySubjectSessionRegistry();
    registry.register(SubjectId.of("alice"), RAW);
    List<String> seenByListener = new ArrayList<>();
    SubjectClearingLogoutService<String> service = new SubjectClearingLogoutService<>(
        new MapSubjectStore(), String.class, registry, audit);
    service.addListener((subject, sessionId, scope) -> seenByListener.add(sessionId));

    service.logout(SubjectId.of("alice"), LogoutScope.AllSessionsOfSubject);

    assertEquals(List.of(RAW), seenByListener, "a listener must still be able to end the session");
    assertEquals(List.of(LogoutPerformed.class), audit.types());
    assertEquals(List.of(REF), audit.sessionIds());
    audit.assertRawIdNowhere();
  }

  @Test
  @DisplayName("JCustosVersionEnforcer: SessionStale carries the reference of a raw id and keeps a reference")
  void jCustosVersionEnforcer() {
    Recording audit = new Recording();
    InMemoryJCustosVersionStore versions = new InMemoryJCustosVersionStore();
    versions.increment(new JCustosVersionKey(TenantId.DEFAULT, SubjectId.of("alice")));
    JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(versions, audit);

    enforcer.enforce(SubjectId.of("alice"), TenantId.DEFAULT, JCustosVersion.INITIAL, RAW, "/orders");
    enforcer.enforce(SubjectId.of("alice"), TenantId.DEFAULT, JCustosVersion.INITIAL, REF, "/orders");
    enforcer.enforce(SubjectId.of("alice"), TenantId.DEFAULT, JCustosVersion.INITIAL, null, "/orders");

    assertEquals(List.of(SessionStale.class, SessionStale.class, SessionStale.class), audit.types());
    assertEquals(java.util.Arrays.asList(REF, REF, null), audit.sessionIds());
    audit.assertRawIdNowhere();
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static SessionContext<String> context(Instant created, Instant lastActivity) {
    return new SessionContext<>("alice", RAW, created, lastActivity, "10.0.0.1", Map.of());
  }

  private static Clock clockAt(Instant instant) {
    return Clock.fixed(instant, ZoneOffset.UTC);
  }

  /** Hand-written audit service that keeps what it is given, as the ring buffer does. */
  private static final class Recording implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }

    List<Class<?>> types() {
      return events.stream().<Class<?>>map(Object::getClass).toList();
    }

    List<String> sessionIds() {
      List<String> ids = new ArrayList<>();
      for (AuditEvent event : events) {
        ids.add(switch (event) {
          case SessionCreated e -> e.sessionId();
          case SessionExpired e -> e.sessionId();
          case SessionInvalidated e -> e.sessionId();
          case SessionStale e -> e.sessionId();
          case LogoutPerformed e -> e.sessionId();
          default -> throw new AssertionError("unexpected event " + event.getClass());
        });
      }
      return ids;
    }

    void assertRawIdNowhere() {
      assertFalse(events.isEmpty());
      for (AuditEvent event : events) {
        assertFalse(event.toString().contains(RAW), "raw session id in " + event);
        assertTrue(event.toString().contains(REF) || event instanceof SessionStale,
            "the reference is missing in " + event);
      }
    }
  }

  /** Minimal subject store; the logout service clears the current subject through it. */
  private static final class MapSubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> subjects = new HashMap<>();

    @Override
    public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.ofNullable(subjectType.cast(subjects.get(subjectType)));
    }

    @Override
    public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      subjects.put(subjectType, subject);
    }

    @Override
    public <T> void deleteCurrentSubject(Class<T> subjectType) {
      subjects.remove(subjectType);
    }
  }
}
