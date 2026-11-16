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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.81 session-lifecycle regression (real InMemorySessionStore + real
 * TimeoutSessionPolicy, no mocks) — pins the bug report "admin views show
 * weeks-old sessions as ACTIVE": before the sweep decorator no code path
 * ever wrote {@link SessionStatus#EXPIRED} and no retention purge existed.
 */
@DisplayName("SweepingSessionStore — lazy EXPIRED transition + retention purge (no mocks)")
class SweepingSessionStoreTest {

  private static final Instant LOGIN = Instant.parse("2026-08-01T10:00:00Z");

  /** Real recording audit service — core cannot depend on jCustos-test. */
  private static final class RecordingAuditService implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(eu.jsentinel.jcustos.audit.AuditQuery query) {
      return List.copyOf(events);
    }
  }

  private static SessionRecord activeSession(String sid, String subject, Instant at) {
    return new SessionRecord(new SessionId(sid), new SubjectId(subject),
        TenantId.DEFAULT, at, at, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }

  private static TimeoutSessionPolicy<Object> policy(Clock clock) {
    return new TimeoutSessionPolicy<>(
        new TimeoutSessionPolicy.Config(
            Duration.ofMinutes(30), Duration.ofHours(12), false, "/login"),
        clock, null);
  }

  private static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  @Test
  @DisplayName("a weeks-idle ACTIVE record is persisted as EXPIRED on findAll and audited once")
  void staleActiveRecordExpiresOnRead() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-stale", "alice", LOGIN));
    Instant weeksLater = LOGIN.plus(Duration.ofDays(21));
    RecordingAuditService audit = new RecordingAuditService();
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(weeksLater)), Duration.ofDays(30), fixed(weeksLater), audit);

    List<SessionRecord> all = store.findAll();

    assertEquals(1, all.size());
    assertEquals(SessionStatus.EXPIRED, all.get(0).status(),
        "the view must see the policy-true state, not stale ACTIVE");
    assertEquals(SessionStatus.EXPIRED,
        inner.findById(new SessionId("sid-stale")).orElseThrow().status(),
        "the transition must be persisted, not only projected");
    assertEquals(1, audit.events.size(), "exactly one SessionExpired per transition");
    SessionExpired expired = (SessionExpired) audit.events.get(0);
    assertEquals("alice", expired.subjectId());
    assertEquals(SessionRef.of("sid-stale"), expired.sessionId(), "JS-SEC-117: the reference, never the key");
    assertEquals("AbsoluteLifetimeExceeded", expired.reason(),
        "absolute lifetime trumps idle timeout — TimeoutSessionPolicy precedence");
  }

  @Test
  @DisplayName("an idle-timeout sweep carries the IdleTimeout reason")
  void idleTimeoutReason() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-idle", "bob", LOGIN));
    Instant fortyMinutesLater = LOGIN.plus(Duration.ofMinutes(40));
    RecordingAuditService audit = new RecordingAuditService();
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(fortyMinutesLater)), Duration.ofDays(30),
        fixed(fortyMinutesLater), audit);

    store.findById(new SessionId("sid-idle"));

    assertEquals("IdleTimeout", ((SessionExpired) audit.events.get(0)).reason());
  }

  @Test
  @DisplayName("a fresh ACTIVE record passes through untouched — no save, no audit")
  void freshActiveRecordUntouched() {
    InMemorySessionStore inner = new InMemorySessionStore();
    SessionRecord fresh = activeSession("sid-fresh", "carol", LOGIN);
    inner.save(fresh);
    Instant fiveMinutesLater = LOGIN.plus(Duration.ofMinutes(5));
    RecordingAuditService audit = new RecordingAuditService();
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(fiveMinutesLater)), Duration.ofDays(30),
        fixed(fiveMinutesLater), audit);

    Optional<SessionRecord> found = store.findById(new SessionId("sid-fresh"));

    assertEquals(Optional.of(fresh), found);
    assertTrue(audit.events.isEmpty());
  }

  @Test
  @DisplayName("the second read of an expired record does not audit again (single transition)")
  void expiredRecordAuditedOnlyOnce() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-once", "dave", LOGIN));
    Instant later = LOGIN.plus(Duration.ofHours(2));
    RecordingAuditService audit = new RecordingAuditService();
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(later)), Duration.ofDays(30), fixed(later), audit);

    store.findAll();
    store.findAll();

    assertEquals(1, audit.events.size());
  }

  @Test
  @DisplayName("a terminal record past retention is deleted and dropped from every read")
  void terminalRecordPurgedAfterRetention() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-old", "erin", LOGIN)
        .withStatus(SessionStatus.REVOKED));
    Instant pastRetention = LOGIN.plus(Duration.ofDays(31));
    RecordingAuditService audit = new RecordingAuditService();
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(pastRetention)), Duration.ofDays(30),
        fixed(pastRetention), audit);

    assertTrue(store.findAll().isEmpty(), "purged record must not be listed");
    assertTrue(store.findById(new SessionId("sid-old")).isEmpty());
    assertTrue(inner.findById(new SessionId("sid-old")).isEmpty(),
        "purge must delete from the underlying store");
  }

  @Test
  @DisplayName("a terminal record inside retention is kept for audit queries")
  void terminalRecordKeptInsideRetention() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-kept", "frank", LOGIN)
        .withStatus(SessionStatus.EXPIRED));
    Instant insideRetention = LOGIN.plus(Duration.ofDays(7));
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(insideRetention)), Duration.ofDays(30),
        fixed(insideRetention), new RecordingAuditService());

    List<SessionRecord> all = store.findAll();

    assertEquals(1, all.size());
    assertEquals(SessionStatus.EXPIRED, all.get(0).status());
  }

  @Test
  @DisplayName("findBySubject sweeps too — the enumeration a multi-session revoke relies on")
  void findBySubjectSweeps() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-a", "grace", LOGIN));
    inner.save(activeSession("sid-b", "grace", LOGIN.plus(Duration.ofDays(20))));
    Instant now = LOGIN.plus(Duration.ofDays(20)).plus(Duration.ofMinutes(5));
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(now)), Duration.ofDays(30), fixed(now),
        new RecordingAuditService());

    List<SessionRecord> sessions =
        store.findBySubject(TenantId.DEFAULT, new SubjectId("grace"));

    assertEquals(2, sessions.size());
    assertEquals(SessionStatus.EXPIRED, sessions.get(0).status(), "weeks-old session expired");
    assertEquals(SessionStatus.ACTIVE, sessions.get(1).status(), "fresh session stays active");
  }

  @Test
  @DisplayName("a failing audit sink never breaks the sweep")
  void auditFailureNeverBreaksTheSweep() {
    InMemorySessionStore inner = new InMemorySessionStore();
    inner.save(activeSession("sid-audit", "heidi", LOGIN));
    Instant later = LOGIN.plus(Duration.ofDays(1));
    SweepingSessionStore store = new SweepingSessionStore(
        inner, policy(fixed(later)), Duration.ofDays(30), fixed(later),
        new JCustosAuditService() {
          @Override
          public void publish(AuditEvent event) {
            throw new IllegalStateException("sink down");
          }

          @Override
          public List<AuditEvent> query(eu.jsentinel.jcustos.audit.AuditQuery query) {
            return List.of();
          }
        });

    List<SessionRecord> all = store.findAll();

    assertEquals(SessionStatus.EXPIRED, all.get(0).status());
  }
}
