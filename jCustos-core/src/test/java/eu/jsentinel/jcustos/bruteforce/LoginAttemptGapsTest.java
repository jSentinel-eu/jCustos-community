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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.MutableClock;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.RecordingAudit;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptLimits;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit-review additions to JS-SEC-122 / JS-SEC-123 (CWE-778, CWE-770): the store-backed policy
 * audits the lockout it causes, a failing audit sink is counted and reported instead of being
 * swallowed, and a failure that finds no room in a full table is counted and reported instead
 * of being lost. Real policies, real stores, a clock the test moves.
 */
@DisplayName("JS-SEC-122/123 — lockouts are audited, sink failures and unrecorded failures are reported")
class LoginAttemptGapsTest {

  private static final Instant T0 = Instant.parse("2026-11-16T10:00:00Z");
  /** 3 failures / 5 min window / 60 s lockout / 10 min cap. */
  private static final LoginAttemptConfiguration THREE = new LoginAttemptConfiguration(
      3, Duration.ofMinutes(5), Duration.ofSeconds(60), Duration.ofMinutes(10));
  /** One failure locks. */
  private static final LoginAttemptConfiguration ONE = new LoginAttemptConfiguration(
      1, Duration.ofMinutes(5), Duration.ofSeconds(60), Duration.ofMinutes(10));

  private static LoginAttemptContext ctx(String user, Instant at) {
    return new LoginAttemptContext(user, "10.0.0.1", null, at);
  }

  private static List<BruteForceLimitReached> limitEvents(RecordingAudit audit) {
    return audit.events.stream().filter(BruteForceLimitReached.class::isInstance)
        .map(BruteForceLimitReached.class::cast).toList();
  }

  private static void failedLogin(LoginAttemptPolicy policy, String user, Instant at) {
    assertInstanceOf(LoginAttemptDecision.Allowed.class, policy.beforeAttempt(ctx(user, at)));
    policy.recordFailure(ctx(user, at));
  }

  // ── XR07-3: the store-backed policy audits the lockout it causes ─────

  @Test
  @DisplayName("store-backed policy: the failure that locks the key publishes BruteForceLimitReached, the ones before do not")
  void storeBackedPolicyAuditsTheLockout() {
    MutableClock clock = new MutableClock(T0);
    RecordingAudit audit = new RecordingAudit();
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), THREE, TenantId.DEFAULT, clock,
        SubjectKeyCanonicalizer.defaults(), audit);

    failedLogin(policy, "victim", clock.instant());
    failedLogin(policy, "victim", clock.instant());
    assertTrue(limitEvents(audit).isEmpty(), "below the threshold");

    clock.advance(Duration.ofSeconds(1));
    failedLogin(policy, "victim", clock.instant());

    List<BruteForceLimitReached> events = limitEvents(audit);
    assertEquals(1, events.size());
    assertEquals("victim", events.get(0).username());
    assertEquals("10.0.0.1", events.get(0).clientAddress());
    assertEquals(3, events.get(0).failedAttempts());
    assertEquals(Duration.ofSeconds(60), events.get(0).lockoutDuration());
    assertEquals(3, audit.events.stream().filter(LoginFailed.class::isInstance).count());

    // the lockout runs out; the one attempt admitted then fails and locks the key again
    clock.advance(Duration.ofSeconds(61));
    failedLogin(policy, "victim", clock.instant());
    assertEquals(2, limitEvents(audit).size());
  }

  @Test
  @DisplayName("store-backed policy over a store with the SPI defaults audits the lockout as well")
  void storeBackedPolicyOverDefaultsAuditsTheLockout() {
    MutableClock clock = new MutableClock(T0);
    RecordingAudit audit = new RecordingAudit();
    InMemoryLoginAttemptStore real = new InMemoryLoginAttemptStore();
    // counter primitives only - the atomic operations come from the SPI defaults
    LoginAttemptStore countersOnly = new LoginAttemptStore() {
      @Override
      public void recordFailure(LoginAttemptKey key, Instant at) {
        real.recordFailure(key, at);
      }

      @Override
      public int failureCount(LoginAttemptKey key) {
        return real.failureCount(key);
      }

      @Override
      public java.util.Optional<Instant> lastFailureAt(LoginAttemptKey key) {
        return real.lastFailureAt(key);
      }

      @Override
      public void reset(LoginAttemptKey key) {
        real.reset(key);
      }
    };
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(countersOnly, THREE,
        TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), audit);

    for (int i = 0; i < 3; i++) {
      failedLogin(policy, "victim", clock.instant());
    }
    assertEquals(1, limitEvents(audit).size());
  }

  // ── XR07-4: a failing sink is counted and reported ───────────────────

  /** A sink that is down. */
  private static final class FailingAudit implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
      throw new IllegalStateException("audit sink unavailable");
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  @Test
  @DisplayName("a failing sink never breaks the login decision and every failed publication is counted, the warning rate-limited")
  void failingSinkIsCountedNotSwallowed() {
    MutableClock clock = new MutableClock(T0);
    FailingAudit sink = new FailingAudit();
    InMemoryLoginAttemptPolicy inMemory = new InMemoryLoginAttemptPolicy(THREE, clock, sink);
    StoreBackedLoginAttemptPolicy storeBacked = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), THREE, TenantId.DEFAULT, clock,
        SubjectKeyCanonicalizer.defaults(), sink);
    long failuresBefore = LoginFailureAudit.sinkFailures();
    long warningsBefore = LoginFailureAudit.warningsLogged();

    for (LoginAttemptPolicy policy : List.of(inMemory, storeBacked)) {
      for (int i = 0; i < 3; i++) {
        assertDoesNotThrow(() -> failedLogin(policy, "alice", clock.instant()));
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("alice", clock.instant())), "the throttle still works");
    }

    // per policy: three LoginFailed and one BruteForceLimitReached
    assertEquals(8L, LoginFailureAudit.sinkFailures() - failuresBefore);
    assertTrue(LoginFailureAudit.warningsLogged() >= 1L, "a failing sink is announced");
    assertTrue(LoginFailureAudit.warningsLogged() - warningsBefore <= 1L,
        "eight failures within a minute give at most one warning");
  }

  // ── XR07-9: a failure that finds no room is counted ──────────────────

  @Test
  @DisplayName("in-memory policy: a late failure that finds the table full of lockouts is counted and locks nothing")
  void policyCountsTheUnrecordedFailure() {
    MutableClock clock = new MutableClock(T0);
    RecordingAudit audit = new RecordingAudit();
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(ONE, clock, audit, 1);
    assertInstanceOf(LoginAttemptDecision.Allowed.class,
        policy.beforeAttempt(ctx("late", clock.instant())));
    clock.advance(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL.plusSeconds(1));
    failedLogin(policy, "locker", clock.instant()); // the one entry is a live lockout now
    assertEquals(1, limitEvents(audit).size());
    assertEquals(0L, policy.unrecordedFailureCount());

    policy.recordFailure(ctx("late", clock.instant()));

    assertEquals(1L, policy.unrecordedFailureCount());
    assertEquals(1, limitEvents(audit).size(), "an unstored failure announces no lockout");
    assertEquals(2, audit.events.stream().filter(LoginFailed.class::isInstance).count(),
        "the rejected login itself is still audited");
    assertEquals(1, policy.trackedCombinedKeyCount(), "the bound holds");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("late", clock.instant())), "the full table still refuses the key");
  }

  @Test
  @DisplayName("in-memory store: a late failure that finds the store full of lockouts is counted")
  void storeCountsTheUnrecordedFailure() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore(1);
    AttemptLimits limits = new AttemptLimits(1, Duration.ofMinutes(5), Duration.ofSeconds(60),
        InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL);
    LoginAttemptKey late = new LoginAttemptKey(TenantId.DEFAULT, "late", "10.0.0.1");
    LoginAttemptKey locker = new LoginAttemptKey(TenantId.DEFAULT, "locker", "10.0.0.1");
    Instant t1 = T0.plus(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL).plusSeconds(1);

    assertTrue(!store.tryBeginAttempt(late, T0, limits).blocked());
    assertTrue(!store.tryBeginAttempt(locker, t1, limits).blocked());
    assertTrue(store.completeFailure(locker, t1, limits).blocked());
    assertEquals(0L, store.unrecordedFailureCount());

    store.completeFailure(late, t1, limits);
    store.recordFailure(late, t1);

    assertEquals(2L, store.unrecordedFailureCount());
    assertEquals(0, store.failureCount(late));
    assertEquals(1, store.trackedKeyCount());
  }
}
