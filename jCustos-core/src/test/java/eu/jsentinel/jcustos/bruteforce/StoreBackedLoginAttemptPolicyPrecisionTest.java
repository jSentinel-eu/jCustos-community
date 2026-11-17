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

import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.MutableClock;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.RecordingAudit;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * CWE-778: {@link StoreBackedLoginAttemptPolicy} audits the lockout a failure causes also over a
 * store that keeps instants coarser than the clock - milliseconds, as a JDBC {@code TIMESTAMP(3)}
 * column, or whole seconds. Until 00.84.00 the policy compared the lockout the store reported
 * with {@code now + lockout} for equality, and over such a store no {@code BruteForceLimitReached}
 * was ever published. The stores here are hand-written delegates over the real
 * {@link InMemoryLoginAttemptStore} that cut every instant they are handed; the clock stands at a
 * sub-millisecond instant.
 */
@DisplayName("StoreBackedLoginAttemptPolicy - a store with coarse instants still gets its lockouts audited")
class StoreBackedLoginAttemptPolicyPrecisionTest {

  /** A clock reading that no millisecond or second store can keep exactly. */
  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z").plusNanos(123_456_789L);
  private static final LoginAttemptLimits LIMITS = LoginAttemptLimits.defaults();
  private static final int THRESHOLD = LIMITS.perAccount().failureThreshold();

  @Test
  @DisplayName("milliseconds: the failure that locks publishes exactly one BruteForceLimitReached")
  void millisecondStoreAuditsTheLockout() {
    assertOneLockoutAudited(ChronoUnit.MILLIS);
  }

  @Test
  @DisplayName("whole seconds: the failure that locks publishes exactly one BruteForceLimitReached")
  void secondStoreAuditsTheLockout() {
    assertOneLockoutAudited(ChronoUnit.SECONDS);
  }

  @Test
  @DisplayName("milliseconds: a spray that locks the client address is audited once, for the address")
  void millisecondStoreAuditsTheAddressLockout() {
    LoginAttemptLimits limits = LIMITS.withAddressLimit(new LoginAttemptLimits.AddressLimit(
        THRESHOLD, Duration.ofMinutes(15), Duration.ofMinutes(15), Duration.ofHours(4)));
    RecordingAudit audit = new RecordingAudit();
    MutableClock clock = new MutableClock(T0);
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new CoarseStore(new InMemoryLoginAttemptStore(), ChronoUnit.MILLIS), limits,
        TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), audit);

    for (int i = 0; i < THRESHOLD; i++) {
      clock.advance(Duration.ofNanos(1_000_001L)); // a little over a millisecond per guess
      LoginAttemptContext guess = new LoginAttemptContext("user-" + i, "10.0.0.1", null, T0);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(guess), "guess " + i);
      policy.recordFailure(guess);
    }

    List<BruteForceLimitReached> reached = limitReached(audit);
    assertEquals(1, reached.size(), "the address lockout is audited exactly once: " + reached);
    assertEquals("", reached.get(0).username(), "the lockout belongs to the address");
    assertEquals("10.0.0.1", reached.get(0).clientAddress());
  }

  @Test
  @DisplayName("a lockout an earlier failure started is not audited again by a later failure the store does not count into it")
  void anEarlierLockoutIsNotAuditedAgain() {
    RecordingAudit audit = new RecordingAudit();
    MutableClock clock = new MutableClock(T0);
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new FirstLockoutStays(new CoarseStore(new InMemoryLoginAttemptStore(), ChronoUnit.MILLIS)),
        LIMITS, TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), audit);
    lockAlice(policy, clock);
    assertEquals(1, limitReached(audit).size());

    // a failure reported two seconds later - an attempt that was in flight - while the store
    // keeps the lockout of the failure that caused it
    clock.advance(Duration.ofSeconds(2));
    policy.recordFailure(new LoginAttemptContext("alice", "10.0.0.1", null, T0));

    assertEquals(1, limitReached(audit).size(),
        "the lockout of the earlier failure ends more than the tolerance before now + lockout");
  }

  private static void assertOneLockoutAudited(ChronoUnit precision) {
    RecordingAudit audit = new RecordingAudit();
    MutableClock clock = new MutableClock(T0);
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new CoarseStore(new InMemoryLoginAttemptStore(), precision), LIMITS, TenantId.DEFAULT,
        clock, SubjectKeyCanonicalizer.defaults(), audit);

    lockAlice(policy, clock);

    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(new LoginAttemptContext("alice", "10.0.0.1", null, T0)));
    List<BruteForceLimitReached> reached = limitReached(audit);
    assertEquals(1, reached.size(),
        "one event for the failure that locked the tuple and the account key: " + reached);
    assertEquals("alice", reached.get(0).username());
    assertEquals(THRESHOLD, reached.get(0).failedAttempts());
  }

  private static void lockAlice(StoreBackedLoginAttemptPolicy policy, MutableClock clock) {
    for (int i = 0; i < THRESHOLD; i++) {
      clock.advance(Duration.ofNanos(1_234_567L));
      LoginAttemptContext guess = new LoginAttemptContext("alice", "10.0.0.1", null, T0);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(guess), "guess " + i);
      policy.recordFailure(guess);
    }
  }

  private static List<BruteForceLimitReached> limitReached(RecordingAudit audit) {
    return audit.events.stream()
        .filter(BruteForceLimitReached.class::isInstance)
        .map(BruteForceLimitReached.class::cast)
        .toList();
  }

  /**
   * A store that keeps instants at {@code precision}: every instant it is handed is cut before
   * it reaches the real store underneath, as a database column would cut it.
   */
  private static final class CoarseStore implements LoginAttemptStore {
    private final LoginAttemptStore inner;
    private final ChronoUnit precision;

    private CoarseStore(LoginAttemptStore inner, ChronoUnit precision) {
      this.inner = inner;
      this.precision = precision;
    }

    private Instant cut(Instant instant) {
      return instant.truncatedTo(precision);
    }

    @Override
    public void recordFailure(LoginAttemptKey key, Instant at) {
      inner.recordFailure(key, cut(at));
    }

    @Override
    public int failureCount(LoginAttemptKey key) {
      return inner.failureCount(key);
    }

    @Override
    public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
      return inner.lastFailureAt(key);
    }

    @Override
    public void reset(LoginAttemptKey key) {
      inner.reset(key);
    }

    @Override
    public AttemptStatus tryBeginAttempt(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.tryBeginAttempt(key, cut(now), limits);
    }

    @Override
    public AttemptStatus completeFailure(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.completeFailure(key, cut(now), limits);
    }

    @Override
    public AttemptStatus completeSuccess(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.completeSuccess(key, cut(now), limits);
    }

    @Override
    public void abandonAttempt(LoginAttemptKey key, Instant now) {
      inner.abandonAttempt(key, cut(now));
    }
  }

  /**
   * A store that does not move a live lockout: a failure reported while the key is locked is
   * counted, but the lockout keeps the end the failure that caused it gave it.
   */
  private static final class FirstLockoutStays implements LoginAttemptStore {
    private final LoginAttemptStore inner;

    private FirstLockoutStays(LoginAttemptStore inner) {
      this.inner = inner;
    }

    @Override
    public void recordFailure(LoginAttemptKey key, Instant at) {
      inner.recordFailure(key, at);
    }

    @Override
    public int failureCount(LoginAttemptKey key) {
      return inner.failureCount(key);
    }

    @Override
    public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
      return inner.lastFailureAt(key);
    }

    @Override
    public void reset(LoginAttemptKey key) {
      inner.reset(key);
    }

    @Override
    public AttemptStatus tryBeginAttempt(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.tryBeginAttempt(key, now, limits);
    }

    @Override
    public AttemptStatus completeFailure(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      AttemptStatus before = inner.tryBeginAttempt(key, now, limits);
      if (before.blocked() && before.failures() >= limits.failureThreshold()) {
        // the key is locked already: the reservation that tryBeginAttempt did not make stays
        // unmade, and the lockout keeps its end
        return AttemptStatus.blocked(before.failures() + 1, before.blockedUntil().get());
      }
      if (!before.blocked()) {
        inner.abandonAttempt(key, now); // only the probe reserved something
      }
      return inner.completeFailure(key, now, limits);
    }

    @Override
    public AttemptStatus completeSuccess(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.completeSuccess(key, now, limits);
    }

    @Override
    public void abandonAttempt(LoginAttemptKey key, Instant now) {
      inner.abandonAttempt(key, now);
    }
  }
}
