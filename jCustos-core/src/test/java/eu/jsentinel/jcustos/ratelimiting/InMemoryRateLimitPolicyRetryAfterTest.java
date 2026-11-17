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
package eu.jsentinel.jcustos.ratelimiting;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The retry-after of a throttled request is the time until the oldest event in
 * the window has left it - {@code oldest + window - now}, plus one nanosecond
 * because the window includes its start - not the whole window (cross finding 8
 * of the V00.84.00 plan). A request at {@code now + retryAfter} is admitted, one a
 * nanosecond earlier is not.
 */
@DisplayName("InMemoryRateLimitPolicy - retry-after is the time until the oldest event leaves the window")
class InMemoryRateLimitPolicyRetryAfterTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Duration WINDOW = Duration.ofSeconds(60);
  private static final RateLimitKey KEY = new RateLimitKey(TenantId.DEFAULT, "ip:198.51.100.7");
  private static final Duration ONE_NANO = Duration.ofNanos(1);

  @Test
  @DisplayName("three events at T0, T0+10s, T0+20s, throttled at T0+30s: retry after 30 s + 1 ns")
  void retryAfterIsOldestPlusWindowMinusNow() {
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoAudit(), 3, WINDOW, clock);
    admitAt(policy, clock, T0, T0.plusSeconds(10), T0.plusSeconds(20));

    clock.set(T0.plusSeconds(30));
    RateLimitDecision.Throttled throttled = throttled(policy.tryAcquire(KEY));
    // oldest (T0) + window (60 s) - now (T0+30 s)
    assertEquals(Duration.ofSeconds(30).plus(ONE_NANO), throttled.retryAfter());
    assertEquals(InMemoryRateLimitPolicy.MIN_RETRY_AFTER, ONE_NANO);

    clock.set(T0.plusSeconds(45).plusMillis(250));
    assertEquals(Duration.ofMillis(14_750).plus(ONE_NANO), throttled(policy.tryAcquire(KEY))
        .retryAfter(), "the retry-after shrinks as the clock moves on");
  }

  @Test
  @DisplayName("at now + retryAfter the request is admitted; one nanosecond earlier it is still throttled")
  void retryAfterIsExact() {
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoAudit(), 2, WINDOW, clock);
    admitAt(policy, clock, T0.plusMillis(300), T0.plusSeconds(7));

    Instant now = T0.plusSeconds(12);
    clock.set(now);
    Duration retryAfter = throttled(policy.tryAcquire(KEY)).retryAfter();
    assertEquals(Duration.ofMillis(48_300).plus(ONE_NANO), retryAfter);

    clock.set(now.plus(retryAfter).minus(ONE_NANO)); // exactly T0+300ms + window: still inside
    RateLimitDecision.Throttled cusp = throttled(policy.tryAcquire(KEY));
    assertEquals(InMemoryRateLimitPolicy.MIN_RETRY_AFTER, cusp.retryAfter(),
        "on the cusp the event leaves one nanosecond later - never zero, never negative");

    clock.set(now.plus(retryAfter));
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY),
        "a client that waits exactly retryAfter finds a free slot");
  }

  @Test
  @DisplayName("once the oldest event has left, the next oldest sets the retry-after")
  void nextOldestTakesOver() {
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoAudit(), 3, WINDOW, clock);
    admitAt(policy, clock, T0, T0.plusSeconds(10), T0.plusSeconds(20));
    admitAt(policy, clock, T0.plusSeconds(60).plus(ONE_NANO)); // T0 has left: a fourth event

    clock.set(T0.plusSeconds(61));
    // the window now holds T0+10, T0+20 and T0+60s+1ns; T0+10 is the oldest
    assertEquals(Duration.ofSeconds(9).plus(ONE_NANO), throttled(policy.tryAcquire(KEY))
        .retryAfter());
  }

  @Test
  @DisplayName("a store that does not report the oldest event still yields the whole window")
  void storeWithoutOldestEventFallsBackToTheWindow() {
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new PrimitivesOnlyStore(), new NoAudit(), 1, WINDOW, clock);
    admitAt(policy, clock, T0);
    clock.set(T0.plusSeconds(50));
    assertEquals(WINDOW, throttled(policy.tryAcquire(KEY)).retryAfter());
  }

  @Test
  @DisplayName("Admission: the two-argument constructor reports no oldest event; null is refused")
  void admissionShapes() {
    RateLimitStore.Admission legacy = new RateLimitStore.Admission(false, 3);
    assertEquals(Optional.empty(), legacy.oldestInWindow());
    assertEquals(new RateLimitStore.Admission(false, 3, Optional.empty()), legacy);
    assertThrows(NullPointerException.class, () -> new RateLimitStore.Admission(true, 1, null));
    assertEquals(Optional.empty(),
        new PrimitivesOnlyStore().tryAdmit(KEY, T0, T0.minus(WINDOW), 1).oldestInWindow(),
        "the SPI default cannot tell the oldest event");
  }

  private static void admitAt(InMemoryRateLimitPolicy policy, MutableClock clock,
                              Instant... instants) {
    for (Instant at : instants) {
      clock.set(at);
      assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY), "admit at " + at);
    }
  }

  private static RateLimitDecision.Throttled throttled(RateLimitDecision decision) {
    return assertInstanceOf(RateLimitDecision.Throttled.class, decision);
  }

  /** Mutable clock that returns whatever instant the test set. */
  static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    void set(Instant at) {
      this.now = at;
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  /** Discards audit events. */
  static final class NoAudit implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  /** A store written before 00.84.00: the four primitives only, every default inherited. */
  static final class PrimitivesOnlyStore implements RateLimitStore {
    private final List<Instant> events = new CopyOnWriteArrayList<>();

    @Override
    public void recordEvent(RateLimitKey key, Instant at) {
      events.add(at);
    }

    @Override
    public int countSince(RateLimitKey key, Instant since) {
      return (int) events.stream().filter(event -> !event.isBefore(since)).count();
    }

    @Override
    public void reset(RateLimitKey key) {
      events.clear();
    }

    @Override
    public int purgeOlderThan(Instant cutoff) {
      return 0;
    }
  }
}
