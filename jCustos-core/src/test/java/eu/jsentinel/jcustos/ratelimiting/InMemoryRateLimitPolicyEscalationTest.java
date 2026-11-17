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
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicyRetryAfterTest.MutableClock;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicyRetryAfterTest.NoAudit;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicyRetryAfterTest.PrimitivesOnlyStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The opt-in escalation of {@link InMemoryRateLimitPolicy} (F10 b): after
 * {@code n} throttles within the escalation window the key is blocked for the
 * block duration and answered with {@link RateLimitDecision.Blocked}; without an
 * escalation that variant never occurs.
 */
@DisplayName("InMemoryRateLimitPolicy - opt-in escalation to RateLimitDecision.Blocked")
class InMemoryRateLimitPolicyEscalationTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final RateLimitKey KEY = new RateLimitKey(TenantId.DEFAULT, "ip:198.51.100.7");
  private static final Duration WINDOW = Duration.ofMinutes(1);
  private static final Duration BLOCK = Duration.ofMinutes(10);
  /** Three throttles within five minutes block the key for ten. */
  private static final RateLimitEscalation ESCALATION =
      new RateLimitEscalation(3, Duration.ofMinutes(5), BLOCK);

  @Test
  @DisplayName("without an escalation a key is throttled for ever and never blocked")
  void withoutEscalationNothingIsBlocked() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, new NoAudit(), 1, WINDOW, clock);
    assertEquals(Optional.empty(), policy.escalation());
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    for (int i = 1; i <= 50; i++) {
      clock.set(T0.plusMillis(i));
      assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY), "request " + i);
    }
    assertEquals(Optional.empty(), store.blockedUntil(KEY), "nothing was blocked");
    assertEquals(1, store.trackedKeyCount(), "and no throttle was counted under a key of its own");
  }

  @Test
  @DisplayName("the third throttle within five minutes blocks for ten; the block is lifted after ten")
  void blocksAfterExactlyNThrottlesAndLiftsAfterTheBlockDuration() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, new NoAudit(), 1, WINDOW, clock, ESCALATION);
    assertEquals(Optional.of(ESCALATION), policy.escalation());

    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    clock.set(T0.plusSeconds(1));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY), "throttle 1");
    clock.set(T0.plusSeconds(2));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY), "throttle 2");

    Instant third = T0.plusSeconds(3);
    clock.set(third);
    RateLimitDecision.Blocked blocked =
        assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY), "throttle 3");
    assertEquals(BLOCK, blocked.retryAfter());
    assertEquals(3, blocked.throttledCount());
    assertEquals(1, blocked.eventsInWindow());
    assertEquals(1, blocked.limit());
    assertEquals(WINDOW, blocked.window());
    assertEquals(Optional.of(third.plus(BLOCK)), store.blockedUntil(KEY));

    // while blocked: answered as blocked, nothing recorded
    clock.set(third.plusSeconds(90)); // the window is empty again, the block is not over
    RateLimitDecision.Blocked later = assertInstanceOf(RateLimitDecision.Blocked.class,
        policy.tryAcquire(KEY));
    assertEquals(BLOCK.minusSeconds(90), later.retryAfter());
    assertEquals(0, later.eventsInWindow(), "a blocked request records no event");
    assertEquals(1, store.countSince(KEY, T0.minusSeconds(1)),
        "only the admitted event at T0 was ever recorded");
    clock.set(third.plus(BLOCK).minusNanos(1));
    assertEquals(Duration.ofNanos(1), assertInstanceOf(RateLimitDecision.Blocked.class,
        policy.tryAcquire(KEY)).retryAfter());

    // the block ends at third + BLOCK
    clock.set(third.plus(BLOCK));
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY),
        "the block is lifted after its duration");
    // the throttles that caused the block are spent: three new ones block again
    clock.set(third.plus(BLOCK).plusSeconds(1));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    clock.set(third.plus(BLOCK).plusSeconds(2));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    clock.set(third.plus(BLOCK).plusSeconds(3));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY));
  }

  @Test
  @DisplayName("the throttles that caused a block are spent: after a short block the next throttle is no block")
  void throttlesThatCausedABlockAreSpent() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    MutableClock clock = new MutableClock(T0);
    // the block ends long before the three throttles leave the escalation window
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(store, new NoAudit(), 1, WINDOW,
        clock, new RateLimitEscalation(3, Duration.ofMinutes(30), Duration.ofMinutes(2)));
    driveToBlock(policy, clock);
    Instant lifted = T0.plusSeconds(3).plus(Duration.ofMinutes(2));
    clock.set(lifted);
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    clock.set(lifted.plusSeconds(1));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY),
        "the three throttles within the last 30 minutes already caused a block");
    clock.set(lifted.plusSeconds(2));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    clock.set(lifted.plusSeconds(3));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY),
        "three new throttles block again");
  }

  @Test
  @DisplayName("throttles further apart than the escalation window never add up to a block")
  void throttlesOutsideTheEscalationWindowDoNotCount() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(store, new NoAudit(), 1,
        Duration.ofSeconds(10), clock,
        new RateLimitEscalation(3, Duration.ofMinutes(1), BLOCK));
    for (int round = 0; round < 10; round++) {
      Instant start = T0.plusSeconds(40L * round);
      clock.set(start);
      assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY), "round " + round);
      clock.set(start.plusSeconds(1));
      // at most two throttles - 40 s apart - lie within any minute
      assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY), "round " + round);
    }
    assertEquals(Optional.empty(), store.blockedUntil(KEY));
  }

  @Test
  @DisplayName("the escalating throttle and every blocked request publish RateLimitExceeded")
  void blocksAreAudited() {
    CollectingAudit audit = new CollectingAudit();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), audit, 1, WINDOW, clock, ESCALATION);
    RateLimitKey subject = new RateLimitKey(TenantId.DEFAULT, "subject:alice");
    policy.tryAcquire(subject);
    for (int i = 1; i <= 5; i++) { // two throttles, the escalating one, two blocked requests
      clock.set(T0.plusSeconds(i));
      policy.tryAcquire(subject);
    }
    assertEquals(5, audit.published.size());
    for (AuditEvent event : audit.published) {
      RateLimitExceeded exceeded = assertInstanceOf(RateLimitExceeded.class, event);
      assertEquals("subject:alice", exceeded.scope());
      assertEquals("alice", exceeded.subjectId());
      assertEquals(1, exceeded.limit());
      assertEquals(WINDOW, exceeded.window());
    }
  }

  @Test
  @DisplayName("reset lifts the block")
  void resetLiftsTheBlock() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, new NoAudit(), 1, WINDOW, clock, ESCALATION);
    driveToBlock(policy, clock);
    policy.reset(KEY);
    assertEquals(Optional.empty(), store.blockedUntil(KEY));
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
  }

  @Test
  @DisplayName("reset forgets the throttles counted towards a block")
  void resetForgetsTheThrottles() {
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoAudit(), 1, WINDOW, clock, ESCALATION);
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    policy.reset(KEY);
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY),
        "the first throttle after the reset, not the third of a series");
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY));
  }

  @Test
  @DisplayName("purgeOldEvents keeps the throttles the escalation still counts")
  void purgeKeepsThrottlesWithinTheEscalationWindow() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, new NoAudit(), 1, WINDOW, clock, ESCALATION);
    policy.tryAcquire(KEY);
    clock.set(T0.plusSeconds(1));
    policy.tryAcquire(KEY);
    clock.set(T0.plusSeconds(2));
    policy.tryAcquire(KEY); // two throttles

    clock.set(T0.plusSeconds(180)); // beyond the window, within the escalation window
    assertEquals(0, policy.purgeOldEvents(),
        "the purge keeps what the escalation window still covers - the throttles above all");
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    clock.set(T0.plusSeconds(181));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY),
        "the third throttle within five minutes");

    clock.set(T0.plusSeconds(181).plus(BLOCK).plusSeconds(301));
    assertEquals(1, policy.purgeOldEvents(), "the event at T0+180 s is older than five minutes");
    assertEquals(Optional.empty(), store.blockedUntil(KEY),
        "the block that ended before the cutoff is dropped as well");
    assertEquals(0, store.trackedKeyCount());
  }

  @Test
  @DisplayName("of 48 parallel requests at the limit none is admitted, and the key ends up blocked")
  void parallelThrottlesEscalate() throws Exception {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(store, new NoAudit(), 1, WINDOW,
        Clock.fixed(T0, ZoneOffset.UTC), new RateLimitEscalation(5, Duration.ofMinutes(5), BLOCK));
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    int threads = 48;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    List<RateLimitDecision> decisions = new CopyOnWriteArrayList<>();
    try {
      CountDownLatch ready = new CountDownLatch(threads);
      CountDownLatch start = new CountDownLatch(1);
      List<Future<?>> outcomes = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        Callable<Void> caller = () -> {
          ready.countDown();
          start.await();
          decisions.add(policy.tryAcquire(KEY));
          return null;
        };
        outcomes.add(pool.submit(caller));
      }
      assertTrue(ready.await(10, TimeUnit.SECONDS));
      start.countDown();
      for (Future<?> outcome : outcomes) {
        outcome.get(30, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }
    long allowed = decisions.stream().filter(RateLimitDecision.Allowed.class::isInstance).count();
    long throttled = decisions.stream()
        .filter(RateLimitDecision.Throttled.class::isInstance).count();
    long blocked = decisions.stream().filter(RateLimitDecision.Blocked.class::isInstance).count();
    assertEquals(0, allowed);
    assertEquals(threads, throttled + blocked);
    assertTrue(blocked >= 1, "the burst must escalate");
    assertTrue(throttled >= 4, "four throttles come before the one that blocks: " + throttled);
    assertEquals(Optional.of(T0.plus(BLOCK)), store.blockedUntil(KEY));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY));
  }

  @Test
  @DisplayName("a store that keeps no blocks, or bounds a key below the threshold, is refused at construction")
  void escalationIsRefusedOverAStoreThatCannotCarryItOut() {
    NoAudit audit = new NoAudit();
    IllegalArgumentException noBlocks = assertThrows(IllegalArgumentException.class,
        () -> new InMemoryRateLimitPolicy(new PrimitivesOnlyStore(), audit, 1, WINDOW,
            Clock.systemUTC(), ESCALATION));
    assertTrue(noBlocks.getMessage().contains("keeps no blocks"), noBlocks.getMessage());
    assertInstanceOf(UnsupportedOperationException.class, noBlocks.getCause());
    // without an escalation the same store stays usable, as before 00.84.00
    assertEquals(1, new InMemoryRateLimitPolicy(new PrimitivesOnlyStore(), audit, 1, WINDOW)
        .limit());

    IllegalArgumentException bound = assertThrows(IllegalArgumentException.class,
        () -> new InMemoryRateLimitPolicy(new InMemoryRateLimitStore(10, 3), audit, 1, WINDOW,
            Clock.systemUTC(), new RateLimitEscalation(4, WINDOW, BLOCK)));
    assertTrue(bound.getMessage().contains("throttleThreshold 4 exceeds the 3 events"),
        bound.getMessage());
    assertThrows(NullPointerException.class, () -> new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), audit, 1, WINDOW, Clock.systemUTC(), null));
  }

  @Test
  @DisplayName("with an escalation the scopes of the throttle counts are reserved")
  void throttleScopesAreReserved() {
    RateLimitKey forged = new RateLimitKey(TenantId.DEFAULT,
        InMemoryRateLimitPolicy.THROTTLE_SCOPE_PREFIX + KEY.scope());
    InMemoryRateLimitPolicy escalating = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoAudit(), 1, WINDOW, Clock.systemUTC(), ESCALATION);
    assertThrows(IllegalArgumentException.class, () -> escalating.tryAcquire(forged));
    InMemoryRateLimitPolicy plain = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoAudit(), 1, WINDOW);
    assertInstanceOf(RateLimitDecision.Allowed.class, plain.tryAcquire(forged),
        "without an escalation nothing changes");
  }

  @Test
  @DisplayName("RateLimitEscalation and RateLimitDecision.Blocked validate their components")
  void invariants() {
    Duration minute = Duration.ofMinutes(1);
    assertThrows(IllegalArgumentException.class, () -> new RateLimitEscalation(0, minute, minute));
    assertThrows(NullPointerException.class, () -> new RateLimitEscalation(1, null, minute));
    assertThrows(NullPointerException.class, () -> new RateLimitEscalation(1, minute, null));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitEscalation(1, Duration.ZERO, minute));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitEscalation(1, minute, minute.negated()));

    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Blocked(-1, 1, minute, minute, 1));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Blocked(0, 0, minute, minute, 1));
    assertThrows(NullPointerException.class,
        () -> new RateLimitDecision.Blocked(0, 1, null, minute, 1));
    assertThrows(NullPointerException.class,
        () -> new RateLimitDecision.Blocked(0, 1, minute, null, 1));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Blocked(0, 1, minute, Duration.ZERO, 1));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Blocked(0, 1, minute, minute, -1));
    assertEquals(3, new RateLimitDecision.Blocked(0, 1, minute, minute, 3).throttledCount());
  }

  /** One admitted request, then three throttles: the third blocks. */
  private static void driveToBlock(InMemoryRateLimitPolicy policy, MutableClock clock) {
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
    for (int i = 1; i <= 2; i++) {
      clock.set(T0.plusSeconds(i));
      assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
    }
    clock.set(T0.plusSeconds(3));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY));
  }

  private static final class CollectingAudit implements JCustosAuditService {
    final List<AuditEvent> published = new CopyOnWriteArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      published.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(published);
    }
  }
}
