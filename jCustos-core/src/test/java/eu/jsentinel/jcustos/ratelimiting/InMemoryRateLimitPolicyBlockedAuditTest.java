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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF11 (CWE-779): the requests of a blocked key are audited at most once a second per
 * key, and the next event carries the refusals that were held back. Real policy, real store, real
 * threads; time from a clock the test sets.
 */
@DisplayName("RF11 - InMemoryRateLimitPolicy audits a blocked key once a second, with the count")
class InMemoryRateLimitPolicyBlockedAuditTest {

  private static final Instant T0 = Instant.parse("2026-11-19T10:00:00Z");
  private static final Duration WINDOW = Duration.ofMinutes(1);
  private static final Duration SECOND = Duration.ofSeconds(1);
  /** The first throttle blocks the key for an hour. */
  private static final RateLimitEscalation ESCALATION =
      new RateLimitEscalation(1, Duration.ofMinutes(5), Duration.ofHours(1));
  private static final RateLimitKey ALICE = new RateLimitKey(TenantId.DEFAULT, "subject:alice");
  private static final RateLimitKey BOB = new RateLimitKey(TenantId.DEFAULT, "subject:bob");

  /** Clock whose instant the test sets; safe to read from other threads. */
  private static final class SettableClock extends Clock {
    private volatile Instant now;

    SettableClock(Instant now) {
      this.now = now;
    }

    void set(Instant at) {
      this.now = at;
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }
  }

  /** Thread-safe audit recorder. */
  private static final class Audit implements JCustosAuditService {
    final List<RateLimitExceeded> events = new CopyOnWriteArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(assertInstanceOf(RateLimitExceeded.class, event));
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }

    List<RateLimitExceeded> of(String scope) {
      return events.stream().filter(event -> event.scope().equals(scope)).toList();
    }

    long sum(String scope) {
      return of(scope).stream().mapToLong(RateLimitExceeded::eventsInWindow).sum();
    }
  }

  private static InMemoryRateLimitPolicy policy(Audit audit, Clock clock) {
    return new InMemoryRateLimitPolicy(new InMemoryRateLimitStore(), audit, 1, WINDOW, clock,
        ESCALATION);
  }

  /** One admitted request, then the throttle that blocks; leaves the audit empty. */
  private static void block(InMemoryRateLimitPolicy policy, RateLimitKey key, Audit audit) {
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(key));
    assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(key),
        "the escalating throttle");
    assertEquals(1, audit.events.size(), "the throttle that starts the block is audited as before");
    assertEquals(1, audit.events.getFirst().eventsInWindow(), "with the events in the window");
    audit.events.clear();
  }

  private static void refuse(InMemoryRateLimitPolicy policy, RateLimitKey key, int times) {
    for (int i = 0; i < times; i++) {
      assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(key));
    }
  }

  @Test
  @DisplayName("1 000 blocked requests within one second: one event; the first one a second later carries 1 000")
  void floodOfABlockedKeyIsAuditedOnceASecond() {
    Audit audit = new Audit();
    SettableClock clock = new SettableClock(T0);
    InMemoryRateLimitPolicy policy = policy(audit, clock);
    block(policy, ALICE, audit);

    Instant first = T0.plusMillis(1);
    clock.set(first);
    refuse(policy, ALICE, 600);
    clock.set(first.plus(SECOND).minusNanos(1));
    refuse(policy, ALICE, 400);
    assertEquals(1, audit.events.size(), "one event for 1 000 blocked requests within one second");
    RateLimitExceeded event = audit.events.getFirst();
    assertEquals("subject:alice", event.scope());
    assertEquals("alice", event.subjectId());
    assertEquals(1, event.limit());
    assertEquals(WINDOW, event.window());
    assertEquals(1, event.eventsInWindow(), "the first refusal stands for itself");
    assertEquals(first, event.timestamp());

    Instant next = first.plus(SECOND);
    clock.set(next);
    RateLimitDecision.Blocked decision = assertInstanceOf(RateLimitDecision.Blocked.class,
        policy.tryAcquire(ALICE));
    assertEquals(1, decision.eventsInWindow(), "the decision still reports the events in the window");
    assertEquals(2, audit.events.size());
    assertEquals(1_000, audit.events.get(1).eventsInWindow(), "999 held back + the publishing one");
    assertEquals(next, audit.events.get(1).timestamp());
    assertEquals(1_001, audit.sum("subject:alice"), "summed: every blocked request, once");
  }

  @Test
  @DisplayName("two blocked keys are audited independently")
  void keysAreIndependent() {
    Audit audit = new Audit();
    SettableClock clock = new SettableClock(T0);
    InMemoryRateLimitPolicy policy = policy(audit, clock);
    block(policy, ALICE, audit);
    block(policy, BOB, audit);

    clock.set(T0.plusMillis(10));
    refuse(policy, ALICE, 50);
    refuse(policy, BOB, 20);
    assertEquals(1, audit.of("subject:alice").size());
    assertEquals(1, audit.of("subject:bob").size(), "Alice's flood does not silence Bob");

    clock.set(T0.plusMillis(10).plus(SECOND));
    refuse(policy, BOB, 1);
    assertEquals(List.of(1, 20), audit.of("subject:bob").stream()
        .map(RateLimitExceeded::eventsInWindow).toList());
    assertEquals(1, audit.of("subject:alice").size(), "Alice's count waits for Alice");
  }

  @Test
  @DisplayName("purgeOldEvents publishes the held-back refusals once their second is over")
  void purgeFlushesHeldBackRefusals() {
    Audit audit = new Audit();
    SettableClock clock = new SettableClock(T0);
    InMemoryRateLimitPolicy policy = policy(audit, clock);
    block(policy, ALICE, audit);
    clock.set(T0.plusMillis(1));
    refuse(policy, ALICE, 25);

    clock.set(T0.plusMillis(500));
    policy.purgeOldEvents();
    assertEquals(1, audit.events.size(), "not before the second is over");

    clock.set(T0.plusMillis(1).plus(SECOND));
    policy.purgeOldEvents();
    assertEquals(2, audit.events.size());
    assertEquals(24, audit.events.get(1).eventsInWindow(), "the trailing burst, published by the purge");
    assertEquals(25, audit.sum("subject:alice"));
    assertEquals(0, policy.blockedRefusalAudit().pendingRefusals());

    clock.set(T0.plusSeconds(5));
    policy.purgeOldEvents();
    assertEquals(0, policy.blockedRefusalAudit().trackedKeyCount(),
        "a key with nothing counted is forgotten");
    assertEquals(2, audit.events.size());
  }

  @Test
  @DisplayName("10 002 blocked keys within one second: 10 000 tracked, the last two counted under the aggregate scope")
  void freshKeysBeyondTheBoundAreAggregated() {
    Audit audit = new Audit();
    SettableClock clock = new SettableClock(T0);
    InMemoryRateLimitPolicy policy = policy(audit, clock);
    int bound = RefusalAuditThrottle.MAX_TRACKED_KEYS;
    List<RateLimitKey> keys = new ArrayList<>();
    for (int i = 0; i < bound + 2; i++) {
      RateLimitKey key = new RateLimitKey(TenantId.DEFAULT, "ip:10.0." + (i / 256) + "." + (i % 256));
      keys.add(key);
      policy.tryAcquire(key); // admitted
      policy.tryAcquire(key); // throttled, and blocked
    }
    audit.events.clear();

    clock.set(T0.plusMillis(1));
    for (RateLimitKey key : keys) {
      refuse(policy, key, 2);
    }
    assertEquals(bound, policy.blockedRefusalAudit().trackedKeyCount(), "the bound holds");
    List<RateLimitExceeded> aggregated = audit.of(InMemoryRateLimitPolicy.UNTRACKED_KEYS_AUDIT_SCOPE);
    assertEquals(1, aggregated.size(), "one aggregate event, at once");
    RateLimitExceeded aggregate = aggregated.getFirst();
    assertEquals("", aggregate.subjectId());
    assertEquals(1, aggregate.limit());
    assertEquals(WINDOW, aggregate.window());
    assertEquals(1, aggregate.eventsInWindow());
    assertEquals(bound + 1, audit.events.size(), "one event per tracked key plus the aggregate");

    long refused = 2L * keys.size();
    long published = audit.events.stream().mapToLong(RateLimitExceeded::eventsInWindow).sum();
    assertEquals(refused, published + policy.blockedRefusalAudit().pendingRefusals(),
        "no refusal lost");
    clock.set(T0.plusMillis(1).plus(SECOND));
    policy.purgeOldEvents();
    assertEquals(refused, audit.events.stream().mapToLong(RateLimitExceeded::eventsInWindow).sum());
    assertEquals(4, audit.sum(InMemoryRateLimitPolicy.UNTRACKED_KEYS_AUDIT_SCOPE),
        "the two untracked keys, refused twice each");
  }

  @Test
  @DisplayName("32 threads send 100 requests each for one blocked key: one event; the next carries all 3 200")
  void concurrentRefusalsOfOneKey() throws Exception {
    Audit audit = new Audit();
    SettableClock clock = new SettableClock(T0);
    InMemoryRateLimitPolicy policy = policy(audit, clock);
    block(policy, ALICE, audit);
    int threads = 32;
    int perThread = 100;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      CountDownLatch ready = new CountDownLatch(threads);
      CountDownLatch start = new CountDownLatch(1);
      List<Future<?>> outcomes = new ArrayList<>();
      for (int t = 0; t < threads; t++) {
        outcomes.add(pool.submit(() -> {
          ready.countDown();
          start.await();
          refuse(policy, ALICE, perThread);
          return null;
        }));
      }
      assertTrue(ready.await(10, TimeUnit.SECONDS));
      start.countDown();
      for (Future<?> outcome : outcomes) {
        outcome.get(30, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }
    int total = threads * perThread;
    assertEquals(1, audit.events.size(), "exactly one event within the second");
    assertEquals(total - 1, policy.blockedRefusalAudit().pendingRefusals());

    clock.set(T0.plus(SECOND));
    refuse(policy, ALICE, 1);
    assertEquals(2, audit.events.size());
    assertEquals(total, audit.events.get(1).eventsInWindow());
    assertEquals(total + 1, audit.sum("subject:alice"));
  }

  @Test
  @DisplayName("throttles are audited one by one, as before: the fix covers blocked keys only")
  void throttlesAreStillAuditedEachTime() {
    Audit audit = new Audit();
    InMemoryRateLimitPolicy plain = new InMemoryRateLimitPolicy(new InMemoryRateLimitStore(), audit,
        1, WINDOW, Clock.fixed(T0, ZoneOffset.UTC));
    assertInstanceOf(RateLimitDecision.Allowed.class, plain.tryAcquire(ALICE));
    for (int i = 0; i < 5; i++) {
      assertInstanceOf(RateLimitDecision.Throttled.class, plain.tryAcquire(ALICE));
    }
    assertEquals(5, audit.events.size());
    audit.events.forEach(event -> assertEquals(1, event.eventsInWindow(),
        "the events in the window, as before"));
    assertNull(plain.blockedRefusalAudit(), "no throttle state without an escalation");
  }
}
