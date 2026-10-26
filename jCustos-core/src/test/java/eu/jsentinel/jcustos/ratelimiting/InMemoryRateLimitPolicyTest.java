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
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryRateLimitPolicy")
class InMemoryRateLimitPolicyTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final RateLimitKey IP_KEY = new RateLimitKey(TenantId.DEFAULT, "ip:1.2.3.4");
  private static final RateLimitKey ALICE_KEY =
      new RateLimitKey(TenantId.DEFAULT, "subject:alice");

  private static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  /** Mutable clock that returns whatever instant the caller set. */
  private static final class MutableClock extends Clock {
    private Instant now;
    MutableClock(Instant now) { this.now = now; }
    void set(Instant at) { this.now = at; }
    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    @Override public Instant instant() { return now; }
  }

  @Test
  @DisplayName("JS-SEC-078: 50 threads against limit 10 admit at most 10 (check-then-act is atomic)")
  void concurrentAcquireRespectsLimit() throws Exception {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, new CollectingAuditService(), 10, Duration.ofMinutes(1), fixed(T0));
    int threads = 50;
    java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
    java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
    java.util.concurrent.atomic.AtomicInteger allowed = new java.util.concurrent.atomic.AtomicInteger();
    try {
      List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(pool.submit(() -> {
          start.await(5, java.util.concurrent.TimeUnit.SECONDS);
          if (policy.tryAcquire(IP_KEY) instanceof RateLimitDecision.Allowed) {
            allowed.incrementAndGet();
          }
          return null;
        }));
      }
      start.countDown();
      for (java.util.concurrent.Future<?> f : futures) {
        f.get(10, java.util.concurrent.TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }
    assertEquals(10, allowed.get(), "exactly the limit may pass, never more");
    assertEquals(10, store.countSince(IP_KEY, T0.minusSeconds(1)));
  }

  @Test
  @DisplayName("first N events are admitted, the (N+1)-th is throttled and emits audit")
  void slidingWindowEnforcesLimit() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    CollectingAuditService audit = new CollectingAuditService();
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, audit, 3, Duration.ofMinutes(1), fixed(T0));

    for (int i = 0; i < 3; i++) {
      RateLimitDecision d = policy.tryAcquire(IP_KEY);
      assertInstanceOf(RateLimitDecision.Allowed.class, d);
      assertEquals(i + 1, d.eventsInWindow());
      assertEquals(3, d.limit());
    }

    RateLimitDecision fourth = policy.tryAcquire(IP_KEY);
    RateLimitDecision.Throttled t =
        assertInstanceOf(RateLimitDecision.Throttled.class, fourth);
    assertEquals(3, t.eventsInWindow());
    assertEquals(3, t.limit());
    assertEquals(Duration.ofMinutes(1), t.retryAfter());

    // a single RateLimitExceeded audit event
    assertEquals(1, audit.published.size());
    RateLimitExceeded event = (RateLimitExceeded) audit.published.get(0);
    assertEquals("ip:1.2.3.4", event.scope());
    assertEquals("", event.subjectId(), "non-subject scope leaves subjectId empty");
    assertEquals(3, event.limit());
    assertEquals(3, event.eventsInWindow());
  }

  @Test
  @DisplayName("subject:-prefixed scope surfaces subjectId on the audit event")
  void subjectScopeSurfacesSubjectId() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    CollectingAuditService audit = new CollectingAuditService();
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, audit, 1, Duration.ofMinutes(1), fixed(T0));

    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(ALICE_KEY));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(ALICE_KEY));

    RateLimitExceeded event = (RateLimitExceeded) audit.published.get(0);
    assertEquals("subject:alice", event.scope());
    assertEquals("alice", event.subjectId());
  }

  @Test
  @DisplayName("events slide out of the window over time, restoring capacity")
  void eventsExpireFromWindow() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    CollectingAuditService audit = new CollectingAuditService();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, audit, 2, Duration.ofMinutes(1), clock);

    // T0 → admit
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(IP_KEY));
    // T0+30s → admit
    clock.set(T0.plusSeconds(30));
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(IP_KEY));
    // T0+45s → throttle (2 events in last minute)
    clock.set(T0.plusSeconds(45));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(IP_KEY));
    // T0+90s → the T0 event has slid out; admit
    clock.set(T0.plusSeconds(90));
    RateLimitDecision recovered = policy.tryAcquire(IP_KEY);
    assertInstanceOf(RateLimitDecision.Allowed.class, recovered);
  }

  @Test
  @DisplayName("reset drops the per-key window")
  void resetClearsWindow() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    CollectingAuditService audit = new CollectingAuditService();
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, audit, 1, Duration.ofMinutes(1), fixed(T0));

    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(IP_KEY));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(IP_KEY));

    policy.reset(IP_KEY);
    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(IP_KEY));
  }

  @Test
  @DisplayName("purgeOldEvents drops events past the configured window")
  void purgeOldEvents() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    CollectingAuditService audit = new CollectingAuditService();
    MutableClock clock = new MutableClock(T0);
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, audit, 5, Duration.ofMinutes(1), clock);

    policy.tryAcquire(IP_KEY); // T0
    clock.set(T0.plusSeconds(30));
    policy.tryAcquire(IP_KEY); // T0+30
    clock.set(T0.plusSeconds(90));
    // T0 event is now older than now-window (T0+30); it must be purged
    int purged = policy.purgeOldEvents();
    assertEquals(1, purged);
  }

  @Test
  @DisplayName("audit failures do not block the decision")
  void auditFailureSwallowed() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    JCustosAuditService throwing = new JCustosAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, throwing, 1, Duration.ofMinutes(1), fixed(T0));

    assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(IP_KEY));
    assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(IP_KEY));
  }

  @Test
  @DisplayName("null arguments and non-positive limit / window are rejected")
  void rejectNulls() {
    InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    CollectingAuditService audit = new CollectingAuditService();

    assertThrows(NullPointerException.class,
        () -> new InMemoryRateLimitPolicy(null, audit, 1, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> new InMemoryRateLimitPolicy(store, null, 1, Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> new InMemoryRateLimitPolicy(store, audit, 0, Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> new InMemoryRateLimitPolicy(store, audit, -1, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> new InMemoryRateLimitPolicy(store, audit, 1, null));
    assertThrows(IllegalArgumentException.class,
        () -> new InMemoryRateLimitPolicy(store, audit, 1, Duration.ZERO));
    assertThrows(NullPointerException.class,
        () -> new InMemoryRateLimitPolicy(store, audit, 1, Duration.ofMinutes(1), null));

    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        store, audit, 1, Duration.ofMinutes(1), fixed(T0));
    assertThrows(NullPointerException.class, () -> policy.tryAcquire(null));
    assertThrows(NullPointerException.class, () -> policy.reset(null));
  }

  @Test
  @DisplayName("limit() / window() expose the configured values")
  void exposeConfiguration() {
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new CollectingAuditService(),
        7, Duration.ofSeconds(42));
    assertEquals(7, policy.limit());
    assertEquals(Duration.ofSeconds(42), policy.window());
  }

  @Test
  @DisplayName("RateLimitDecision sealed-record invariants are enforced")
  void decisionRecordInvariants() {
    Duration window = Duration.ofMinutes(1);
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Allowed(-1, 1, window));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Allowed(0, 0, window));
    assertThrows(NullPointerException.class,
        () -> new RateLimitDecision.Allowed(0, 1, null));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Throttled(-1, 1, window, Duration.ZERO));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Throttled(0, 0, window, Duration.ZERO));
    assertThrows(NullPointerException.class,
        () -> new RateLimitDecision.Throttled(0, 1, null, Duration.ZERO));
    assertThrows(NullPointerException.class,
        () -> new RateLimitDecision.Throttled(0, 1, window, null));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitDecision.Throttled(0, 1, window, Duration.ofSeconds(-1)));

    // Duration.ZERO is a valid retryAfter (event boundary on the cusp)
    RateLimitDecision.Throttled t =
        new RateLimitDecision.Throttled(1, 1, window, Duration.ZERO);
    assertTrue(t.retryAfter().isZero());
  }

  private static final class CollectingAuditService implements JCustosAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
