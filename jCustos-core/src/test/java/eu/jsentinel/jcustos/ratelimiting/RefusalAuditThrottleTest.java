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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.ratelimiting.RefusalAuditThrottle.Publication;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF11 (CWE-779): the audit throttle of blocked keys - at most one event per key and
 * second, the count carried by the next event, a hard bound on the keys it tracks, and nothing
 * lost at the bound.
 */
@DisplayName("RF11 - RefusalAuditThrottle: one event per key and second, bounded, nothing lost")
class RefusalAuditThrottleTest {

  private static final Instant T0 = Instant.parse("2026-11-19T10:00:00Z");
  private static final Duration SECOND = RefusalAuditThrottle.INTERVAL;
  private static final RateLimitKey AGGREGATE = new RateLimitKey(TenantId.DEFAULT,
      InMemoryRateLimitPolicy.UNTRACKED_KEYS_AUDIT_SCOPE);
  private static final RateLimitKey A = key("ip:192.0.2.1");
  private static final RateLimitKey B = key("ip:192.0.2.2");
  private static final RateLimitKey C = key("ip:192.0.2.3");

  private static RateLimitKey key(String scope) {
    return new RateLimitKey(TenantId.DEFAULT, scope);
  }

  private static RefusalAuditThrottle bounded(int maxKeys) {
    return new RefusalAuditThrottle(SECOND, maxKeys, AGGREGATE);
  }

  private static int refuse(RefusalAuditThrottle throttle, RateLimitKey key, Instant at, int times,
                            List<Publication> sink) {
    for (int i = 0; i < times; i++) {
      sink.addAll(throttle.refused(key, at));
    }
    return times;
  }

  @Test
  @DisplayName("defaults: one second, 10 000 keys")
  void defaults() {
    assertEquals(Duration.ofSeconds(1), RefusalAuditThrottle.INTERVAL);
    assertEquals(10_000, RefusalAuditThrottle.MAX_TRACKED_KEYS);
  }

  @Test
  @DisplayName("a flood within one second: one publication; the next one carries the held-back refusals and itself")
  void floodPublishesOnceAndTheNextCarriesTheCount() {
    RefusalAuditThrottle throttle = new RefusalAuditThrottle(AGGREGATE);
    List<Publication> published = new ArrayList<>();
    refuse(throttle, A, T0, 600, published);
    refuse(throttle, A, T0.plus(SECOND).minusNanos(1), 400, published);
    assertEquals(List.of(new Publication(A, 1)), published);
    assertEquals(999, throttle.pendingRefusals());

    refuse(throttle, A, T0.plus(SECOND), 1, published);
    assertEquals(new Publication(A, 1_000), published.get(1));
    assertEquals(0, throttle.pendingRefusals());
  }

  @Test
  @DisplayName("distinct keys are throttled independently")
  void keysAreIndependent() {
    RefusalAuditThrottle throttle = new RefusalAuditThrottle(AGGREGATE);
    List<Publication> published = new ArrayList<>();
    refuse(throttle, A, T0, 10, published);
    refuse(throttle, B, T0.plusMillis(1), 5, published);
    refuse(throttle, A, T0.plusMillis(2), 1, published);
    assertEquals(List.of(new Publication(A, 1), new Publication(B, 1)), published);
    refuse(throttle, B, T0.plusMillis(1).plus(SECOND), 1, published);
    assertEquals(new Publication(B, 5), published.get(2), "B's interval runs from B's event");
    refuse(throttle, A, T0.plus(SECOND), 1, published);
    assertEquals(new Publication(A, 11), published.get(3));
  }

  @Test
  @DisplayName("a clock that went back behind the last event publishes at once")
  void clockGoingBackPublishes() {
    RefusalAuditThrottle throttle = new RefusalAuditThrottle(AGGREGATE);
    List<Publication> published = new ArrayList<>();
    refuse(throttle, A, T0, 3, published);
    refuse(throttle, A, T0.minusNanos(1), 1, published);
    assertEquals(List.of(new Publication(A, 1), new Publication(A, 3)), published);
  }

  @Test
  @DisplayName("flushDue publishes what is counted and due, keeps what is not due, forgets idle keys")
  void flushDuePublishesDueCountsAndForgetsIdleKeys() {
    RefusalAuditThrottle throttle = new RefusalAuditThrottle(AGGREGATE);
    List<Publication> published = new ArrayList<>();
    refuse(throttle, A, T0, 4, published);          // A: 3 held back
    refuse(throttle, B, T0, 1, published);          // B: nothing held back
    refuse(throttle, C, T0.plusMillis(500), 2, published); // C: 1 held back, due at T0 + 1.5 s
    published.clear();

    assertEquals(List.of(), throttle.flushDue(T0.plusMillis(999)), "nothing is due yet");
    assertEquals(3, throttle.trackedKeyCount());

    Instant flush = T0.plus(SECOND);
    assertEquals(List.of(new Publication(A, 3)), throttle.flushDue(flush));
    assertEquals(2, throttle.trackedKeyCount(), "B had nothing counted and is forgotten; A and C stay");
    assertEquals(1, throttle.pendingRefusals(), "C's refusal waits for C's second");

    refuse(throttle, A, flush.plusMillis(10), 1, published);
    assertEquals(List.of(), published, "the flush started A's next interval");

    assertEquals(List.of(new Publication(C, 1)), throttle.flushDue(T0.plusMillis(1_500)));
  }

  @Test
  @DisplayName("at the bound: a fresh key while all keys published within the second is counted under the aggregate scope")
  void freshKeysBeyondTheBoundAreAggregated() {
    RefusalAuditThrottle throttle = bounded(2);
    List<Publication> published = new ArrayList<>();
    refuse(throttle, A, T0, 1, published);
    refuse(throttle, B, T0, 1, published);
    refuse(throttle, C, T0, 1, published);
    refuse(throttle, key("ip:192.0.2.4"), T0, 1, published);
    refuse(throttle, key("ip:192.0.2.5"), T0.plusMillis(1), 3, published);
    assertEquals(List.of(new Publication(A, 1), new Publication(B, 1),
        new Publication(AGGREGATE, 1)), published, "one aggregate event, at once");
    assertEquals(2, throttle.trackedKeyCount());
    assertEquals(4, throttle.pendingRefusals(), "the other four untracked refusals are counted");

    // a second later the oldest key is evicted to make room; the aggregate is due as well
    published.clear();
    refuse(throttle, key("ip:192.0.2.6"), T0.plus(SECOND), 1, published);
    assertEquals(List.of(new Publication(key("ip:192.0.2.6"), 1)), published,
        "A had nothing counted, so its eviction publishes nothing");
    assertEquals(List.of(new Publication(AGGREGATE, 4)), throttle.flushDue(T0.plus(SECOND)));
  }

  @Test
  @DisplayName("at the bound: an evicted key's held-back refusals move to the aggregate scope")
  void evictionMovesTheHeldBackCountToTheAggregate() {
    RefusalAuditThrottle throttle = bounded(2);
    List<Publication> published = new ArrayList<>();
    refuse(throttle, A, T0, 7, published);         // A: 6 held back
    refuse(throttle, B, T0.plusMillis(1), 1, published);
    published.clear();

    refuse(throttle, C, T0.plus(SECOND), 1, published);
    assertEquals(List.of(new Publication(AGGREGATE, 6), new Publication(C, 1)), published,
        "A's six held-back refusals are published under the aggregate scope, C under its own");
    assertEquals(2, throttle.trackedKeyCount());
    assertEquals(0, throttle.pendingRefusals());

    // A refuses again: a fresh key whose last event lies a second back
    published.clear();
    refuse(throttle, A, T0.plus(SECOND).plusMillis(1), 1, published);
    assertEquals(List.of(new Publication(A, 1)), published, "B was evicted for A");
  }

  @Test
  @DisplayName("a flood of 100 000 fresh keys: the bound holds, every refusal is counted, events stay bounded")
  void keyFloodIsBoundedAndLosesNothing() {
    int bound = 1_000;
    RefusalAuditThrottle throttle = bounded(bound);
    List<Publication> published = new ArrayList<>();
    long refusals = 0;
    for (int i = 0; i < 100_000; i++) {
      // ten keys per millisecond: ten seconds of fresh keys
      refusals += refuse(throttle, key("user:" + i), T0.plusNanos(100_000L * i), 1, published);
      assertTrue(throttle.trackedKeyCount() <= bound);
    }
    published.addAll(throttle.flushDue(T0.plusSeconds(200)));
    long sum = published.stream().mapToLong(Publication::refusals).sum();
    assertEquals(refusals, sum + throttle.pendingRefusals(), "no refusal lost");
    assertEquals(0, throttle.pendingRefusals());
    long aggregateEvents = published.stream().filter(p -> p.key().equals(AGGREGATE)).count();
    assertTrue(aggregateEvents <= 11,
        "at most one aggregate event a second, plus the final flush: " + aggregateEvents);
    assertTrue(published.size() < refusals,
        "fewer events than refusals once the bound is reached: " + published.size());
  }

  @Test
  @DisplayName("32 threads refuse one key 100 times each within one second: one publication, every refusal counted once")
  void concurrentRefusalsOfOneKey() throws Exception {
    RefusalAuditThrottle throttle = new RefusalAuditThrottle(AGGREGATE);
    List<Publication> published = new CopyOnWriteArrayList<>();
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
          for (int i = 0; i < perThread; i++) {
            published.addAll(throttle.refused(A, T0));
          }
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
    assertEquals(List.of(new Publication(A, 1)), published);
    assertEquals(total - 1, throttle.pendingRefusals());
    assertEquals(List.of(new Publication(A, total)), throttle.refused(A, T0.plus(SECOND)));
  }

  @Test
  @DisplayName("the constructor refuses a non-positive interval or bound")
  void validates() {
    assertThrows(IllegalArgumentException.class,
        () -> new RefusalAuditThrottle(Duration.ZERO, 1, AGGREGATE));
    assertThrows(IllegalArgumentException.class,
        () -> new RefusalAuditThrottle(SECOND, 0, AGGREGATE));
    assertThrows(NullPointerException.class, () -> new RefusalAuditThrottle(null, 1, AGGREGATE));
    assertThrows(NullPointerException.class, () -> new RefusalAuditThrottle(SECOND, 1, null));
    RefusalAuditThrottle throttle = new RefusalAuditThrottle(AGGREGATE);
    assertThrows(NullPointerException.class, () -> throttle.refused(null, T0));
    assertThrows(NullPointerException.class, () -> throttle.refused(A, null));
    assertThrows(NullPointerException.class, () -> throttle.flushDue(null));
  }
}
