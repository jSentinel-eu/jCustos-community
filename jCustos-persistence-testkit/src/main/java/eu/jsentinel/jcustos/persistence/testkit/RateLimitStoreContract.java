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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Contract every {@link RateLimitStore} implementation must satisfy.
 *
 * <p>The tests whose name starts with {@code JS-SEC-118} cover what a limit
 * rests on: events with the same instant are separate events, and
 * {@link RateLimitStore#tryAdmit} admits exactly {@code limit} of N parallel
 * callers. The concurrency test runs real threads against the store. A store
 * that cannot make the admission atomic — its backing service offers no such
 * operation — overrides {@link #admitsAtomically()} to return {@code false},
 * which skips that one test and documents the gap in its own test class; such
 * a store lets parallel requests exceed every limit built on it.</p>
 *
 * <p>Since 00.84.00 the contract also covers what a retry-after and an
 * escalation rest on: {@link RateLimitStore.Admission#oldestInWindow()} names
 * the oldest event in the window, and {@link RateLimitStore#block} /
 * {@link RateLimitStore#blockedUntil} keep a block per key that only ever
 * grows - also under real concurrency - that {@code reset} lifts and that
 * {@code purgeOlderThan} drops once it has ended. A store that does not report
 * the oldest event overrides {@link #reportsOldestInWindow()}; a store that
 * keeps no blocks overrides {@link #keepsBlocks()}, and the contract then checks
 * that it refuses blocks instead of dropping them.</p>
 */
@DisplayName("RateLimitStore — contract")
public interface RateLimitStoreContract {

  /**
   * @return a fresh, empty {@code RateLimitStore}
   */
  RateLimitStore newStore();

  /**
   * @return {@code true} (the default) when {@link RateLimitStore#tryAdmit}
   *     of the store under test checks and records as one step; {@code false}
   *     skips the concurrency test
   */
  default boolean admitsAtomically() {
    return true;
  }

  /**
   * @return {@code true} (the default) when {@link RateLimitStore#tryAdmit} of
   *     the store under test reports the oldest event in the window;
   *     {@code false} for a store that inherits the SPI default, whose admissions
   *     report none - a policy over it answers every throttle with the whole window
   * @since 00.84.00
   */
  default boolean reportsOldestInWindow() {
    return true;
  }

  /**
   * @return {@code true} (the default) when the store under test keeps blocks
   *     ({@link RateLimitStore#block}, {@link RateLimitStore#blockedUntil});
   *     {@code false} for a store that inherits the SPI defaults - the contract
   *     then checks that both refuse with {@link UnsupportedOperationException}
   * @since 00.84.00
   */
  default boolean keepsBlocks() {
    return true;
  }

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  /**
   * Builds a key in the default tenant.
   *
   * @param scope scope string
   * @return new key
   */
  default RateLimitKey key(String scope) {
    return new RateLimitKey(TenantId.DEFAULT, scope);
  }

  @Test
  @DisplayName("countSince on an unknown key returns 0")
  default void unknownKeyZero() {
    RateLimitStore store = newStore();
    assertEquals(0, store.countSince(key("ip:1.2.3.4"), T0));
  }

  @Test
  @DisplayName("recordEvent + countSince — counts at-or-after the cutoff")
  default void countAtOrAfter() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    store.recordEvent(k, T0.plusSeconds(20));
    store.recordEvent(k, T0.plusSeconds(30));

    assertEquals(2, store.countSince(k, T0.plusSeconds(15)));
    assertEquals(2, store.countSince(k, T0.plusSeconds(20)));
    assertEquals(0, store.countSince(k, T0.plusSeconds(40)));
  }

  @Test
  @DisplayName("keys are isolated")
  default void keysAreIsolated() {
    RateLimitStore store = newStore();
    RateLimitKey a = key("ip:1.2.3.4");
    RateLimitKey b = key("ip:5.6.7.8");
    store.recordEvent(a, T0);
    store.recordEvent(a, T0.plusSeconds(10));
    store.recordEvent(b, T0);

    assertEquals(2, store.countSince(a, T0));
    assertEquals(1, store.countSince(b, T0));
  }

  @Test
  @DisplayName("tenant is part of the key")
  default void tenantScoped() {
    RateLimitStore store = newStore();
    RateLimitKey defaultScope = new RateLimitKey(TenantId.DEFAULT, "ip:1.2.3.4");
    RateLimitKey acmeScope = new RateLimitKey(new TenantId("acme"), "ip:1.2.3.4");
    store.recordEvent(defaultScope, T0);
    store.recordEvent(acmeScope, T0);
    store.recordEvent(acmeScope, T0.plusSeconds(10));

    assertEquals(1, store.countSince(defaultScope, T0));
    assertEquals(2, store.countSince(acmeScope, T0));
  }

  @Test
  @DisplayName("reset drops every event under the key")
  default void resetClears() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    store.reset(k);
    assertEquals(0, store.countSince(k, T0));
  }

  @Test
  @DisplayName("reset on unknown is a no-op")
  default void resetUnknown() {
    RateLimitStore store = newStore();
    store.reset(key("ghost"));
    assertEquals(0, store.countSince(key("ghost"), T0));
  }

  @Test
  @DisplayName("purgeOlderThan drops events strictly before the cutoff; at-cutoff survives")
  default void purgeStrictlyBefore() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);                       // before
    store.recordEvent(k, T0.plusSeconds(10));       // at cutoff
    store.recordEvent(k, T0.plusSeconds(20));       // after

    assertEquals(1, store.purgeOlderThan(T0.plusSeconds(10)));
    assertEquals(2, store.countSince(k, T0.plusSeconds(10)));
  }

  @Test
  @DisplayName("purgeOlderThan on an empty store returns 0")
  default void purgeEmpty() {
    RateLimitStore store = newStore();
    assertEquals(0, store.purgeOlderThan(T0.plusSeconds(10)));
  }

  @Test
  @DisplayName("all methods reject null arguments")
  default void rejectNulls() {
    RateLimitStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.recordEvent(null, T0));
    assertThrows(NullPointerException.class,
        () -> store.recordEvent(key("ip:1.2.3.4"), null));
    assertThrows(NullPointerException.class, () -> store.countSince(null, T0));
    assertThrows(NullPointerException.class,
        () -> store.countSince(key("ip:1.2.3.4"), null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
    assertThrows(NullPointerException.class, () -> store.purgeOlderThan(null));
  }

  // ── JS-SEC-118: what a limit rests on ──────────────────────────────

  @Test
  @DisplayName("JS-SEC-118: events with the same instant are separate events")
  default void equalInstantsAreCountedSeparately() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0);
    store.recordEvent(k, T0);
    assertEquals(3, store.countSince(k, T0),
        "a clock that ticks coarsely must not make events disappear");
    assertEquals(3, store.purgeOlderThan(T0.plusSeconds(1)));
  }

  @Test
  @DisplayName("JS-SEC-118: events recorded out of order are all counted")
  default void eventsOutOfOrderAreCounted() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    // two requests read the clock and reach the store in the other order
    store.recordEvent(k, T0.plusSeconds(20));
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    assertEquals(3, store.countSince(k, T0));
    assertEquals(2, store.countSince(k, T0.plusSeconds(10)));
    assertEquals(1, store.countSince(k, T0.plusSeconds(15)));
    assertEquals(1, store.purgeOlderThan(T0.plusSeconds(5)));
    assertEquals(2, store.countSince(k, T0));
  }

  @Test
  @DisplayName("JS-SEC-118: tryAdmit admits exactly `limit` calls with one and the same instant")
  default void tryAdmitWithIdenticalInstants() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    Instant since = T0.minusSeconds(60);
    for (int i = 1; i <= 3; i++) {
      RateLimitStore.Admission admission = store.tryAdmit(k, T0, since, 3);
      assertTrue(admission.admitted(), "call " + i + " is within the limit");
      assertEquals(i, admission.eventsInWindow());
    }
    for (int i = 0; i < 20; i++) {
      RateLimitStore.Admission refused = store.tryAdmit(k, T0, since, 3);
      assertFalse(refused.admitted(), "the limit is reached although the clock has not moved");
      assertEquals(3, refused.eventsInWindow());
    }
    assertEquals(3, store.countSince(k, since), "a refused call records nothing");
  }

  @Test
  @DisplayName("JS-SEC-118: tryAdmit counts the window only and keeps other keys apart")
  default void tryAdmitCountsTheWindowOnly() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    RateLimitKey other = key("ip:5.6.7.8");
    for (int i = 0; i < 3; i++) {
      assertTrue(store.tryAdmit(k, T0.plusSeconds(i), T0.minusSeconds(60), 3).admitted());
    }
    assertFalse(store.tryAdmit(k, T0.plusSeconds(3), T0.minusSeconds(57), 3).admitted());
    assertTrue(store.tryAdmit(other, T0.plusSeconds(3), T0.minusSeconds(57), 3).admitted(),
        "another key has its own count");

    // the window has moved on: the three events lie before it
    RateLimitStore.Admission later = store.tryAdmit(k, T0.plusSeconds(100), T0.plusSeconds(40), 3);
    assertTrue(later.admitted());
    assertEquals(1, later.eventsInWindow());
    assertEquals(1, store.countSince(k, T0.plusSeconds(40)));
  }

  @Test
  @DisplayName("JS-SEC-118: of 48 parallel callers exactly `limit` are admitted - real threads, every round")
  default void tryAdmitIsAtomicUnderConcurrency() throws Exception {
    assumeTrue(admitsAtomically(),
        "this store declares that it cannot check and record as one step");
    RateLimitStore store = newStore();
    int threads = 48;
    int limit = 10;
    int rounds = 12;
    Instant since = T0.minusSeconds(60);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      for (int round = 0; round < rounds; round++) {
        RateLimitKey k = key("login:round-" + round);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> outcomes = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
          // even callers share one instant, odd callers differ: both shapes of real traffic
          Instant at = i % 2 == 0 ? T0 : T0.plusNanos(i);
          Callable<Boolean> caller = () -> {
            ready.countDown();
            start.await();
            return store.tryAdmit(k, at, since, limit).admitted();
          };
          outcomes.add(pool.submit(caller));
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS), "callers did not start");
        start.countDown();
        int admitted = 0;
        for (Future<Boolean> outcome : outcomes) {
          if (outcome.get(30, TimeUnit.SECONDS)) {
            admitted++;
          }
        }
        assertEquals(limit, admitted,
            "round " + round + ": " + threads + " parallel callers against limit " + limit);
        assertEquals(limit, store.countSince(k, since),
            "round " + round + ": the store holds exactly the admitted events");
      }
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("JS-SEC-118: tryAdmit rejects null arguments")
  default void tryAdmitRejectsNulls() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    assertThrows(NullPointerException.class, () -> store.tryAdmit(null, T0, T0, 1));
    assertThrows(NullPointerException.class, () -> store.tryAdmit(k, null, T0, 1));
    assertThrows(NullPointerException.class, () -> store.tryAdmit(k, T0, null, 1));
  }

  // ── 00.84.00: the oldest event in the window ───────────────────────

  @Test
  @DisplayName("tryAdmit names the oldest event left in the window - refused and admitted")
  default void tryAdmitReportsTheOldestEventInTheWindow() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    Instant since = T0.minusSeconds(60);
    RateLimitStore.Admission first = store.tryAdmit(k, T0.plusSeconds(10), since, 3);
    store.tryAdmit(k, T0.plusSeconds(20), since, 3);
    store.tryAdmit(k, T0.plusSeconds(30), since, 3);
    RateLimitStore.Admission refused = store.tryAdmit(k, T0.plusSeconds(40), since, 3);
    assertFalse(refused.admitted());
    assertEquals(3, refused.eventsInWindow());
    // the window has moved past the first event: the second one is now the oldest
    RateLimitStore.Admission moved =
        store.tryAdmit(k, T0.plusSeconds(75), T0.plusSeconds(15), 3);
    assertTrue(moved.admitted(), "the event at T0+10 has left the window");
    RateLimitStore.Admission refusedLater =
        store.tryAdmit(k, T0.plusSeconds(76), T0.plusSeconds(16), 3);
    assertFalse(refusedLater.admitted());

    if (reportsOldestInWindow()) {
      assertEquals(Optional.of(T0.plusSeconds(10)), first.oldestInWindow(),
          "the admitted event is the only one, so it is the oldest");
      assertEquals(Optional.of(T0.plusSeconds(10)), refused.oldestInWindow());
      assertEquals(Optional.of(T0.plusSeconds(20)), moved.oldestInWindow());
      assertEquals(Optional.of(T0.plusSeconds(20)), refusedLater.oldestInWindow());
    } else {
      // a store that cannot say must not guess
      for (RateLimitStore.Admission admission : List.of(first, refused, moved, refusedLater)) {
        assertEquals(Optional.empty(), admission.oldestInWindow());
      }
    }
  }

  @Test
  @DisplayName("the oldest event in the window: two events at one instant, and other keys kept apart")
  default void oldestInWindowWithEqualInstantsAndOtherKeys() {
    assumeTrue(reportsOldestInWindow(), "this store does not report the oldest event");
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    RateLimitKey other = key("ip:5.6.7.8");
    Instant since = T0.minusSeconds(60);
    store.tryAdmit(other, T0.minusSeconds(30), since, 5);
    store.tryAdmit(k, T0.plusSeconds(5), since, 2);
    store.tryAdmit(k, T0.plusSeconds(5), since, 2);
    RateLimitStore.Admission refused = store.tryAdmit(k, T0.plusSeconds(6), since, 2);
    assertFalse(refused.admitted());
    assertEquals(Optional.of(T0.plusSeconds(5)), refused.oldestInWindow(),
        "another key's earlier event is not this key's oldest");
  }

  // ── 00.84.00: blocks ────────────────────────────────────────────────

  @Test
  @DisplayName("block records the end of the block; an unknown key has none; a store without blocks refuses")
  default void blockIsRecorded() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    if (!keepsBlocks()) {
      // a store that keeps no blocks must refuse them, not drop them without a word
      assertThrows(UnsupportedOperationException.class, () -> store.blockedUntil(k));
      assertThrows(UnsupportedOperationException.class,
          () -> store.block(k, T0.plusSeconds(60)));
      return;
    }
    assertEquals(Optional.empty(), store.blockedUntil(k));
    assertEquals(T0.plusSeconds(600), store.block(k, T0.plusSeconds(600)));
    assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(k));
    assertEquals(Optional.empty(), store.blockedUntil(key("ip:5.6.7.8")), "keys are isolated");
    assertEquals(Optional.empty(),
        store.blockedUntil(new RateLimitKey(new TenantId("acme"), "ip:1.2.3.4")),
        "the tenant is part of the key");
  }

  @Test
  @DisplayName("a block only ever grows: a shorter block does not shorten a longer one")
  default void blockOnlyGrows() {
    assumeTrue(keepsBlocks(), "this store keeps no blocks");
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.block(k, T0.plusSeconds(600));
    assertEquals(T0.plusSeconds(600), store.block(k, T0.plusSeconds(300)),
        "the later end is kept and returned");
    assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(k));
    assertEquals(T0.plusSeconds(900), store.block(k, T0.plusSeconds(900)));
    assertEquals(Optional.of(T0.plusSeconds(900)), store.blockedUntil(k));
  }

  @Test
  @DisplayName("a block is no event: it is not counted and does not change an admission")
  default void blockIsNoEvent() {
    assumeTrue(keepsBlocks(), "this store keeps no blocks");
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.block(k, T0.plusSeconds(600));
    assertEquals(0, store.countSince(k, T0.minusSeconds(3_600)));
    RateLimitStore.Admission admission = store.tryAdmit(k, T0, T0.minusSeconds(60), 1);
    assertTrue(admission.admitted(), "tryAdmit does not look at blocks - the policy does");
    assertEquals(1, admission.eventsInWindow());
    assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(k),
        "an admission does not lift the block");
  }

  @Test
  @DisplayName("reset lifts the block together with the events")
  default void resetLiftsTheBlock() {
    assumeTrue(keepsBlocks(), "this store keeps no blocks");
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.block(k, T0.plusSeconds(600));
    store.reset(k);
    assertEquals(Optional.empty(), store.blockedUntil(k));
    assertEquals(0, store.countSince(k, T0));
  }

  @Test
  @DisplayName("purgeOlderThan drops a block that ended before the cutoff and keeps a lasting one")
  default void purgeDropsEndedBlocksOnly() {
    assumeTrue(keepsBlocks(), "this store keeps no blocks");
    RateLimitStore store = newStore();
    RateLimitKey ended = key("ip:1.2.3.4");
    RateLimitKey atCutoff = key("ip:5.6.7.8");
    RateLimitKey lasting = key("ip:9.9.9.9");
    store.block(ended, T0.plusSeconds(10));
    store.block(atCutoff, T0.plusSeconds(20));
    store.block(lasting, T0.plusSeconds(600));
    store.recordEvent(lasting, T0); // purged, while the key's block stays

    assertEquals(1, store.purgeOlderThan(T0.plusSeconds(20)), "a block is no purged event");
    assertEquals(Optional.empty(), store.blockedUntil(ended));
    assertEquals(Optional.of(T0.plusSeconds(20)), store.blockedUntil(atCutoff),
        "strictly before, as for events");
    assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(lasting),
        "a key without events keeps its block while it lasts");
    assertEquals(0, store.countSince(lasting, T0));
  }

  @Test
  @DisplayName("block of 48 parallel callers: the latest end wins, every round, whatever the order")
  default void blockIsAtomicUnderConcurrency() throws Exception {
    assumeTrue(keepsBlocks(), "this store keeps no blocks");
    RateLimitStore store = newStore();
    int threads = 48;
    int rounds = 12;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      for (int round = 0; round < rounds; round++) {
        RateLimitKey k = key("login:block-round-" + round);
        if (round % 2 == 1) {
          store.recordEvent(k, T0); // a key with events and a key without
        }
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Instant>> outcomes = new ArrayList<>();
        Instant latest = T0;
        for (int i = 0; i < threads; i++) {
          // ends in a shuffled order, so that the latest one is not the last to arrive
          Instant until = T0.plusSeconds(60L + (i * 7L) % threads);
          latest = until.isAfter(latest) ? until : latest;
          Callable<Instant> caller = () -> {
            ready.countDown();
            start.await();
            Instant effective = store.block(k, until);
            assertFalse(effective.isBefore(until), "a block must not come back shorter");
            Optional<Instant> seen = store.blockedUntil(k);
            assertTrue(seen.isPresent() && !seen.get().isBefore(until),
                "a reader saw the block shrink below " + until + ": " + seen);
            return effective;
          };
          outcomes.add(pool.submit(caller));
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS), "callers did not start");
        start.countDown();
        for (Future<Instant> outcome : outcomes) {
          assertFalse(outcome.get(30, TimeUnit.SECONDS).isAfter(latest));
        }
        assertEquals(Optional.of(latest), store.blockedUntil(k),
            "round " + round + ": the latest of " + threads + " parallel ends is kept");
      }
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("block and blockedUntil reject null arguments")
  default void blockRejectsNulls() {
    assumeTrue(keepsBlocks(), "this store keeps no blocks");
    RateLimitStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.blockedUntil(null));
    assertThrows(NullPointerException.class, () -> store.block(null, T0));
    assertThrows(NullPointerException.class, () -> store.block(key("ip:1.2.3.4"), null));
  }
}
