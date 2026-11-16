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
}
