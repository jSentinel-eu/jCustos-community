package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.sequence.JCustosEventSequenceStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JCustosEventSequenceStore} implementations.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
@DisplayName("JCustosEventSequenceStore — contract")
public interface SequenceStoreContract {

  JCustosEventSequenceStore newSequenceStore();

  EventProducerId PRODUCER_A = EventProducerId.of("producer-a");
  EventProducerId PRODUCER_B = EventProducerId.of("producer-b");

  @Test
  @DisplayName("a fresh scope has no last sequence")
  default void freshScopeEmpty() {
    assertTrue(newSequenceStore().lastSequence(TenantId.DEFAULT, PRODUCER_A).isEmpty());
  }

  @Test
  @DisplayName("updateSequence then lastSequence round-trips")
  default void updateThenRead() {
    JCustosEventSequenceStore store = newSequenceStore();
    store.updateSequence(TenantId.DEFAULT, PRODUCER_A, EventSequence.of(42));
    assertEquals(42, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
  }

  @Test
  @DisplayName("sequences are isolated per tenant + producer")
  default void scopedPerTenantAndProducer() {
    JCustosEventSequenceStore store = newSequenceStore();
    store.updateSequence(TenantId.DEFAULT, PRODUCER_A, EventSequence.of(10));
    store.updateSequence(TenantId.DEFAULT, PRODUCER_B, EventSequence.of(20));
    store.updateSequence(TenantId.of("other"), PRODUCER_A, EventSequence.of(30));
    assertEquals(10, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
    assertEquals(20, store.lastSequence(TenantId.DEFAULT, PRODUCER_B).orElseThrow().value());
    assertEquals(30, store.lastSequence(TenantId.of("other"), PRODUCER_A).orElseThrow().value());
  }

  @Test
  @DisplayName("reserveNext starts at FIRST and advances monotonically")
  default void reserveNextAdvances() {
    JCustosEventSequenceStore store = newSequenceStore();
    assertEquals(EventSequence.FIRST, store.reserveNext(TenantId.DEFAULT, PRODUCER_A));
    assertEquals(2, store.reserveNext(TenantId.DEFAULT, PRODUCER_A).value());
    assertEquals(2, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
    // a different scope is independent
    assertEquals(EventSequence.FIRST, store.reserveNext(TenantId.DEFAULT, PRODUCER_B));
  }

  @Test
  @DisplayName("reserveNext is atomic — N concurrent reservations yield N distinct, gap-free sequences (R011)")
  default void reserveNextIsAtomicUnderContention() throws InterruptedException {
    JCustosEventSequenceStore store = newSequenceStore();
    int threads = 64;
    ConcurrentHashMap.KeySetView<Long, Boolean> seen = ConcurrentHashMap.newKeySet();
    AtomicInteger duplicates = new AtomicInteger();
    CountDownLatch start = new CountDownLatch(1);
    Thread[] pool = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      pool[i] = new Thread(() -> {
        try {
          start.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
        EventSequence reserved = store.reserveNext(TenantId.DEFAULT, PRODUCER_A);
        if (!seen.add(reserved.value())) {
          duplicates.incrementAndGet();
        }
      });
    }
    for (Thread t : pool) {
      t.start();
    }
    start.countDown();
    for (Thread t : pool) {
      t.join();
    }
    assertEquals(0, duplicates.get(), "no two reservations may share a sequence");
    assertEquals(threads, seen.size(), "every reservation is distinct");
    assertEquals(threads, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value(),
        "the last reserved sequence equals the reservation count (gap-free)");
    long sum = seen.stream().mapToLong(Long::longValue).sum();
    assertEquals((long) threads * (threads + 1) / 2, sum,
        "the reserved sequences are exactly 1..N with no gaps");
  }

  // ── R016 (V00.76.10): consume-side compareAndAdvance ───────────

  @Test
  @DisplayName("compareAndAdvance from a fresh scope succeeds once, then the stale 'empty' expectation fails")
  default void compareAndAdvanceFromFresh() {
    JCustosEventSequenceStore store = newSequenceStore();
    assertTrue(store.compareAndAdvance(TenantId.DEFAULT, PRODUCER_A,
        Optional.empty(), EventSequence.FIRST), "fresh-scope advance must apply");
    assertEquals(EventSequence.FIRST,
        store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow());
    // the scope is no longer fresh — a second 'empty' expectation must fail
    assertFalse(store.compareAndAdvance(TenantId.DEFAULT, PRODUCER_A,
        Optional.empty(), EventSequence.of(99)), "stale 'empty' expectation must not apply");
    assertEquals(EventSequence.FIRST,
        store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow());
  }

  @Test
  @DisplayName("compareAndAdvance applies when the expected last matches, and is rejected when it is stale")
  default void compareAndAdvanceMatchesOrRejects() {
    JCustosEventSequenceStore store = newSequenceStore();
    store.updateSequence(TenantId.DEFAULT, PRODUCER_A, EventSequence.of(5));
    // matching expectation advances
    assertTrue(store.compareAndAdvance(TenantId.DEFAULT, PRODUCER_A,
        Optional.of(EventSequence.of(5)), EventSequence.of(6)));
    assertEquals(6, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
    // stale expectation (still expecting 5) is rejected, last unchanged
    assertFalse(store.compareAndAdvance(TenantId.DEFAULT, PRODUCER_A,
        Optional.of(EventSequence.of(5)), EventSequence.of(7)));
    assertEquals(6, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
  }

  @Test
  @DisplayName("compareAndAdvance is atomic — N envelopes claiming the same next sequence: exactly one wins (R016)")
  default void compareAndAdvanceAtomicUnderContention() throws InterruptedException {
    JCustosEventSequenceStore store = newSequenceStore();
    int threads = 64;
    AtomicInteger winners = new AtomicInteger();
    CountDownLatch start = new CountDownLatch(1);
    Thread[] pool = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      pool[i] = new Thread(() -> {
        try {
          start.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
        // every thread observed an empty scope and validated sequence FIRST —
        // the consume-side race the bus faces when distinct envelopes claim the
        // same next sequence concurrently.
        if (store.compareAndAdvance(TenantId.DEFAULT, PRODUCER_A,
            Optional.empty(), EventSequence.FIRST)) {
          winners.incrementAndGet();
        }
      });
    }
    for (Thread t : pool) {
      t.start();
    }
    start.countDown();
    for (Thread t : pool) {
      t.join();
    }
    assertEquals(1, winners.get(),
        "exactly one of N envelopes claiming the same next sequence may be accepted");
    assertEquals(EventSequence.FIRST,
        store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow());
  }

  @Test
  @DisplayName("JS-SEC-108: releaseReservation hands back the last reservation, so the next reuses it")
  default void releaseReservationHandsTheSequenceBack() {
    JCustosEventSequenceStore store = newSequenceStore();
    store.reserveNext(TenantId.DEFAULT, PRODUCER_A);
    EventSequence second = store.reserveNext(TenantId.DEFAULT, PRODUCER_A);

    assertTrue(store.releaseReservation(TenantId.DEFAULT, PRODUCER_A, second));

    assertEquals(second, store.reserveNext(TenantId.DEFAULT, PRODUCER_A),
        "the released sequence is the next one reserved — no hole");
  }

  @Test
  @DisplayName("JS-SEC-108: releasing the very first reservation leaves a scope that starts at FIRST")
  default void releaseOfFirstReservationRestartsAtFirst() {
    JCustosEventSequenceStore store = newSequenceStore();
    EventSequence first = store.reserveNext(TenantId.DEFAULT, PRODUCER_A);

    assertTrue(store.releaseReservation(TenantId.DEFAULT, PRODUCER_A, first));

    assertEquals(EventSequence.FIRST, store.reserveNext(TenantId.DEFAULT, PRODUCER_A));
  }

  @Test
  @DisplayName("JS-SEC-108: releaseReservation leaves a scope alone once a later sequence was reserved")
  default void releaseReservationRefusesAnOvertakenSequence() {
    JCustosEventSequenceStore store = newSequenceStore();
    EventSequence first = store.reserveNext(TenantId.DEFAULT, PRODUCER_A);
    EventSequence second = store.reserveNext(TenantId.DEFAULT, PRODUCER_A);

    assertFalse(store.releaseReservation(TenantId.DEFAULT, PRODUCER_A, first),
        "a later reservation may already be on its way — the hole stays");
    assertFalse(store.releaseReservation(TenantId.DEFAULT, PRODUCER_B, first),
        "nothing to release in a scope that never reserved");

    assertEquals(second, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow());
    assertTrue(store.lastSequence(TenantId.DEFAULT, PRODUCER_B).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-105: resetSequence makes FIRST the next expected sequence of that scope only")
  default void resetSequenceRestartsOneScope() {
    JCustosEventSequenceStore store = newSequenceStore();
    store.updateSequence(TenantId.DEFAULT, PRODUCER_A, EventSequence.of(Long.MAX_VALUE));
    store.updateSequence(TenantId.DEFAULT, PRODUCER_B, EventSequence.of(7));

    store.resetSequence(TenantId.DEFAULT, PRODUCER_A);

    assertEquals(EventSequence.FIRST, store.reserveNext(TenantId.DEFAULT, PRODUCER_A),
        "after the reset the scope starts over");
    assertEquals(7, store.lastSequence(TenantId.DEFAULT, PRODUCER_B).orElseThrow().value(),
        "other scopes are untouched");
  }
}
