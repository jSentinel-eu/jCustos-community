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

import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a {@link LoginAttemptStore} must satisfy when it implements the
 * attempt operations <em>atomically</em> (JS-SEC-122, JS-SEC-123) instead
 * of inheriting the SPI defaults: an admitted attempt is a reservation,
 * parallel requests cannot exceed the threshold, and a counter is
 * forgotten once no failure has been recorded for a full window.
 *
 * <p>A store that passes this contract gives
 * {@code StoreBackedLoginAttemptPolicy} its full guarantees. A store that
 * only passes {@link LoginAttemptStoreContract} keeps the behaviour of
 * before 00.84.00.
 *
 * @since 00.84.00
 */
@DisplayName("LoginAttemptStore — atomic attempt contract")
public interface AtomicLoginAttemptStoreContract extends LoginAttemptStoreContract {

  @Test
  @DisplayName("JS-SEC-123: an admitted attempt is in flight - threshold-many are admitted, the next is refused")
  default void admittedAttemptsAreReservations() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();

    for (int i = 0; i < limits.failureThreshold(); i++) {
      assertFalse(store.tryBeginAttempt(k, t0, limits).blocked(), "attempt " + (i + 1));
    }
    AttemptStatus saturated = store.tryBeginAttempt(k, t0.plusSeconds(1), limits);
    assertTrue(saturated.blocked(), "no failure is counted yet, but the threshold is in flight");
    assertEquals(0, saturated.failures());
    assertEquals(Optional.of(t0.plus(limits.reservationTtl())), saturated.blockedUntil(),
        "the refusal ends when the oldest reservation lapses");
    assertEquals(0, store.failureCount(k), "a reservation is not a failure");
  }

  @Test
  @DisplayName("JS-SEC-123: failure, success and abandon each release one reservation")
  default void reportsReleaseReservations() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();

    // abandon: any number of rounds, never saturated
    for (int round = 0; round < 10; round++) {
      assertFalse(store.tryBeginAttempt(k, t0, limits).blocked(), "round " + round);
      store.abandonAttempt(k, t0);
    }
    // failure: one failure held, so two more attempts fit, the third does not
    store.tryBeginAttempt(k, t0, limits);
    store.completeFailure(k, t0, limits);
    assertFalse(store.tryBeginAttempt(k, t0, limits).blocked());
    assertFalse(store.tryBeginAttempt(k, t0, limits).blocked());
    assertTrue(store.tryBeginAttempt(k, t0, limits).blocked(), "1 failure + 2 in flight = threshold");
    // success: clears the counter and frees its own slot, the other attempt stays in flight
    assertFalse(store.completeSuccess(k, t0, limits).blocked());
    assertEquals(0, store.failureCount(k));
    assertFalse(store.tryBeginAttempt(k, t0, limits).blocked());
    assertFalse(store.tryBeginAttempt(k, t0, limits).blocked());
    assertTrue(store.tryBeginAttempt(k, t0, limits).blocked(), "0 failures + 3 in flight = threshold");
  }

  @Test
  @DisplayName("JS-SEC-123: a reservation that is never reported lapses after reservationTtl")
  default void forgottenReservationsLapse() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();

    for (int i = 0; i < limits.failureThreshold(); i++) {
      store.tryBeginAttempt(k, t0, limits);
    }
    assertTrue(store.tryBeginAttempt(k, t0.plus(limits.reservationTtl()).minusMillis(1), limits)
        .blocked());
    assertFalse(store.tryBeginAttempt(k, t0.plus(limits.reservationTtl()), limits).blocked());
  }

  @Test
  @DisplayName("JS-SEC-123: 50 parallel attempts - exactly threshold-many are admitted")
  default void parallelAttemptsCannotExceedThreshold() throws InterruptedException {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("victim", "1.1.1.1");
    AttemptLimits limits = limits();
    int threads = 50;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch go = new CountDownLatch(1);
    CountDownLatch gatePassed = new CountDownLatch(threads);
    CountDownLatch done = new CountDownLatch(threads);
    AtomicInteger admitted = new AtomicInteger();

    for (int i = 0; i < threads; i++) {
      Thread thread = new Thread(() -> {
        ready.countDown();
        try {
          go.await();
          boolean blocked = store.tryBeginAttempt(k, t0, limits).blocked();
          gatePassed.countDown();
          if (!blocked) {
            admitted.incrementAndGet();
            gatePassed.await(10, TimeUnit.SECONDS);
            store.completeFailure(k, t0, limits);
          }
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        } finally {
          done.countDown();
        }
      });
      thread.setDaemon(true);
      thread.start();
    }
    assertTrue(ready.await(10, TimeUnit.SECONDS));
    go.countDown();
    assertTrue(done.await(60, TimeUnit.SECONDS), "all attempts must finish");

    assertEquals(limits.failureThreshold(), admitted.get());
    assertEquals(limits.failureThreshold(), store.failureCount(k));
    assertTrue(store.tryBeginAttempt(k, t0, limits).blocked());
  }

  @Test
  @DisplayName("JS-SEC-122: a counter is forgotten once no failure was recorded for a full window")
  default void counterIsForgottenAfterTheWindow() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");
    LoginAttemptKey other = key("bob", "1.1.1.1");
    AttemptLimits limits = limits();

    store.tryBeginAttempt(k, t0, limits);
    store.completeFailure(k, t0, limits);
    store.tryBeginAttempt(k, t0, limits);
    store.completeFailure(k, t0.plusSeconds(1), limits);
    assertEquals(2, store.failureCount(k));

    // an operation on ANOTHER key after the window sweeps the outdated counter away
    Instant afterWindow = t0.plusSeconds(1).plus(limits.window());
    store.tryBeginAttempt(other, afterWindow, limits);
    store.abandonAttempt(other, afterWindow);
    assertEquals(0, store.failureCount(k), "expired state must not wait for a successful login");
    assertTrue(store.lastFailureAt(k).isEmpty());

    // and the key starts from zero: one failure does not lock it
    store.tryBeginAttempt(k, afterWindow, limits);
    assertFalse(store.completeFailure(k, afterWindow, limits).blocked());
    assertEquals(1, store.failureCount(k));
  }

  @Test
  @DisplayName("JS-SEC-122: after a lockout, within the window, one attempt at a time and one failure locks again")
  default void lapsedLockoutWithinTheWindow() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();   // lockout 5 min < window 10 min
    for (int i = 0; i < limits.failureThreshold(); i++) {
      store.completeFailure(k, t0, limits);
    }
    Instant afterLockout = t0.plus(limits.lockout());

    assertFalse(store.tryBeginAttempt(k, afterLockout, limits).blocked(), "one probe is admitted");
    assertTrue(store.tryBeginAttempt(k, afterLockout, limits).blocked(), "but not two at once");
    AttemptStatus relocked = store.completeFailure(k, afterLockout, limits);
    assertTrue(relocked.blocked());
    assertEquals(Optional.of(afterLockout.plus(limits.lockout())), relocked.blockedUntil());
  }
}
