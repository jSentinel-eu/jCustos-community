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
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Contract every {@link LoginAttemptStore} implementation must
 * satisfy.
 *
 * <p>The tests on the attempt operations in this interface hold for a
 * store that merely inherits the SPI defaults as well as for one that
 * implements them atomically. What only an atomic implementation can
 * promise — reservations, the window, parallel requests — is in
 * {@link AtomicLoginAttemptStoreContract}.
 *
 * <p>Address keys (JS-SEC-062): {@code StoreBackedLoginAttemptPolicy} counts
 * the failures of a client address on {@link LoginAttemptKey#forAddress}, an
 * ordinary key with a reserved user id, under limits of their own. A store
 * keeps such a key like any other; the tests below check the round trip,
 * the independence from account keys and - for an atomic store - the
 * reservation.
 */
@DisplayName("LoginAttemptStore — contract")
public interface LoginAttemptStoreContract {

  /**
   * @return a fresh, empty {@code LoginAttemptStore}
   */
  LoginAttemptStore newStore();

  /**
   * Builds a key with {@link TenantId#DEFAULT}.
   *
   * @param user username dimension
   * @param ip   client address
   * @return new key
   */
  default LoginAttemptKey key(String user, String ip) {
    return new LoginAttemptKey(TenantId.DEFAULT, user, ip);
  }

  @Test
  @DisplayName("recordFailure increments the counter and stores the timestamp")
  default void recordFailureIncrements() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");

    store.recordFailure(k, t0);
    assertEquals(1, store.failureCount(k));
    assertEquals(Optional.of(t0), store.lastFailureAt(k));

    Instant t1 = t0.plusSeconds(30);
    store.recordFailure(k, t1);
    assertEquals(2, store.failureCount(k));
    assertEquals(Optional.of(t1), store.lastFailureAt(k));
  }

  @Test
  @DisplayName("failureCount / lastFailureAt return 0 / empty for an unknown key")
  default void unknownKeyDefaults() {
    LoginAttemptStore store = newStore();
    assertEquals(0, store.failureCount(key("ghost", "1.1.1.1")));
    assertTrue(store.lastFailureAt(key("ghost", "1.1.1.1")).isEmpty());
  }

  @Test
  @DisplayName("reset drops counter and timestamp")
  default void resetClears() {
    LoginAttemptStore store = newStore();
    LoginAttemptKey k = key("alice", "1.1.1.1");
    store.recordFailure(k, Instant.now());
    store.reset(k);
    assertEquals(0, store.failureCount(k));
    assertTrue(store.lastFailureAt(k).isEmpty());
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  default void resetUnknownIsNoOp() {
    LoginAttemptStore store = newStore();
    store.reset(key("ghost", "1.1.1.1"));
    assertEquals(0, store.failureCount(key("ghost", "1.1.1.1")));
  }

  @Test
  @DisplayName("counters are keyed per (tenant, user, ip)")
  default void countersAreKeyIndependent() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    store.recordFailure(key("alice", "1.1.1.1"), t);
    store.recordFailure(key("alice", "1.1.1.1"), t);
    store.recordFailure(key("alice", "2.2.2.2"), t);
    store.recordFailure(key("bob", "1.1.1.1"), t);

    assertEquals(2, store.failureCount(key("alice", "1.1.1.1")));
    assertEquals(1, store.failureCount(key("alice", "2.2.2.2")));
    assertEquals(1, store.failureCount(key("bob", "1.1.1.1")));
  }

  @Test
  @DisplayName("tenant is part of the key — same (user,ip) under different tenants are independent")
  default void tenantPartOfKey() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    LoginAttemptKey defaultScope =
        new LoginAttemptKey(TenantId.DEFAULT, "alice", "1.1.1.1");
    LoginAttemptKey acmeScope =
        new LoginAttemptKey(new TenantId("acme"), "alice", "1.1.1.1");

    store.recordFailure(defaultScope, t);
    store.recordFailure(defaultScope, t);
    store.recordFailure(acmeScope, t);

    assertEquals(2, store.failureCount(defaultScope));
    assertEquals(1, store.failureCount(acmeScope));
  }

  @Test
  @DisplayName("all methods reject null arguments")
  default void rejectNulls() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    assertThrows(NullPointerException.class, () -> store.recordFailure(null, t));
    assertThrows(NullPointerException.class,
        () -> store.recordFailure(key("alice", "1.1.1.1"), null));
    assertThrows(NullPointerException.class, () -> store.failureCount(null));
    assertThrows(NullPointerException.class, () -> store.lastFailureAt(null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
  }

  // ── attempt operations (since 00.84.00) ────────────────────────────

  /**
   * Limits used by the attempt-operation tests: 3 failures, 10 min window,
   * 5 min lockout, 30 s reservation.
   *
   * @return the limits
   */
  default AttemptLimits limits() {
    return new AttemptLimits(3, Duration.ofMinutes(10), Duration.ofMinutes(5),
        Duration.ofSeconds(30));
  }

  @Test
  @DisplayName("JS-SEC-122: the threshold-th failure locks the key until lastFailure + lockout")
  default void completeFailureLocksAtThreshold() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();

    assertFalse(store.tryBeginAttempt(k, t0, limits).blocked(), "an unknown key is admitted");
    assertFalse(store.completeFailure(k, t0, limits).blocked());
    assertFalse(store.tryBeginAttempt(k, t0, limits).blocked());
    assertFalse(store.completeFailure(k, t0.plusSeconds(1), limits).blocked());
    assertFalse(store.tryBeginAttempt(k, t0.plusSeconds(1), limits).blocked());

    AttemptStatus third = store.completeFailure(k, t0.plusSeconds(2), limits);
    assertTrue(third.blocked(), "the third failure locks");
    assertEquals(3, third.failures());
    assertEquals(Optional.of(t0.plusSeconds(2).plus(Duration.ofMinutes(5))), third.blockedUntil());

    AttemptStatus gate = store.tryBeginAttempt(k, t0.plusSeconds(60), limits);
    assertTrue(gate.blocked());
    assertEquals(Optional.of(t0.plusSeconds(2).plus(Duration.ofMinutes(5))), gate.blockedUntil());
    assertEquals(3, store.failureCount(k), "the counter primitives see the same state");

    assertFalse(store.tryBeginAttempt(k, t0.plusSeconds(2).plus(Duration.ofMinutes(5)), limits)
        .blocked(), "the lockout ends at blockedUntil");
  }

  @Test
  @DisplayName("JS-SEC-123: completeSuccess clears an unlocked key but never lifts a live lockout")
  default void completeSuccessDoesNotLiftLiveLockout() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey unlocked = key("bob", "1.1.1.1");
    LoginAttemptKey locked = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();

    store.tryBeginAttempt(unlocked, t0, limits);
    store.completeFailure(unlocked, t0, limits);
    store.tryBeginAttempt(unlocked, t0, limits);
    AttemptStatus cleared = store.completeSuccess(unlocked, t0, limits);
    assertFalse(cleared.blocked());
    assertEquals(0, store.failureCount(unlocked));

    for (int i = 0; i < 3; i++) {
      store.completeFailure(locked, t0, limits);
    }
    AttemptStatus late = store.completeSuccess(locked, t0.plusSeconds(10), limits);
    assertTrue(late.blocked(), "a success during the lockout must be reported as blocked");
    assertEquals(3, store.failureCount(locked), "... and must leave the counter alone");
    assertTrue(store.tryBeginAttempt(locked, t0.plusSeconds(10), limits).blocked());
  }

  @Test
  @DisplayName("abandonAttempt on an unknown key is a no-op and never counts a failure")
  default void abandonAttemptCountsNothing() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");

    store.abandonAttempt(k, t0);
    store.tryBeginAttempt(k, t0, limits());
    store.abandonAttempt(k, t0);

    assertEquals(0, store.failureCount(k));
    assertTrue(store.lastFailureAt(k).isEmpty());
  }

  @Test
  @DisplayName("attempt operations reject null arguments")
  default void attemptOperationsRejectNulls() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();
    assertThrows(NullPointerException.class, () -> store.tryBeginAttempt(null, t, limits));
    assertThrows(NullPointerException.class, () -> store.tryBeginAttempt(k, null, limits));
    assertThrows(NullPointerException.class, () -> store.tryBeginAttempt(k, t, null));
    assertThrows(NullPointerException.class, () -> store.completeFailure(null, t, limits));
    assertThrows(NullPointerException.class, () -> store.completeFailure(k, null, limits));
    assertThrows(NullPointerException.class, () -> store.completeFailure(k, t, null));
    assertThrows(NullPointerException.class, () -> store.completeSuccess(null, t, limits));
    assertThrows(NullPointerException.class, () -> store.completeSuccess(k, null, limits));
    assertThrows(NullPointerException.class, () -> store.completeSuccess(k, t, null));
    assertThrows(NullPointerException.class, () -> store.abandonAttempt(null, t));
    assertThrows(NullPointerException.class, () -> store.abandonAttempt(k, null));
  }

  // ── address keys (JS-SEC-062, since 00.84.00) ──────────────────────

  /**
   * Limits of the address-key tests: 5 failures, 1 h window, 30 min lockout,
   * 30 s reservation - deliberately different from {@link #limits()}.
   *
   * @return the address limits
   */
  default AttemptLimits addressLimits() {
    return new AttemptLimits(5, Duration.ofHours(1), Duration.ofMinutes(30),
        Duration.ofSeconds(30));
  }

  @Test
  @DisplayName("JS-SEC-062: an address key round-trips and is independent of the account keys on the same address")
  default void addressKeyRoundTrip() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey address = LoginAttemptKey.forAddress(TenantId.DEFAULT, "1.1.1.1");
    LoginAttemptKey account = key("alice", "1.1.1.1");

    assertTrue(address.addressScoped());
    assertFalse(account.addressScoped());
    store.recordFailure(address, t0);
    store.recordFailure(address, t0.plusSeconds(5));
    store.recordFailure(account, t0);

    assertEquals(2, store.failureCount(address));
    assertEquals(Optional.of(t0.plusSeconds(5)), store.lastFailureAt(address));
    assertEquals(1, store.failureCount(account), "the account key on the same address is separate");
    assertEquals(0, store.failureCount(LoginAttemptKey.forAddress(TenantId.DEFAULT, "2.2.2.2")));
    assertEquals(0, store.failureCount(LoginAttemptKey.forAddress(new TenantId("acme"), "1.1.1.1")),
        "the tenant is part of the address key");

    store.reset(address);
    assertEquals(0, store.failureCount(address));
    assertTrue(store.lastFailureAt(address).isEmpty());
    assertEquals(1, store.failureCount(account), "resetting the address leaves the account alone");
  }

  @Test
  @DisplayName("JS-SEC-062: an address key locks at its own threshold while account keys keep theirs")
  default void addressKeyLocksWithItsOwnLimits() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey address = LoginAttemptKey.forAddress(TenantId.DEFAULT, "1.1.1.1");
    AttemptLimits accountLimits = limits();
    AttemptLimits addressLimits = addressLimits();

    // a spray: one failure on each of five accounts, every one also counted on the address
    for (int i = 0; i < addressLimits.failureThreshold(); i++) {
      Instant at = t0.plusSeconds(i);
      LoginAttemptKey account = key("user-" + i, "1.1.1.1");
      assertFalse(store.tryBeginAttempt(account, at, accountLimits).blocked());
      assertFalse(store.tryBeginAttempt(address, at, addressLimits).blocked(), "attempt " + (i + 1));
      assertFalse(store.completeFailure(account, at, accountLimits).blocked(),
          "one failure does not lock an account");
      AttemptStatus status = store.completeFailure(address, at, addressLimits);
      assertEquals(i + 1 == addressLimits.failureThreshold(), status.blocked(), "failure " + (i + 1));
    }

    Instant last = t0.plusSeconds(addressLimits.failureThreshold() - 1L);
    AttemptStatus refused = store.tryBeginAttempt(address, last.plusSeconds(60), addressLimits);
    assertTrue(refused.blocked(), "the address is locked");
    assertEquals(Optional.of(last.plus(addressLimits.lockout())), refused.blockedUntil(),
        "with the address lockout, not with the account lockout");
    assertFalse(store.tryBeginAttempt(key("user-0", "1.1.1.1"), last.plusSeconds(60), accountLimits)
        .blocked(), "the sprayed accounts themselves are not locked");
  }

  @Test
  @DisplayName("JS-SEC-062: an admitted attempt on an address key is a reservation; abandon gives it back and counts nothing")
  default void addressKeyReservation() {
    assumeTrue(this instanceof AtomicLoginAttemptStoreContract,
        "only an atomic store reserves attempts");
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey address = LoginAttemptKey.forAddress(TenantId.DEFAULT, "1.1.1.1");
    AttemptLimits limits = addressLimits();

    for (int i = 0; i < limits.failureThreshold(); i++) {
      assertFalse(store.tryBeginAttempt(address, t0, limits).blocked(), "attempt " + (i + 1));
    }
    AttemptStatus saturated = store.tryBeginAttempt(address, t0, limits);
    assertTrue(saturated.blocked(), "the threshold is in flight on the address");
    assertEquals(Optional.of(t0.plus(limits.reservationTtl())), saturated.blockedUntil());

    store.abandonAttempt(address, t0.plusSeconds(1));
    assertFalse(store.tryBeginAttempt(address, t0.plusSeconds(1), limits).blocked(),
        "an abandoned attempt frees its slot");
    assertEquals(0, store.failureCount(address), "and counts nothing");
  }
}
