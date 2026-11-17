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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptStatus;
import eu.jsentinel.jcustos.bruteforce.StoreBackedLoginAttemptPolicy;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
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
 *
 * <p>Precision (since 00.84.00): the tests whose name starts with {@code CWE-778}
 * run at sub-millisecond instants - every other test uses whole seconds. A store
 * may keep instants in milliseconds or whole seconds, as a database column does;
 * the lockout it reports must then start and end within
 * {@link StoreBackedLoginAttemptPolicy#STORE_INSTANT_TOLERANCE} of the failure
 * that caused it, and a {@link StoreBackedLoginAttemptPolicy} over it must
 * publish exactly one {@code BruteForceLimitReached} for that failure.
 *
 * <p>Several nodes (JS-SEC-166, since 00.84.00): the tests whose name starts with
 * {@code JS-SEC-166} run two {@link StoreBackedLoginAttemptPolicy} instances - two
 * "nodes" - on the one store under test, with clocks of their own and, for the
 * reservations, on threads of their own: a lockout earned through one node refuses
 * the account on the other, from any address; the attempts in flight on both nodes
 * together never exceed the threshold; the reservations of a node that fails lapse;
 * and a skew of two seconds between the node clocks moves the end of a lockout by
 * at most those two seconds, neither releasing it early nor keeping it for good.
 * Node B works with {@link #secondNodeStore(LoginAttemptStore)}: by default the
 * same instance as node A, which proves atomicity within one instance only - a
 * store whose atomicity rests on a lock inside the JVM passes then. A store meant
 * for several nodes overrides it with a second client of the same backend, so that
 * the two nodes meet in the backend as they do in a cluster.
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

  // ── precision of instants (CWE-778, since 00.84.00) ────────────────

  /**
   * An instant no store that keeps milliseconds or whole seconds can hold exactly.
   */
  private static Instant subMillisecond() {
    return Instant.parse("2026-01-01T00:00:00Z").plusNanos(123_456_789L);
  }

  @Test
  @DisplayName("CWE-778: failures at sub-millisecond instants lock the key; the lockout starts and ends with the locking failure, within the tolerance")
  default void lockoutAtSubMillisecondInstants() {
    LoginAttemptStore store = newStore();
    LoginAttemptKey k = key("alice", "1.1.1.1");
    AttemptLimits limits = limits();
    Duration tolerance = StoreBackedLoginAttemptPolicy.STORE_INSTANT_TOLERANCE;
    Instant at = subMillisecond();

    AttemptStatus last = null;
    for (int i = 0; i < limits.failureThreshold(); i++) {
      at = at.plusNanos(1_000_001L); // a little over a millisecond per failure
      assertFalse(store.tryBeginAttempt(k, at, limits).blocked(), "attempt " + (i + 1));
      last = store.completeFailure(k, at, limits);
    }
    assertTrue(last.blocked(), "the threshold-th failure locks");
    assertEquals(limits.failureThreshold(), last.failures());
    Instant expectedEnd = at.plus(limits.lockout());
    Instant reportedEnd = last.blockedUntil().orElseThrow();
    assertFalse(reportedEnd.isBefore(expectedEnd.minus(tolerance)),
        "the lockout starts with the locking failure: " + reportedEnd + " vs " + expectedEnd);
    assertFalse(reportedEnd.isAfter(expectedEnd.plus(tolerance)),
        "the lockout is no longer than lockout + tolerance: " + reportedEnd);

    assertTrue(store.tryBeginAttempt(k, expectedEnd.minus(tolerance).minusNanos(1), limits)
        .blocked(), "the lockout holds until shortly before its end");
    assertFalse(store.tryBeginAttempt(k, expectedEnd.plus(tolerance), limits).blocked(),
        "the lockout has ended once the tolerance has passed");
  }

  @Test
  @DisplayName("CWE-778: over this store the store-backed policy publishes exactly one BruteForceLimitReached for the failure that locks - at sub-millisecond instants")
  default void lockoutIsAuditedOnceAtSubMillisecondInstants() {
    LoginAttemptStore store = newStore();
    SharedTime time = new SharedTime(subMillisecond());
    List<AuditEvent> events = new CopyOnWriteArrayList<>();
    JCustosAuditService audit = new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        events.add(event);
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return List.copyOf(events);
      }
    };
    LoginAttemptLimits limits = nodeLimits().withAddressLimit(new LoginAttemptLimits.AddressLimit(
        5, Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofHours(4)));
    LoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(store, limits,
        TenantId.DEFAULT, time.node(Duration.ZERO), SubjectKeyCanonicalizer.defaults(), audit);
    int threshold = limits.perAccount().failureThreshold();

    // one account, one address: the tuple and the account key lock with the same failure
    for (int i = 0; i < threshold; i++) {
      time.set(time.now().plusNanos(1_234_567L));
      LoginAttemptContext guess = attempt("alice", "10.0.0.1", time);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(guess), "guess " + (i + 1));
      policy.recordFailure(guess);
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(attempt("alice", "10.0.0.1", time)));
    List<BruteForceLimitReached> account = limitReached(events);
    assertEquals(1, account.size(), "one event for the account lockout: " + account);
    assertEquals("alice", account.get(0).username());

    // a spray from another address: one failure per account until the address locks
    int addressThreshold = limits.perAddress().orElseThrow().failureThreshold();
    for (int i = 0; i < addressThreshold; i++) {
      time.set(time.now().plusNanos(1_234_567L));
      LoginAttemptContext guess = attempt("user-" + i, "10.0.0.2", time);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(guess), "spray " + (i + 1));
      policy.recordFailure(guess);
    }
    List<BruteForceLimitReached> all = limitReached(events);
    assertEquals(2, all.size(), "one more event, for the address lockout: " + all);
    assertEquals("10.0.0.2", all.get(1).clientAddress());
  }

  /** The {@code BruteForceLimitReached} events among {@code events}, in order. */
  private static List<BruteForceLimitReached> limitReached(List<AuditEvent> events) {
    return events.stream()
        .filter(BruteForceLimitReached.class::isInstance)
        .map(BruteForceLimitReached.class::cast)
        .toList();
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

  // ── several nodes on one store (JS-SEC-166, since 00.84.00) ────────

  /**
   * The thresholds of the two-node tests, the vocabulary of {@link #limits()}: 3 failures within
   * 10 min lock for 5 min.
   */
  private static LoginAttemptLimits nodeLimits() {
    return LoginAttemptLimits.of(new LoginAttemptConfiguration(3, Duration.ofMinutes(10),
        Duration.ofMinutes(5), Duration.ofMinutes(5)));
  }

  /**
   * The store node B of the two-node tests (JS-SEC-166) counts on: a second instance over the
   * same backing data as {@code store}, built the way a second node would build it. The default
   * returns {@code store} itself.
   *
   * @param store the store of node A, as {@link #newStore()} returned it
   * @return the store of node B
   * @since 00.84.00
   */
  default LoginAttemptStore secondNodeStore(LoginAttemptStore store) {
    return store;
  }

  /** One node of a cluster: a store-backed policy on the shared {@code store}. */
  private static LoginAttemptPolicy node(LoginAttemptStore store, Clock clock) {
    return new StoreBackedLoginAttemptPolicy(store, nodeLimits(), TenantId.DEFAULT, clock,
        SubjectKeyCanonicalizer.defaults(), NoopJCustosAuditService.INSTANCE);
  }

  private static LoginAttemptContext attempt(String user, String address, SharedTime time) {
    return new LoginAttemptContext(user, address, null, time.now());
  }

  @Test
  @DisplayName("JS-SEC-166: a lockout earned through node A refuses the account on node B - from the same address and from any other")
  default void lockoutOnOneNodeAppliesOnTheOther() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    SharedTime time = new SharedTime(t0);
    LoginAttemptPolicy nodeA = node(store, time.node(Duration.ZERO));
    LoginAttemptPolicy nodeB = node(secondNodeStore(store), time.node(Duration.ZERO));
    LoginAttemptConfiguration limits = nodeLimits().perAccount();

    // one address, every guess through node A
    for (int i = 0; i < limits.failureThreshold(); i++) {
      LoginAttemptContext guess = attempt("alice", "10.0.0.1", time);
      assertEquals(LoginAttemptDecision.allowed(), nodeA.beforeAttempt(guess), "guess " + (i + 1));
      nodeA.recordFailure(guess);
    }
    LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        nodeB.beforeAttempt(attempt("alice", "10.0.0.1", time)), "node B sees node A's lockout");
    assertEquals(limits.initialLockout(), locked.remaining());
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        nodeB.peek(attempt("alice", "192.0.2.99", time)), "from an address alice never used");

    // address hopping, the guesses spread over both nodes
    for (int i = 0; i < limits.failureThreshold(); i++) {
      LoginAttemptPolicy node = i % 2 == 0 ? nodeA : nodeB;
      LoginAttemptContext guess = attempt("carol", "10.0.1." + i, time);
      assertEquals(LoginAttemptDecision.allowed(), node.beforeAttempt(guess), "guess " + (i + 1));
      node.recordFailure(guess);
    }
    for (LoginAttemptPolicy node : List.of(nodeA, nodeB)) {
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          node.beforeAttempt(attempt("carol", "192.0.2.99", time)),
          "the account is locked on every node, whatever the address");
    }
    assertEquals(LoginAttemptDecision.allowed(), nodeB.peek(attempt("bob", "10.0.1.0", time)),
        "the addresses themselves are not locked");

    time.set(t0.plus(limits.initialLockout()));
    for (LoginAttemptPolicy node : List.of(nodeA, nodeB)) {
      LoginAttemptContext later = attempt("carol", "192.0.2.99", time);
      assertEquals(LoginAttemptDecision.allowed(), node.beforeAttempt(later),
          "the lockout ends on time on every node");
      node.abandonAttempt(later);
    }
  }

  @Test
  @DisplayName("JS-SEC-166: two nodes with 24 threads each, every guess from its own address - exactly threshold-many are evaluated, every round")
  default void reservationsOfBothNodesStayWithinTheThreshold() throws Exception {
    assumeTrue(this instanceof AtomicLoginAttemptStoreContract,
        "only an atomic store reserves attempts");
    LoginAttemptStore store = newStore();
    SharedTime time = new SharedTime(Instant.parse("2026-01-01T00:00:00Z"));
    List<LoginAttemptPolicy> nodes = List.of(node(store, time.node(Duration.ZERO)),
        node(secondNodeStore(store), time.node(Duration.ZERO)));
    int threshold = nodeLimits().perAccount().failureThreshold();
    int perNode = 24;
    int rounds = 8;
    List<ExecutorService> pools = List.of(Executors.newFixedThreadPool(perNode),
        Executors.newFixedThreadPool(perNode));
    try {
      for (int round = 0; round < rounds; round++) {
        String victim = "victim-" + round;
        CountDownLatch ready = new CountDownLatch(2 * perNode);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch decided = new CountDownLatch(2 * perNode);
        List<Future<Boolean>> outcomes = new ArrayList<>();
        for (int i = 0; i < 2 * perNode; i++) {
          LoginAttemptPolicy node = nodes.get(i % 2);
          LoginAttemptContext guess = attempt(victim, "10." + round + ".0." + i, time);
          outcomes.add(pools.get(i % 2).submit(() -> {
            ready.countDown();
            start.await();
            boolean admitted = node.beforeAttempt(guess) instanceof LoginAttemptDecision.Allowed;
            decided.countDown();
            if (admitted) {
              // every guess is decided before the first failure is reported
              decided.await(30, TimeUnit.SECONDS);
              node.recordFailure(guess);
            }
            return admitted;
          }));
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS), "the threads did not start");
        start.countDown();
        int admitted = 0;
        for (Future<Boolean> outcome : outcomes) {
          if (outcome.get(60, TimeUnit.SECONDS)) {
            admitted++;
          }
        }
        assertEquals(threshold, admitted, "round " + round + ": " + (2 * perNode)
            + " parallel guesses on two nodes against threshold " + threshold);
        assertEquals(threshold,
            store.failureCount(LoginAttemptKey.forAccount(TenantId.DEFAULT, victim)),
            "round " + round + ": the account key holds exactly the evaluated guesses");
        for (LoginAttemptPolicy node : nodes) {
          assertInstanceOf(LoginAttemptDecision.LockedOut.class,
              node.beforeAttempt(attempt(victim, "192.0.2.1", time)), "round " + round);
        }
      }
    } finally {
      pools.forEach(ExecutorService::shutdownNow);
    }
  }

  @Test
  @DisplayName("JS-SEC-166: the attempts in flight of a node that fails lapse - the other node gets the account back")
  default void reservationsOfAFailedNodeLapse() {
    assumeTrue(this instanceof AtomicLoginAttemptStoreContract,
        "only an atomic store reserves attempts");
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    SharedTime time = new SharedTime(t0);
    LoginAttemptPolicy nodeA = node(store, time.node(Duration.ZERO));
    LoginAttemptPolicy nodeB = node(secondNodeStore(store), time.node(Duration.ZERO));
    int threshold = nodeLimits().perAccount().failureThreshold();

    for (int i = 0; i < threshold; i++) {
      // node A admits and then fails before it can report anything
      assertEquals(LoginAttemptDecision.allowed(),
          nodeA.beforeAttempt(attempt("alice", "10.0.0." + i, time)));
    }
    LoginAttemptDecision.LockedOut refused = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        nodeB.beforeAttempt(attempt("alice", "192.0.2.1", time)),
        "the threshold is in flight on node A");
    assertTrue(refused.remaining().compareTo(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL) <= 0,
        "until a reservation lapses: " + refused.remaining());

    time.set(t0.plus(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL).minusMillis(1));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        nodeB.beforeAttempt(attempt("alice", "192.0.2.1", time)));
    time.set(t0.plus(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL));
    LoginAttemptContext owner = attempt("alice", "192.0.2.1", time);
    assertEquals(LoginAttemptDecision.allowed(), nodeB.beforeAttempt(owner),
        "the reservations of the failed node have lapsed");
    assertEquals(LoginAttemptDecision.allowed(), nodeB.confirmSuccess(owner));
    assertEquals(0, store.failureCount(LoginAttemptKey.forAccount(TenantId.DEFAULT, "alice")),
        "a lapsed reservation counts no failure");
  }

  @Test
  @DisplayName("JS-SEC-166: a clock skew of ±2 s between the nodes moves the end of a lockout by at most 2 s - no early release, no lockout for good")
  default void clockSkewMovesTheLockoutByTheSkewAtMost() {
    Duration skew = Duration.ofSeconds(2);
    LoginAttemptConfiguration limits = nodeLimits().perAccount();
    int threshold = limits.failureThreshold();
    // one store for all four scenarios, each a day after the one before and on its own account
    LoginAttemptStore store = newStore();
    int scenarioIndex = 0;
    for (Duration skewOfB : List.of(skew, skew.negated())) {
      for (int lockingNode = 0; lockingNode < 2; lockingNode++) {
        String scenario = "node B " + skewOfB + ", the locking failure on node "
            + (lockingNode == 0 ? "A" : "B");
        Instant t0 = Instant.parse("2026-01-01T00:00:00Z").plus(Duration.ofDays(scenarioIndex));
        String user = "alice-" + scenarioIndex++;
        SharedTime time = new SharedTime(t0);
        List<LoginAttemptPolicy> nodes = List.of(node(store, time.node(Duration.ZERO)),
            node(secondNodeStore(store), time.node(skewOfB)));

        // one guess a second, alternating between the nodes, every one from its own address
        for (int i = 0; i < threshold; i++) {
          time.set(t0.plusSeconds(i));
          LoginAttemptPolicy node = nodes.get((threshold - 1 - i + lockingNode) % 2);
          LoginAttemptContext guess = attempt(user, "10.0.0." + i, time);
          assertEquals(LoginAttemptDecision.allowed(), node.beforeAttempt(guess),
              scenario + ", guess " + (i + 1));
          node.recordFailure(guess);
        }
        Instant lockingFailure = t0.plusSeconds(threshold - 1L);
        Instant lockoutEnds = lockingFailure.plus(limits.initialLockout());

        time.set(lockoutEnds.minus(skew).minusMillis(1));
        for (int n = 0; n < 2; n++) {
          assertInstanceOf(LoginAttemptDecision.LockedOut.class,
              nodes.get(n).beforeAttempt(attempt(user, "192.0.2.1", time)),
              scenario + ": node " + (n == 0 ? "A" : "B") + " released the lockout more than "
                  + skew + " early");
        }

        time.set(lockoutEnds.plus(skew));
        for (int n = 0; n < 2; n++) {
          LoginAttemptContext probe = attempt(user, "192.0.2.1", time);
          assertEquals(LoginAttemptDecision.allowed(), nodes.get(n).beforeAttempt(probe),
              scenario + ": node " + (n == 0 ? "A" : "B") + " still locks " + skew
                  + " after the lockout ended");
          nodes.get(n).abandonAttempt(probe);
        }
        LoginAttemptContext owner = attempt(user, "192.0.2.1", time);
        assertEquals(LoginAttemptDecision.allowed(), nodes.get(1).beforeAttempt(owner), scenario);
        assertEquals(LoginAttemptDecision.allowed(), nodes.get(1).confirmSuccess(owner),
            scenario + ": the owner's login is accepted");
        assertEquals(0, store.failureCount(LoginAttemptKey.forAccount(TenantId.DEFAULT, user)),
            scenario + ": and clears the account");
      }
    }
  }
}
