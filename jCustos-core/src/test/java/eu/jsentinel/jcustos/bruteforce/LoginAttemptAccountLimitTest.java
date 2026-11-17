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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.MutableClock;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.RecordingAudit;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-166 (CWE-307): the account counter. An attacker who changes the client address after
 * every guess keeps each {@code (user, address)} counter below the threshold; the account counter
 * counts the account across all addresses. {@link InMemoryLoginAttemptPolicy} has always had it
 * (its user-name counter); {@link StoreBackedLoginAttemptPolicy} has it since 00.84.00 through
 * {@link LoginAttemptKey#forAccount(TenantId, String)}. Every behavioural test runs against both
 * policies - parity is the point. Real policies, real stores, synthetic data.
 */
@DisplayName("JS-SEC-166 - the account counter follows an account across client addresses")
class LoginAttemptAccountLimitTest {

  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
  /** Five failures within 15 min lock for 15 min (the defaults). */
  private static final LoginAttemptLimits LIMITS = LoginAttemptLimits.defaults();
  private static final int THRESHOLD = LIMITS.perAccount().failureThreshold();
  private static final Duration LOCKOUT = LIMITS.perAccount().initialLockout();
  private static final String HOME = "192.0.2.10";

  private static LoginAttemptContext ctx(String user, String address, Instant at) {
    return new LoginAttemptContext(user, address, null, at);
  }

  /** An address of the attacker's pool: a different one for every {@code i}. */
  private static String pool(int i) {
    return "198.51." + (i / 250) + "." + (i % 250);
  }

  /** The policies under test, each on a clock the test controls. */
  private static List<Function<Clock, LoginAttemptPolicy>> bothPolicies(RecordingAudit audit) {
    return List.of(
        clock -> new InMemoryLoginAttemptPolicy(LIMITS, clock, audit),
        clock -> new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore(), LIMITS,
            TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), audit));
  }

  /** One complete failed login; returns whether it was evaluated at all. */
  private static boolean failedLogin(LoginAttemptPolicy policy, LoginAttemptContext attempt) {
    if (policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.LockedOut) {
      return false;
    }
    policy.recordFailure(attempt);
    return true;
  }

  // ── distributed credential stuffing ────────────────────────────────

  @Test
  @DisplayName("one guess per address against one account: the account locks at its threshold, from every address")
  void addressHoppingLocksTheAccount() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      audit.events.clear();
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();

      int evaluated = 0;
      for (int i = 0; i < 100; i++) {
        if (failedLogin(policy, ctx("alice", pool(i), T0))) {
          evaluated++;
        }
      }

      assertEquals(THRESHOLD, evaluated,
          name + ": only threshold-many guesses against the account may be evaluated");
      LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("alice", HOME, T0)),
          name + ": the lockout follows the account to an address it was never tried from");
      assertEquals(LOCKOUT, locked.remaining(), name);
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("ALICE ", HOME, T0)),
          name + ": every spelling of the account is the same account");
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("bob", pool(1), T0)),
          name + ": the addresses themselves are not locked");

      List<BruteForceLimitReached> limitReached = limitReached(audit);
      assertEquals(1, limitReached.size(), name + ": the account lockout is audited once");
      assertEquals("alice", limitReached.getFirst().username(), name);
      assertEquals(THRESHOLD, limitReached.getFirst().failedAttempts(), name);
    }
  }

  @Test
  @DisplayName("attempts in flight from many addresses: threshold-many are admitted, abandon gives a slot back")
  void attemptsInFlightAreCountedOnTheAccount() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();

      for (int i = 0; i < THRESHOLD; i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("alice", pool(i), T0)),
            name + ": attempt " + (i + 1));
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("alice", pool(THRESHOLD), T0)),
          name + ": the threshold is in flight on the account, whatever the address");
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("alice", pool(THRESHOLD), T0)),
          name + ": attempts in flight are no lockout");

      policy.abandonAttempt(ctx("alice", pool(0), T0));
      assertEquals(LoginAttemptDecision.allowed(),
          policy.beforeAttempt(ctx("alice", pool(THRESHOLD), T0)),
          name + ": an abandoned attempt frees its slot on the account");
    }
  }

  @Test
  @DisplayName("one failure on each of 50 accounts from 50 addresses locks none of them - the counter is per account")
  void theAccountCounterCountsOneAccount() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      audit.events.clear();
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();
      for (int i = 0; i < 50; i++) {
        assertTrue(failedLogin(policy, ctx("user-" + i, pool(i), T0)), name + ": attempt " + i);
      }
      for (int i = 0; i < THRESHOLD - 1; i++) {
        assertTrue(failedLogin(policy, ctx("alice", pool(i), T0)), name);
      }
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("alice", HOME, T0)),
          name + ": one failure short of the threshold");
      assertEquals(0, limitReached(audit).size(), name);
    }
  }

  @Test
  @DisplayName("five failures from one address lock the tuple and the account at once - audited once")
  void tupleAndAccountLockTogetherAuditedOnce() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      audit.events.clear();
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();
      for (int i = 0; i < THRESHOLD; i++) {
        assertTrue(failedLogin(policy, ctx("alice", pool(7), T0)), name);
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("alice", HOME, T0)),
          name);
      assertEquals(1, limitReached(audit).size(), name + ": one lockout, one event");
    }
  }

  // ── what a success does ────────────────────────────────────────────

  @Test
  @DisplayName("a successful login clears the account counter, from whichever address it comes")
  void successClearsTheAccountCounter() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();
      for (int i = 0; i < THRESHOLD - 1; i++) {
        assertTrue(failedLogin(policy, ctx("alice", pool(i), T0)), name);
      }
      LoginAttemptContext owner = ctx("alice", HOME, T0);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(owner), name);
      assertEquals(LoginAttemptDecision.allowed(), policy.confirmSuccess(owner), name);

      for (int i = 0; i < THRESHOLD - 1; i++) {
        assertTrue(failedLogin(policy, ctx("alice", pool(100 + i), T0)), name);
      }
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("alice", HOME, T0)),
          name + ": the failures before the success no longer count");
    }
  }

  @Test
  @DisplayName("an account lockout earned from other addresses while the owner's check ran denies the owner's login")
  void lockoutDuringTheCheckDeniesTheLogin() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();
      LoginAttemptContext owner = ctx("alice", HOME, T0);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(owner), name);
      // reports without a gate, as an adapter with lapsed reservations produces them
      for (int i = 0; i < THRESHOLD; i++) {
        policy.recordFailure(ctx("alice", pool(i), T0));
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.confirmSuccess(owner),
          name + ": the correct password does not pass the account lockout");
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(owner),
          name + ": and the lockout stays");
    }
  }

  @Test
  @DisplayName("the documented consequence: whoever knows a user name can lock the account for the lockout duration, not longer")
  void targetedLockoutEndsOnTime() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(audit)) {
      MutableClock clock = new MutableClock(T0);
      LoginAttemptPolicy policy = factory.apply(clock);
      String name = policy.getClass().getSimpleName();
      for (int i = 0; i < THRESHOLD; i++) {
        assertTrue(failedLogin(policy, ctx("alice", pool(i), clock.instant())), name);
      }
      clock.advance(LOCKOUT.minusMillis(1));
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("alice", HOME, clock.instant())), name);
      clock.advance(Duration.ofMillis(1));
      LoginAttemptContext owner = ctx("alice", HOME, clock.instant());
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(owner),
          name + ": the owner gets in once the lockout ends");
      assertEquals(LoginAttemptDecision.allowed(), policy.confirmSuccess(owner), name);
    }
  }

  // ── store-backed: the account key ──────────────────────────────────

  @Test
  @DisplayName("store-backed: the failures of all addresses are stored on the account key, per tenant")
  void accountKeyIsStoredPerTenant() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
    RecordingAudit audit = new RecordingAudit();
    StoreBackedLoginAttemptPolicy acme = new StoreBackedLoginAttemptPolicy(store, LIMITS,
        new TenantId("acme"), clock, SubjectKeyCanonicalizer.defaults(), audit);
    StoreBackedLoginAttemptPolicy other = new StoreBackedLoginAttemptPolicy(store, LIMITS,
        TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), audit);

    assertTrue(failedLogin(acme, ctx("Alice", pool(1), T0)));
    assertTrue(failedLogin(acme, ctx("ALICE", pool(2), T0)));
    assertTrue(failedLogin(acme, ctx("alice", pool(3), T0)));

    LoginAttemptKey account = LoginAttemptKey.forAccount(new TenantId("acme"), "alice");
    assertEquals(3, store.failureCount(account));
    assertEquals(1, store.failureCount(new LoginAttemptKey(new TenantId("acme"), "alice", pool(1))),
        "the tuple keys keep counting as before");
    assertEquals(0, store.failureCount(LoginAttemptKey.forAccount(TenantId.DEFAULT, "alice")));
    for (int i = 0; i < THRESHOLD; i++) {
      failedLogin(acme, ctx("alice", pool(10 + i), T0));
    }
    assertEquals(LoginAttemptDecision.allowed(), other.peek(ctx("alice", HOME, T0)),
        "an account lockout in one tenant does not reach the same name in another");
  }

  @Test
  @DisplayName("store-backed: a user named like an account key gets a tuple key of its own")
  void reservedAccountIdCannotBeTaken() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(store, LIMITS,
        TenantId.DEFAULT, Clock.fixed(T0, ZoneOffset.UTC), SubjectKeyCanonicalizer.exact(),
        new RecordingAudit());
    String lookalike = LoginAttemptKey.ACCOUNT_USER_ID_PREFIX + "alice";
    for (int i = 0; i < THRESHOLD; i++) {
      assertTrue(failedLogin(policy, ctx(lookalike, LoginAttemptKey.ANY_ADDRESS, T0)));
    }

    assertEquals(0, store.failureCount(LoginAttemptKey.forAccount(TenantId.DEFAULT, "alice")),
        "the user name must not reach alice's account key");
    assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("alice", HOME, T0)));
    assertEquals(THRESHOLD, store.failureCount(new LoginAttemptKey(TenantId.DEFAULT,
        LoginAttemptKey.RESERVED_PREFIX + lookalike, LoginAttemptKey.ANY_ADDRESS)),
        "the escaped tuple key");
    assertEquals(THRESHOLD, store.failureCount(
        LoginAttemptKey.forAccount(TenantId.DEFAULT, lookalike)), "its own account key");
  }

  @Test
  @DisplayName("forAccount keys never equal a tuple key or the address key, and the mapping is injective")
  void accountKeysHaveTheirOwnNamespace() {
    List<String> names = List.of("alice", "#account:alice", "account:alice", "#address", "##x",
        "#", "-", "#any", "a#account:b");
    for (String name : names) {
      LoginAttemptKey account = LoginAttemptKey.forAccount(null, name);
      assertEquals(TenantId.DEFAULT, account.tenant());
      assertTrue(account.accountScoped(), name);
      assertFalse(account.addressScoped(), name);
      assertEquals(LoginAttemptKey.ANY_ADDRESS, account.ip());
      assertNotEquals(LoginAttemptKey.ADDRESS_USER_ID, account.userId(), name);
      for (String other : names) {
        assertNotEquals(LoginAttemptKey.accountUserId(other), account.userId(),
            "account key of '" + name + "' vs tuple user id of '" + other + "'");
        assertNotEquals(LoginAttemptKey.forAddress(null, other), account, name);
        assertEquals(name.equals(other),
            account.equals(LoginAttemptKey.forAccount(null, other)), name + " / " + other);
      }
      assertFalse(new LoginAttemptKey(null, LoginAttemptKey.accountUserId(name), HOME)
          .accountScoped(), "a tuple key is never account-scoped: " + name);
    }
    assertFalse(LoginAttemptKey.forAddress(null, HOME).accountScoped());
    assertThrows(IllegalArgumentException.class, () -> LoginAttemptKey.forAccount(null, " "));
    assertThrows(IllegalArgumentException.class, () -> LoginAttemptKey.forAccount(null, null));
  }

  private static List<BruteForceLimitReached> limitReached(RecordingAudit audit) {
    return audit.events.stream()
        .filter(BruteForceLimitReached.class::isInstance)
        .map(BruteForceLimitReached.class::cast)
        .toList();
  }

}
