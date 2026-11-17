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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.LoginFailed;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-062 (CWE-307): the address counter of both shipped policies. Password spraying - one
 * address, one guess against each of many accounts - stays below every account threshold; with
 * {@link LoginAttemptLimits#perAddress()} the address itself locks. Real policies, real stores,
 * synthetic data.
 */
@DisplayName("JS-SEC-062 - the address counter stops password spraying")
class LoginAttemptAddressLimitTest {

  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
  private static final String SPRAYER = "203.0.113.50";
  private static final String OTHER = "198.51.100.7";
  /** Ten failures from one address within an hour lock it for 30 min, doubling up to 2 h. */
  private static final LoginAttemptLimits.AddressLimit ADDRESS = new LoginAttemptLimits.AddressLimit(
      10, Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofHours(2));
  private static final LoginAttemptLimits LIMITS = LoginAttemptLimits.defaults().withAddressLimit(ADDRESS);
  private static final int SPRAYED_ACCOUNTS = 50;

  private static LoginAttemptContext ctx(String user, String address, Instant at) {
    return new LoginAttemptContext(user, address, null, at);
  }

  /** The policies under test, each on a clock the test controls. */
  private static List<Function<Clock, LoginAttemptPolicy>> bothPolicies(LoginAttemptLimits limits,
                                                                       RecordingAudit audit) {
    return List.of(
        clock -> new InMemoryLoginAttemptPolicy(limits, clock, audit),
        clock -> new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore(), limits,
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

  // ── the spray ──────────────────────────────────────────────────────

  @Test
  @DisplayName("50 user names from one address: the address locks at its threshold, the accounts stay open")
  void sprayLocksTheAddressNotTheAccounts() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(LIMITS, audit)) {
      audit.events.clear();
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();

      int evaluated = 0;
      for (int i = 0; i < SPRAYED_ACCOUNTS; i++) {
        if (failedLogin(policy, ctx("user-" + i, SPRAYER, T0))) {
          evaluated++;
        }
      }

      assertEquals(ADDRESS.failureThreshold(), evaluated,
          name + ": only threshold-many guesses from the spraying address may be evaluated");
      LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("someone-new", SPRAYER, T0)), name);
      assertEquals(ADDRESS.initialLockout(), locked.remaining(), name);
      for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("user-" + i, OTHER, T0)),
            name + ": a sprayed account is not locked - its owner logs in from elsewhere");
      }
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("user-0", OTHER, T0)),
          name);
      policy.abandonAttempt(ctx("user-0", OTHER, T0));

      assertEquals(ADDRESS.failureThreshold(), count(audit, LoginFailed.class), name);
      List<BruteForceLimitReached> limitReached = audit.events.stream()
          .filter(BruteForceLimitReached.class::isInstance)
          .map(BruteForceLimitReached.class::cast)
          .toList();
      assertEquals(1, limitReached.size(), name + ": the address lockout is audited once");
      assertEquals("", limitReached.getFirst().username(), name + ": it names no account");
      assertEquals(SPRAYER, limitReached.getFirst().clientAddress(), name);
    }
  }

  @Test
  @DisplayName("defaults: without perAddress the same spray is evaluated in full - nothing changes without configuration")
  void withoutAddressLimitNothingChanges() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory
        : bothPolicies(LoginAttemptLimits.defaults(), audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      int evaluated = 0;
      for (int i = 0; i < SPRAYED_ACCOUNTS; i++) {
        if (failedLogin(policy, ctx("user-" + i, SPRAYER, T0))) {
          evaluated++;
        }
      }
      assertEquals(SPRAYED_ACCOUNTS, evaluated, policy.getClass().getSimpleName());
    }
    InMemoryLoginAttemptPolicy plain = new InMemoryLoginAttemptPolicy(
        LoginAttemptConfiguration.defaults(), Clock.fixed(T0, ZoneOffset.UTC), audit);
    assertTrue(plain.limits().perAddress().isEmpty());
    assertEquals(0, plain.trackedAddressCount());
  }

  @Test
  @DisplayName("an attempt without a client address is not counted on any address")
  void attemptsWithoutAddressAreNotCounted() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(LIMITS, audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      for (int i = 0; i < SPRAYED_ACCOUNTS; i++) {
        assertTrue(failedLogin(policy, ctx("user-" + i, i % 2 == 0 ? null : "  ", T0)),
            policy.getClass().getSimpleName() + ": attempt " + i);
      }
    }
  }

  // ── what a success does and does not do ────────────────────────────

  @Test
  @DisplayName("a successful login does not reset the address counter - one own account must not reset the spray")
  void successDoesNotResetTheAddress() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(LIMITS, audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();
      int evaluated = 0;
      for (int i = 0; i < SPRAYED_ACCOUNTS; i++) {
        if (i % 3 == 0) {
          // the attacker's own account, with the right password, every third request
          LoginAttemptContext own = ctx("attacker", SPRAYER, T0);
          if (policy.beforeAttempt(own) instanceof LoginAttemptDecision.Allowed) {
            assertEquals(LoginAttemptDecision.allowed(), policy.confirmSuccess(own), name);
          }
        } else if (failedLogin(policy, ctx("user-" + i, SPRAYER, T0))) {
          evaluated++;
        }
      }
      assertEquals(ADDRESS.failureThreshold(), evaluated, name);
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("attacker", SPRAYER, T0)),
          name + ": the locked address refuses the attacker's own account as well");
    }
  }

  @Test
  @DisplayName("a lockout of the address that set in while the check ran denies the login (JS-SEC-123)")
  void addressLockedDuringTheCheckDeniesTheLogin() {
    RecordingAudit audit = new RecordingAudit();
    for (Function<Clock, LoginAttemptPolicy> factory : bothPolicies(LIMITS, audit)) {
      LoginAttemptPolicy policy = factory.apply(Clock.fixed(T0, ZoneOffset.UTC));
      String name = policy.getClass().getSimpleName();
      LoginAttemptContext pending = ctx("alice", SPRAYER, T0);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(pending), name);
      // reports without a gate, as an adapter with lapsed reservations produces them
      for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
        policy.recordFailure(ctx("user-" + i, SPRAYER, T0));
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.confirmSuccess(pending),
          name + ": the correct password does not pass the address lockout");
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("bob", SPRAYER, T0)),
          name + ": and does not lift it");
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("alice", OTHER, T0)), name);
    }
  }

  // ── lockout lifetime ───────────────────────────────────────────────

  @Test
  @DisplayName("in memory: the address lockout ends on time and doubles on the next breach")
  void inMemoryAddressLockoutEscalates() {
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(LIMITS, clock, new RecordingAudit());
    for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
      assertTrue(failedLogin(policy, ctx("first-" + i, SPRAYER, clock.instant())));
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("x", SPRAYER, T0)));

    clock.advance(ADDRESS.initialLockout());
    assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("x", SPRAYER, clock.instant())),
        "the first lockout lasts initialLockout");
    for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
      assertTrue(failedLogin(policy, ctx("second-" + i, SPRAYER, clock.instant())));
    }
    LoginAttemptDecision.LockedOut second = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.peek(ctx("x", SPRAYER, clock.instant())));
    assertEquals(ADDRESS.initialLockout().multipliedBy(2), second.remaining(),
        "the second breach doubles the address lockout");
  }

  @Test
  @DisplayName("store-backed: the address lockout is flat - initialLockout from the failure that reached the threshold")
  void storeBackedAddressLockoutIsFlat() {
    MutableClock clock = new MutableClock(T0);
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), LIMITS, TenantId.DEFAULT, clock,
        SubjectKeyCanonicalizer.defaults(), new RecordingAudit());
    for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
      assertTrue(failedLogin(policy, ctx("user-" + i, SPRAYER, clock.instant())));
    }
    LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.peek(ctx("x", SPRAYER, clock.instant())));
    assertEquals(ADDRESS.initialLockout(), locked.remaining());
    clock.advance(ADDRESS.initialLockout());
    assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("x", SPRAYER, clock.instant())));
  }

  @Test
  @DisplayName("store-backed: a refusal by the address gives the account's reservation back")
  void storeBackedAddressRefusalReleasesTheAccount() {
    MutableClock clock = new MutableClock(T0);
    LoginAttemptLimits shortAddressLockout = LoginAttemptLimits.defaults().withAddressLimit(
        new LoginAttemptLimits.AddressLimit(2, Duration.ofHours(1), Duration.ofSeconds(5),
            Duration.ofSeconds(5)));
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), shortAddressLockout, TenantId.DEFAULT, clock,
        SubjectKeyCanonicalizer.defaults(), new RecordingAudit());
    assertTrue(failedLogin(policy, ctx("a", SPRAYER, clock.instant())));
    assertTrue(failedLogin(policy, ctx("b", SPRAYER, clock.instant())));

    int accountThreshold = LoginAttemptConfiguration.defaults().failureThreshold();
    for (int i = 0; i < accountThreshold + 2; i++) {
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("victim", SPRAYER, clock.instant())), "refused by the address");
    }
    // the address lockout ends long before an account reservation (30 s) would lapse
    clock.advance(Duration.ofSeconds(6));
    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("victim", SPRAYER, clock.instant())),
        "no reservation of the refused attempts may be left on the account");
  }

  // ── capacity (JS-SEC-122) and the reserved user id ─────────────────

  @Test
  @DisplayName("in memory: the address map is bounded and never evicts a live address lockout")
  void addressMapIsBoundedAndKeepsLockouts() {
    int cap = 4;
    LoginAttemptLimits limits = LoginAttemptLimits.defaults().withAddressLimit(
        new LoginAttemptLimits.AddressLimit(2, Duration.ofHours(1), Duration.ofHours(1),
            Duration.ofHours(1)));
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(limits, clock,
        new RecordingAudit(), cap, SubjectKeyCanonicalizer.defaults());
    assertTrue(failedLogin(policy, ctx("a", SPRAYER, clock.instant())));
    assertTrue(failedLogin(policy, ctx("b", SPRAYER, clock.instant())));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("c", SPRAYER, T0)));

    for (int i = 0; i < cap * 5; i++) {
      clock.advance(Duration.ofMillis(10));
      failedLogin(policy, ctx("spray-" + i, "10.1.0." + i, clock.instant()));
      assertTrue(policy.trackedAddressCount() <= cap, "address map over its bound");
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.peek(ctx("c", SPRAYER, clock.instant())),
          "the address lockout was pushed out after " + (i + 1) + " new addresses");
    }
  }

  @Test
  @DisplayName("in memory: an address map full of lockouts refuses a new address (RF01)")
  void fullAddressMapRefusesNewAddresses() {
    int cap = 2;
    LoginAttemptLimits limits = LoginAttemptLimits.defaults().withAddressLimit(
        new LoginAttemptLimits.AddressLimit(1, Duration.ofHours(1), Duration.ofHours(1),
            Duration.ofHours(1)));
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(limits,
        Clock.fixed(T0, ZoneOffset.UTC), new RecordingAudit(), cap, SubjectKeyCanonicalizer.defaults());
    assertTrue(failedLogin(policy, ctx("a", "10.0.0.1", T0)));
    assertTrue(failedLogin(policy, ctx("b", "10.0.0.2", T0)));

    LoginAttemptDecision.LockedOut refused = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("c", "10.0.0.3", T0)));
    assertEquals(Duration.ofHours(1), refused.remaining(), "until the first lockout ends");
    assertEquals(cap, policy.trackedAddressCount());
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("z", "10.0.0.1", T0)));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("z", "10.0.0.2", T0)));
  }

  @Test
  @DisplayName("store-backed: a user named like the reserved address id gets an account key of its own")
  void reservedUserIdCannotBeTaken() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(store,
        LoginAttemptLimits.defaults(), TenantId.DEFAULT, Clock.fixed(T0, ZoneOffset.UTC),
        SubjectKeyCanonicalizer.exact(), new RecordingAudit());
    assertTrue(failedLogin(policy, ctx(LoginAttemptKey.ADDRESS_USER_ID, SPRAYER, T0)));
    assertTrue(failedLogin(policy, ctx(LoginAttemptKey.ADDRESS_USER_ID, SPRAYER, T0)));

    assertEquals(0, store.failureCount(LoginAttemptKey.forAddress(TenantId.DEFAULT, SPRAYER)),
        "the user name must not reach the address key");
    assertEquals(2, store.failureCount(new LoginAttemptKey(TenantId.DEFAULT,
        LoginAttemptKey.RESERVED_PREFIX + LoginAttemptKey.ADDRESS_USER_ID, SPRAYER)));
  }

  @Test
  @DisplayName("accountUserId is injective and never yields the reserved address id")
  void accountUserIdEscapesTheReservedPrefix() {
    assertEquals("alice", LoginAttemptKey.accountUserId("alice"));
    assertEquals("##address", LoginAttemptKey.accountUserId("#address"));
    assertEquals("###x", LoginAttemptKey.accountUserId("##x"));
    for (String name : List.of("#address", "address", "#", "##address", "-", "a#address")) {
      assertNotEquals(LoginAttemptKey.ADDRESS_USER_ID, LoginAttemptKey.accountUserId(name), name);
    }
    assertNotEquals(LoginAttemptKey.accountUserId("#x"), LoginAttemptKey.accountUserId("##x"));
    assertTrue(LoginAttemptKey.forAddress(null, SPRAYER).addressScoped());
    assertFalse(new LoginAttemptKey(null, "alice", SPRAYER).addressScoped());
  }

  private static long count(RecordingAudit audit, Class<? extends AuditEvent> type) {
    return audit.events.stream().filter(type::isInstance).count();
  }
}
