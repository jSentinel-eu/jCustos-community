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
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.RecordingAudit;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF03 (R3, JS-SEC-062, CWE-307): the address counter counts failures, not attempts
 * in flight. With a reservation on the address, three users behind one NAT address who log in at
 * the same moment made a fourth user of another account wait 30 s - the reservation's lifetime -
 * without a single failure. Real policies, real stores, synthetic data.
 */
@DisplayName("RF03 - the address counter counts failures, not logins in flight")
class LoginAttemptAddressInFlightTest {

  private static final Instant T0 = Instant.parse("2026-11-19T10:00:00Z");
  private static final String NAT = "198.51.100.10";
  /** Three failures from one address within an hour lock it for 30 min. */
  private static final LoginAttemptLimits.AddressLimit ADDRESS = new LoginAttemptLimits.AddressLimit(
      3, Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofHours(2));
  private static final LoginAttemptLimits LIMITS = LoginAttemptLimits.defaults().withAddressLimit(ADDRESS);

  private static LoginAttemptContext ctx(String user, String address) {
    return new LoginAttemptContext(user, address, null, T0);
  }

  /** A policy and, for the store-backed one, the store it counts in. */
  private record Subject(LoginAttemptPolicy policy, InMemoryLoginAttemptStore store) {

    String name() {
      return policy.getClass().getSimpleName();
    }
  }

  private static List<Subject> bothPolicies(RecordingAudit audit) {
    Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    return List.of(
        new Subject(new InMemoryLoginAttemptPolicy(LIMITS, clock, audit), null),
        new Subject(new StoreBackedLoginAttemptPolicy(store, LIMITS, TenantId.DEFAULT, clock,
            SubjectKeyCanonicalizer.defaults(), audit), store));
  }

  @Test
  @DisplayName("threshold 3, three logins of different accounts in flight from one address: the fourth account is Allowed")
  void loginsInFlightDoNotSaturateTheAddress() {
    for (Subject subject : bothPolicies(new RecordingAudit())) {
      LoginAttemptPolicy policy = subject.policy();
      for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("user" + i, NAT)),
            subject.name() + ": user" + i);
      }

      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("user3", NAT)),
          subject.name() + ": a fourth account behind the same address must not wait for the"
              + " logins in flight");

      if (policy instanceof InMemoryLoginAttemptPolicy inMemory) {
        assertEquals(0, inMemory.trackedAddressCount(), "the address holds no reservation");
      } else {
        assertEquals(0, subject.store().failureCount(
            LoginAttemptKey.forAddress(TenantId.DEFAULT, NAT)));
        assertEquals(8, subject.store().trackedKeyCount(),
            "four tuple keys and four account keys are in flight - and no address key");
      }
      for (int i = 0; i <= ADDRESS.failureThreshold(); i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.confirmSuccess(ctx("user" + i, NAT)),
            subject.name() + ": user" + i + " logs in");
      }
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("user9", NAT)), subject.name());
    }
  }

  @Test
  @DisplayName("failures still lock the address at its threshold; the logins already in flight are the bounded overshoot")
  void failuresStillLockTheAddress() {
    RecordingAudit audit = new RecordingAudit();
    for (Subject subject : bothPolicies(audit)) {
      audit.events.clear();
      LoginAttemptPolicy policy = subject.policy();
      int inFlight = ADDRESS.failureThreshold() + 1;
      for (int i = 0; i < inFlight; i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("user" + i, NAT)),
            subject.name() + ": user" + i);
      }
      for (int i = 0; i < inFlight; i++) {
        policy.recordFailure(ctx("user" + i, NAT));
      }

      LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("user-next", NAT)), subject.name() + ": the address is locked");
      assertEquals(ADDRESS.initialLockout(), locked.remaining(), subject.name());
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("someone", NAT)),
          subject.name());
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("user0", "203.0.113.9")),
          subject.name() + ": the accounts themselves are not locked");
      if (subject.store() != null) {
        assertEquals(inFlight, subject.store().failureCount(
            LoginAttemptKey.forAddress(TenantId.DEFAULT, NAT)),
            "every attempt that was already in flight is counted");
      }
      BruteForceLimitReached first = audit.events.stream()
          .filter(BruteForceLimitReached.class::isInstance)
          .map(BruteForceLimitReached.class::cast)
          .findFirst()
          .orElseThrow(() -> new AssertionError(subject.name() + ": no BruteForceLimitReached"));
      assertEquals("", first.username(), subject.name());
      assertEquals(NAT, first.clientAddress(), subject.name());
    }
  }

  @Test
  @DisplayName("an abandoned or failed attempt gives back no address slot it never took; the next ones are still admitted")
  void abandonAndFailureReleaseNothingOnTheAddress() {
    for (Subject subject : bothPolicies(new RecordingAudit())) {
      LoginAttemptPolicy policy = subject.policy();
      for (int round = 0; round < 3 * ADDRESS.failureThreshold(); round++) {
        LoginAttemptContext attempt = ctx("user" + round, NAT);
        assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt),
            subject.name() + ": round " + round);
        policy.abandonAttempt(attempt);
      }
      // two failures, then threshold-many logins in flight: still admitted, the third failure locks
      policy.beforeAttempt(ctx("a", NAT));
      policy.recordFailure(ctx("a", NAT));
      policy.beforeAttempt(ctx("b", NAT));
      policy.recordFailure(ctx("b", NAT));
      for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("c" + i, NAT)),
            subject.name() + ": two failures and " + i + " in flight");
      }
      policy.recordFailure(ctx("c0", NAT));
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("d", NAT)),
          subject.name() + ": the third failure locks");
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.confirmSuccess(ctx("c1", NAT)),
          subject.name() + ": a login in flight is denied by the lockout that set in meanwhile");
    }
  }

  @Test
  @DisplayName("the account keys keep their reservations: one account saturates, another account from the same address is admitted")
  void accountKeysKeepTheirReservations() {
    LoginAttemptLimits roomyAddress = LoginAttemptLimits.defaults().withAddressLimit(
        new LoginAttemptLimits.AddressLimit(2, Duration.ofHours(1), Duration.ofMinutes(30),
            Duration.ofHours(2)));
    Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
    for (LoginAttemptPolicy policy : List.of(
        new InMemoryLoginAttemptPolicy(roomyAddress, clock, new RecordingAudit()),
        new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore(), roomyAddress,
            TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), new RecordingAudit()))) {
      String name = policy.getClass().getSimpleName();
      int accountThreshold = roomyAddress.perAccount().failureThreshold();
      for (int i = 0; i < accountThreshold; i++) {
        assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("victim", NAT)),
            name + ": attempt " + i);
      }
      LoginAttemptDecision.LockedOut saturated = assertInstanceOf(
          LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("victim", NAT)),
          name + ": the account threshold is in flight");
      assertTrue(saturated.remaining().compareTo(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL)
          <= 0, name + ": until a reservation lapses");
      assertFalse(policy.beforeAttempt(ctx("colleague", NAT)) instanceof LoginAttemptDecision.LockedOut,
          name + ": although more attempts than the address threshold are in flight from it");
    }
  }
}
