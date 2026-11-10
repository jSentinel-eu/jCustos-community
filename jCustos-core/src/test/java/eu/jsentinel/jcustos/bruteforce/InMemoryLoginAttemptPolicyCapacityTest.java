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

import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.MutableClock;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.RecordingAudit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-122 (CWE-307, CWE-770): the in-memory policy under capacity pressure (S01 + S02 of the
 * security analysis of 28.10.2026). Real policy, real clock seam, no doubles.
 */
@DisplayName("InMemoryLoginAttemptPolicy - capacity (JS-SEC-122)")
class InMemoryLoginAttemptPolicyCapacityTest {

  private static final Instant T0 = Instant.parse("2026-05-08T10:00:00Z");
  /** 3 failures / 5 min window / 60 s lockout / 10 min cap. */
  private static final LoginAttemptConfiguration CONFIG = new LoginAttemptConfiguration(
      3, Duration.ofMinutes(5), Duration.ofSeconds(60), Duration.ofMinutes(10));

  private static LoginAttemptContext ctx(String user, Instant at) {
    return new LoginAttemptContext(user, "10.0.0.1", null, at);
  }

  /** A full login that fails: gate, then report - what an adapter does. */
  private static LoginAttemptDecision failedLogin(InMemoryLoginAttemptPolicy policy, String user,
                                                  Instant at) {
    LoginAttemptDecision gate = policy.beforeAttempt(ctx(user, at));
    if (gate instanceof LoginAttemptDecision.Allowed) {
      policy.recordFailure(ctx(user, at));
    }
    return gate;
  }

  @Test
  @DisplayName("an active lockout survives a spray of more than maxEntries new keys until it really expires")
  void lockoutSurvivesKeySprayUntilExpiry() {
    int cap = 20;
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy =
        new InMemoryLoginAttemptPolicy(CONFIG, clock, new RecordingAudit(), cap);

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      failedLogin(policy, "victim", clock.instant());
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("victim", clock.instant())));

    // the spray: three times the capacity in fresh user names, one failed login each
    for (int i = 0; i < cap * 3; i++) {
      clock.advance(Duration.ofMillis(10));
      failedLogin(policy, "spray-" + i, clock.instant());
      assertTrue(policy.trackedCombinedKeyCount() <= cap,
          "combined map over the bound: " + policy.trackedCombinedKeyCount());
      assertTrue(policy.trackedUsernameCount() <= cap,
          "username map over the bound: " + policy.trackedUsernameCount());
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("victim", clock.instant())),
          "the victim's lockout was pushed out after " + (i + 1) + " sprayed keys");
    }

    // ... and it ends when its time is up, not earlier and not later
    clock.advance(Duration.ofSeconds(60));
    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("victim", clock.instant())));
  }

  @Test
  @DisplayName("S02: with only locked keys left, a further key is refused and the map does not grow")
  void onlyLockedKeysLeft_newKeyIsRefused() {
    int cap = 2;
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy =
        new InMemoryLoginAttemptPolicy(CONFIG, clock, new RecordingAudit(), cap);

    // the reproduction of S02: twenty accounts, each driven into its lockout through the
    // ordinary beforeAttempt -> recordFailure sequence
    int refused = 0;
    for (int account = 0; account < 20; account++) {
      for (int i = 0; i < CONFIG.failureThreshold(); i++) {
        if (failedLogin(policy, "account-" + account, clock.instant())
            instanceof LoginAttemptDecision.LockedOut) {
          refused++;
        }
        assertTrue(policy.trackedCombinedKeyCount() <= cap,
            "combined map grew to " + policy.trackedCombinedKeyCount());
        assertTrue(policy.trackedUsernameCount() <= cap,
            "username map grew to " + policy.trackedUsernameCount());
      }
    }
    assertEquals(18 * CONFIG.failureThreshold(), refused,
        "accounts 3 to 20 find the map full of live lockouts and are denied");

    // the refusal is a lockout decision that ends with the first live lockout
    LoginAttemptDecision.LockedOut refusal = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("someone-new", clock.instant())));
    assertEquals(Duration.ofSeconds(60), refusal.remaining());
    assertEquals(0, refusal.failedAttempts());

    // both original lockouts are still in force
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("account-0", clock.instant())));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("account-1", clock.instant())));

    // once they have ended, new keys find room again
    clock.advance(Duration.ofSeconds(60));
    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("someone-new", clock.instant())));
    assertTrue(policy.trackedCombinedKeyCount() <= cap);
  }

  @Test
  @DisplayName("state that has expired is removed by the next call, without a successful login")
  void expiredStateIsRemoved() {
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy =
        new InMemoryLoginAttemptPolicy(CONFIG, clock, new RecordingAudit(), 100);

    for (int i = 0; i < 10; i++) {
      failedLogin(policy, "one-shot-" + i, clock.instant());
    }
    assertEquals(10, policy.trackedCombinedKeyCount());
    assertEquals(10, policy.trackedUsernameCount());

    // the failures leave the window; any call sweeps them out
    clock.advance(Duration.ofMinutes(5).plusSeconds(1));
    policy.beforeAttempt(ctx("someone-else", clock.instant()));
    policy.abandonAttempt(ctx("someone-else", clock.instant()));

    assertEquals(0, policy.trackedCombinedKeyCount());
    assertEquals(0, policy.trackedUsernameCount());
  }

  @Test
  @DisplayName("a lockout level is remembered for maxLockout after the lockout, then forgotten")
  void lockoutLevelExpires() {
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy =
        new InMemoryLoginAttemptPolicy(CONFIG, clock, new RecordingAudit(), 100);

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      failedLogin(policy, "alice", clock.instant());
    }
    // lockout over, level still known: the second lockout is twice as long
    clock.advance(Duration.ofSeconds(61));
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      failedLogin(policy, "alice", clock.instant());
    }
    LoginAttemptDecision.LockedOut second = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", clock.instant())));
    assertEquals(Duration.ofSeconds(120), second.remaining());

    // quiet for the lockout plus maxLockout: the entry is gone, the next lockout starts over
    clock.advance(Duration.ofSeconds(120).plus(Duration.ofMinutes(10)));
    policy.peek(ctx("alice", clock.instant()));
    assertEquals(0, policy.trackedUsernameCount());
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      failedLogin(policy, "alice", clock.instant());
    }
    LoginAttemptDecision.LockedOut fresh = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", clock.instant())));
    assertEquals(Duration.ofSeconds(60), fresh.remaining());
  }
}
