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
import eu.jsentinel.jcustos.util.CapacityBound;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-123 (CWE-367, CWE-307, CWE-178): the lockout as one atomic step, a success that does
 * not lift it, and one key per account. Real policy, real threads.
 */
@DisplayName("InMemoryLoginAttemptPolicy - atomic lockout (JS-SEC-123)")
class InMemoryLoginAttemptPolicyAtomicityTest {

  private static final Instant T0 = Instant.parse("2026-05-08T10:00:00Z");
  private static final LoginAttemptConfiguration CONFIG = LoginAttemptConfiguration.defaults();

  private static LoginAttemptContext ctx(String user, String client, Instant at) {
    return new LoginAttemptContext(user, client, null, at);
  }

  private static InMemoryLoginAttemptPolicy policyAt(Clock clock) {
    return new InMemoryLoginAttemptPolicy(CONFIG, clock, new RecordingAudit());
  }

  @Test
  @DisplayName("50 parallel guesses at threshold 5: at most 5 are evaluated")
  void parallelGuessesCannotExceedTheThreshold() throws InterruptedException {
    InMemoryLoginAttemptPolicy policy = policyAt(Clock.fixed(T0, ZoneOffset.UTC));
    int threads = 50;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch go = new CountDownLatch(1);
    CountDownLatch gatePassed = new CountDownLatch(threads);
    CountDownLatch done = new CountDownLatch(threads);
    AtomicInteger allowed = new AtomicInteger();
    AtomicInteger lockedOut = new AtomicInteger();

    for (int i = 0; i < threads; i++) {
      String client = "10.0.0." + i;   // every guess from another address, as an attacker would
      Thread thread = new Thread(() -> {
        ready.countDown();
        try {
          go.await();
          LoginAttemptContext attempt = ctx("victim", client, T0);
          LoginAttemptDecision decision = policy.beforeAttempt(attempt);
          gatePassed.countDown();
          if (decision instanceof LoginAttemptDecision.Allowed) {
            allowed.incrementAndGet();
            // the credential check runs while every other request is already past the gate
            gatePassed.await(5, TimeUnit.SECONDS);
            policy.recordFailure(attempt);
          } else {
            lockedOut.incrementAndGet();
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
    assertTrue(ready.await(5, TimeUnit.SECONDS));
    go.countDown();
    assertTrue(done.await(20, TimeUnit.SECONDS), "all attempts must finish");

    assertEquals(threads, allowed.get() + lockedOut.get());
    assertTrue(allowed.get() <= CONFIG.failureThreshold(),
        allowed.get() + " guesses were evaluated at a threshold of " + CONFIG.failureThreshold());
    assertEquals(CONFIG.failureThreshold(), allowed.get(),
        "the threshold itself must still be usable");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("victim", "10.9.9.9", T0)),
        "five counted failures lock the account");
  }

  @Test
  @DisplayName("a success reported after the lockout set in does not lift it and is answered with LockedOut")
  void lateSuccessDoesNotLiftTheLockout() {
    InMemoryLoginAttemptPolicy policy = policyAt(Clock.fixed(T0, ZoneOffset.UTC));
    LoginAttemptContext attacker = ctx("victim", "10.0.0.66", T0);

    // one attempt is still being checked ...
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attacker));
    // ... while five failures are reported for the account (reports without a gate, as an
    // adapter with a lost reservation produces them)
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx("victim", "10.0.0." + i, T0));
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(attacker));

    // the pending attempt turns out to carry the right password
    LoginAttemptDecision completion = policy.confirmSuccess(attacker);
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, completion,
        "the adapter must be told to deny the login");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(attacker),
        "the lockout must still be in force");

    // the older, void form may not lift it either
    policy.recordSuccess(attacker);
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(attacker));
  }

  @Test
  @DisplayName("a success without a lockout still clears both counters")
  void successWithoutLockoutClears() {
    InMemoryLoginAttemptPolicy policy = policyAt(Clock.fixed(T0, ZoneOffset.UTC));
    LoginAttemptContext alice = ctx("alice", "10.0.0.1", T0);
    for (int i = 0; i < CONFIG.failureThreshold() - 1; i++) {
      policy.beforeAttempt(alice);
      policy.recordFailure(alice);
    }
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(alice));
    assertEquals(LoginAttemptDecision.allowed(), policy.confirmSuccess(alice));
    assertEquals(0, policy.trackedCombinedKeyCount());
    assertEquals(0, policy.trackedUsernameCount());
  }

  @Test
  @DisplayName("an abandoned attempt frees its slot and counts nothing")
  void abandonedAttemptFreesItsSlot() {
    InMemoryLoginAttemptPolicy policy = policyAt(Clock.fixed(T0, ZoneOffset.UTC));
    LoginAttemptContext alice = ctx("alice", "10.0.0.1", T0);

    for (int round = 0; round < 20; round++) {
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(alice),
          "round " + round + ": an attempt without a verdict must not use up the threshold");
      policy.abandonAttempt(alice);
    }
    assertEquals(0, policy.trackedCombinedKeyCount(), "nothing is left behind");
  }

  @Test
  @DisplayName("a reservation whose report never comes lapses after the reservation time")
  void forgottenReservationLapses() {
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptPolicy policy = policyAt(clock);
    LoginAttemptContext alice = ctx("alice", "10.0.0.1", T0);

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(alice));
    }
    LoginAttemptDecision.LockedOut saturated = assertInstanceOf(
        LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(alice),
        "five attempts in flight use up the threshold");
    assertEquals(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL, saturated.remaining());
    assertEquals(LoginAttemptDecision.allowed(), policy.peek(alice),
        "attempts in flight are not a lockout");

    clock.advance(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL);
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(alice),
        "the caller never reported - the slots must come back on their own");
  }

  @Test
  @DisplayName("peek reports a lockout without reserving an attempt")
  void peekDoesNotReserve() {
    InMemoryLoginAttemptPolicy policy = policyAt(Clock.fixed(T0, ZoneOffset.UTC));
    LoginAttemptContext alice = ctx("alice", "10.0.0.1", T0);
    for (int i = 0; i < 50; i++) {
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(alice));
    }
    assertEquals(0, policy.trackedCombinedKeyCount());
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(alice));
  }

  @Test
  @DisplayName("alice / ALICE / full-width spellings share one counter; exact() keeps them apart")
  void spellingsOfOneNameShareACounter() {
    InMemoryLoginAttemptPolicy policy = policyAt(Clock.fixed(T0, ZoneOffset.UTC));
    String[] spellings = {"alice", "ALICE", " Alice ", "\uFF21\uFF2C\uFF29\uFF23\uFF25"};
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx(spellings[i % spellings.length], "10.0.0.1", T0));
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", "10.0.0.1", T0)));

    InMemoryLoginAttemptPolicy exact = new InMemoryLoginAttemptPolicy(CONFIG,
        Clock.fixed(T0, ZoneOffset.UTC), new RecordingAudit(), CapacityBound.DEFAULT_MAX_ENTRIES,
        SubjectKeyCanonicalizer.exact());
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      exact.recordFailure(ctx("ALICE", "10.0.0.1", T0));
    }
    assertEquals(LoginAttemptDecision.allowed(), exact.beforeAttempt(ctx("alice", "10.0.0.1", T0)),
        "with exact() the two spellings are two accounts and two counters");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        exact.beforeAttempt(ctx("ALICE", "10.0.0.1", T0)));
  }

  @Test
  @DisplayName("a separator inside a user name cannot make two (user, client) pairs collide")
  void combinedKeyIsNotAJoinedString() {
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(
        new LoginAttemptConfiguration(2, Duration.ofMinutes(5), Duration.ofMinutes(1),
            Duration.ofMinutes(10)),
        Clock.fixed(T0, ZoneOffset.UTC), new RecordingAudit());
    policy.recordFailure(ctx("a|b", "c", T0));
    policy.recordFailure(ctx("a", "b|c", T0));
    assertEquals(2, policy.trackedCombinedKeyCount());
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("a|b", "c", T0)));
  }
}
