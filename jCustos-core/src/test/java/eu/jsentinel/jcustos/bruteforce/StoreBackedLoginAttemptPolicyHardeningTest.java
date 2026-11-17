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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.MutableClock;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-122 (CWE-307, CWE-770) and JS-SEC-123 (CWE-367, CWE-307, CWE-178) for the store-backed
 * pair: {@link StoreBackedLoginAttemptPolicy} on a real {@link InMemoryLoginAttemptStore}.
 */
@DisplayName("StoreBackedLoginAttemptPolicy + InMemoryLoginAttemptStore - hardening")
class StoreBackedLoginAttemptPolicyHardeningTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  /** 5 failures / 15 min window / 15 min lockout. */
  private static final LoginAttemptConfiguration CONFIG = LoginAttemptConfiguration.defaults();

  private static LoginAttemptContext ctx(String user, String ip, Instant at) {
    return new LoginAttemptContext(user, ip, null, at);
  }

  private static StoreBackedLoginAttemptPolicy policy(LoginAttemptStore store, Clock clock) {
    return new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, clock);
  }

  private static LoginAttemptDecision failedLogin(LoginAttemptPolicy policy, String user,
                                                  Instant at) {
    LoginAttemptDecision gate = policy.beforeAttempt(ctx(user, "10.0.0.1", at));
    if (gate instanceof LoginAttemptDecision.Allowed) {
      policy.recordFailure(ctx(user, "10.0.0.1", at));
    }
    return gate;
  }

  // ── JS-SEC-122 ─────────────────────────────────────────────────────

  @Test
  @DisplayName("S01: an active lockout survives a spray of more than maxEntries new keys until it really expires")
  void lockoutSurvivesKeySprayUntilExpiry() {
    int cap = 20;
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore(cap);
    StoreBackedLoginAttemptPolicy policy = policy(store, clock);

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      failedLogin(policy, "victim", clock.instant());
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("victim", "10.0.0.1", clock.instant())));

    for (int i = 0; i < cap * 3; i++) {
      clock.advance(Duration.ofMillis(10));
      failedLogin(policy, "spray-" + i, clock.instant());
      assertTrue(store.trackedKeyCount() <= cap, "store over the bound: " + store.trackedKeyCount());
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("victim", "10.0.0.1", clock.instant())),
          "the victim's lockout was pushed out after " + (i + 1) + " sprayed keys");
    }

    // the lockout ends 15 minutes after the fifth failure - not earlier, not later
    clock.advance(Duration.ofMinutes(15).minusMillis(10L * cap * 3).minusMillis(1));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("victim", "10.0.0.1", clock.instant())));
    clock.advance(Duration.ofMillis(1));
    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("victim", "10.0.0.1", clock.instant())));
  }

  @Test
  @DisplayName("with only locked keys left, a further key is refused and the store does not grow")
  void onlyLockedKeysLeft_newKeyIsRefused() {
    int cap = 2;
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore(cap);
    StoreBackedLoginAttemptPolicy policy = policy(store, clock);

    for (int account = 0; account < 20; account++) {
      for (int i = 0; i < CONFIG.failureThreshold(); i++) {
        failedLogin(policy, "account-" + account, clock.instant());
        assertTrue(store.trackedKeyCount() <= cap, "store grew to " + store.trackedKeyCount());
      }
    }

    LoginAttemptDecision.LockedOut refusal = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("someone-new", "10.0.0.1", clock.instant())));
    assertEquals(Duration.ofMinutes(15), refusal.remaining(), "until the first live lockout ends");
    assertEquals(0, refusal.failedAttempts());
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("account-0", "10.0.0.1", clock.instant())));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("account-1", "10.0.0.1", clock.instant())));

    clock.advance(Duration.ofMinutes(15));
    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("someone-new", "10.0.0.1", clock.instant())));
    assertTrue(store.trackedKeyCount() <= cap);
  }

  @Test
  @DisplayName("a counter is dropped once no failure has been recorded for a full window")
  void expiredCountersAreRemoved() {
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore(100);
    StoreBackedLoginAttemptPolicy policy = policy(store, clock);

    for (int i = 0; i < 10; i++) {
      failedLogin(policy, "one-shot-" + i, clock.instant());
    }
    // JS-SEC-166: every failure is counted on the tuple and on the account key
    assertEquals(20, store.trackedKeyCount());

    clock.advance(Duration.ofMinutes(15));
    policy.beforeAttempt(ctx("someone-else", "10.0.0.1", clock.instant()));
    policy.abandonAttempt(ctx("someone-else", "10.0.0.1", clock.instant()));

    assertEquals(0, store.trackedKeyCount());
  }

  @Test
  @DisplayName("ER55 acceptance: five failures at T0, one at T0+16 min - the key is allowed again")
  void counterDoesNotOutliveTheWindow() {
    MutableClock clock = new MutableClock(T0);
    StoreBackedLoginAttemptPolicy policy = policy(new InMemoryLoginAttemptStore(), clock);

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      failedLogin(policy, "alice", clock.instant());
    }
    clock.advance(Duration.ofMinutes(16));
    assertEquals(LoginAttemptDecision.allowed(), failedLogin(policy, "alice", clock.instant()));

    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("alice", "10.0.0.1", clock.instant())),
        "one failure after the window must not lock the key again");
  }

  // ── JS-SEC-123 ─────────────────────────────────────────────────────

  @Test
  @DisplayName("50 parallel guesses at threshold 5: at most 5 are evaluated")
  void parallelGuessesCannotExceedTheThreshold() throws InterruptedException {
    StoreBackedLoginAttemptPolicy policy =
        policy(new InMemoryLoginAttemptStore(), Clock.fixed(T0, ZoneOffset.UTC));
    int threads = 50;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch go = new CountDownLatch(1);
    CountDownLatch gatePassed = new CountDownLatch(threads);
    CountDownLatch done = new CountDownLatch(threads);
    AtomicInteger allowed = new AtomicInteger();

    for (int i = 0; i < threads; i++) {
      Thread thread = new Thread(() -> {
        ready.countDown();
        try {
          go.await();
          LoginAttemptContext attempt = ctx("victim", "10.0.0.1", T0);
          LoginAttemptDecision decision = policy.beforeAttempt(attempt);
          gatePassed.countDown();
          if (decision instanceof LoginAttemptDecision.Allowed) {
            allowed.incrementAndGet();
            gatePassed.await(5, TimeUnit.SECONDS);
            policy.recordFailure(attempt);
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

    assertEquals(CONFIG.failureThreshold(), allowed.get(),
        "exactly the threshold may be evaluated, not one per server thread");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("victim", "10.0.0.1", T0)));
  }

  @Test
  @DisplayName("a success reported after the lockout set in does not lift it and is answered with LockedOut")
  void lateSuccessDoesNotLiftTheLockout() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy = policy(store, Clock.fixed(T0, ZoneOffset.UTC));
    LoginAttemptContext attempt = ctx("victim", "10.0.0.1", T0);

    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      policy.recordFailure(attempt);   // reports without a gate: a lost reservation
    }

    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.confirmSuccess(attempt),
        "the adapter must be told to deny the login");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(attempt));
    policy.recordSuccess(attempt);
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(attempt));
    assertEquals(CONFIG.failureThreshold(),
        store.failureCount(new LoginAttemptKey(TenantId.DEFAULT, "victim", "10.0.0.1")));
  }

  @Test
  @DisplayName("abandoned and forgotten reservations give their slots back")
  void reservationsAreReleased() {
    MutableClock clock = new MutableClock(T0);
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy = policy(store, clock);
    LoginAttemptContext attempt = ctx("alice", "10.0.0.1", T0);

    for (int round = 0; round < 20; round++) {
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
      policy.abandonAttempt(attempt);
    }
    assertEquals(0, store.trackedKeyCount());

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
    }
    LoginAttemptDecision.LockedOut saturated = assertInstanceOf(
        LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(attempt));
    assertEquals(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL, saturated.remaining());
    assertEquals(LoginAttemptDecision.allowed(), policy.peek(attempt));

    clock.advance(InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL);
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
  }

  @Test
  @DisplayName("alice / ALICE / full-width spellings share one counter; exact() keeps them apart")
  void spellingsOfOneNameShareACounter() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy = policy(store, Clock.fixed(T0, ZoneOffset.UTC));
    String[] spellings = {"alice", "ALICE", " Alice ", "\uFF21\uFF2C\uFF29\uFF23\uFF25"};
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx(spellings[i % spellings.length], "10.0.0.1", T0));
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", "10.0.0.1", T0)));

    StoreBackedLoginAttemptPolicy exact = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), CONFIG, TenantId.DEFAULT,
        Clock.fixed(T0, ZoneOffset.UTC), SubjectKeyCanonicalizer.exact());
    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      exact.recordFailure(ctx("ALICE", "10.0.0.1", T0));
    }
    assertEquals(LoginAttemptDecision.allowed(), exact.beforeAttempt(ctx("alice", "10.0.0.1", T0)));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        exact.beforeAttempt(ctx("ALICE", "10.0.0.1", T0)));
  }

  // ── stores that only inherit the SPI defaults ──────────────────────

  @Test
  @DisplayName("a store without atomic operations keeps working through the SPI defaults")
  void legacyStoreKeepsWorking() {
    CounterOnlyStore store = new CounterOnlyStore();
    MutableClock clock = new MutableClock(T0);
    StoreBackedLoginAttemptPolicy policy = policy(store, clock);
    LoginAttemptContext attempt = ctx("alice", "10.0.0.1", T0);

    for (int i = 0; i < CONFIG.failureThreshold(); i++) {
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
      policy.recordFailure(attempt);
    }
    LoginAttemptDecision.LockedOut locked = assertInstanceOf(
        LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(attempt));
    assertEquals(Duration.ofMinutes(15), locked.remaining());
    assertEquals(CONFIG.failureThreshold(), locked.failedAttempts());

    // JS-SEC-123 holds even for the defaults: a success does not lift the live lockout
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.confirmSuccess(attempt));
    assertEquals(CONFIG.failureThreshold(), store.failureCount(
        new LoginAttemptKey(TenantId.DEFAULT, "alice", "10.0.0.1")));
    policy.abandonAttempt(attempt);

    clock.advance(Duration.ofMinutes(15));
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
    assertEquals(LoginAttemptDecision.allowed(), policy.confirmSuccess(attempt));
    assertEquals(0, store.failureCount(new LoginAttemptKey(TenantId.DEFAULT, "alice", "10.0.0.1")));
  }

  /** A third-party store as it could exist today: the four counter methods and nothing else. */
  private static final class CounterOnlyStore implements LoginAttemptStore {
    private record Entry(int count, Instant last) {
    }

    private final ConcurrentHashMap<LoginAttemptKey, Entry> entries = new ConcurrentHashMap<>();

    @Override
    public void recordFailure(LoginAttemptKey key, Instant at) {
      entries.merge(key, new Entry(1, at), (old, fresh) -> new Entry(old.count() + 1, at));
    }

    @Override
    public int failureCount(LoginAttemptKey key) {
      Entry entry = entries.get(key);
      return entry == null ? 0 : entry.count();
    }

    @Override
    public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
      return Optional.ofNullable(entries.get(key)).map(Entry::last);
    }

    @Override
    public void reset(LoginAttemptKey key) {
      entries.remove(key);
    }
  }
}
