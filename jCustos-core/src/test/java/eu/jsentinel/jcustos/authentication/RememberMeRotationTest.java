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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.CredentialTestKit.MutableClock;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-128 (CWE-613, CWE-294): a remember-me token is exchanged on every
 * use, and a token that was already exchanged revokes the subject's tokens
 * when it is presented again.
 */
@DisplayName("JS-SEC-128 — remember-me tokens rotate on use; a replayed token revokes the subject's tokens")
class RememberMeRotationTest {

  private static final SubjectId ALICE = SubjectId.of("alice");
  private static final SubjectId BOB = SubjectId.of("bob");
  private static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");
  private static final Duration TTL = Duration.ofDays(14);

  private final MutableClock clock = new MutableClock(T0);
  private final AtomicLong counter = new AtomicLong();

  private StoreBackedRememberMeService service(RememberMeTokenStore store) {
    return new StoreBackedRememberMeService(store, new Sha256TokenHasher(),
        TenantId.DEFAULT, clock, () -> "remember-me-" + counter.incrementAndGet());
  }

  /**
   * A store as a third party would have written it before 00.84.00: it
   * implements the original operations only and inherits the new defaults.
   */
  private static final class StoreWithoutRotationTrail implements RememberMeTokenStore {
    final InMemoryRememberMeTokenStore real = new InMemoryRememberMeTokenStore();

    @Override
    public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
      return real.findByHash(tokenHash);
    }

    @Override
    public void save(RememberMeTokenRecord record) {
      real.save(record);
    }

    @Override
    public boolean deleteByHash(String tokenHash) {
      return real.deleteByHash(tokenHash);
    }

    @Override
    public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
      return real.deleteBySubject(tenant, subjectId);
    }

    @Override
    public int purgeExpired(Instant now) {
      return real.purgeExpired(now);
    }
  }

  @Test
  @DisplayName("rotate returns a successor for the same subject with the same expiry; the old token is dead")
  void rotateExchangesTheToken() {
    StoreBackedRememberMeService service = service(new InMemoryRememberMeTokenStore());
    StoreBackedRememberMeService.IssuedToken first = service.issue(ALICE, TTL);

    clock.advance(Duration.ofDays(3));
    StoreBackedRememberMeService.IssuedToken second =
        service.rotate(first.plainToken()).orElseThrow();

    assertNotEquals(first.plainToken(), second.plainToken());
    assertEquals(ALICE, second.record().subjectId());
    assertEquals(first.record().expiresAt(), second.record().expiresAt(),
        "rotation must not extend the lifetime of a remembered login");
    assertTrue(service.validate(second.plainToken()).isPresent());
    assertTrue(service.rotate(first.plainToken()).isEmpty(), "a token works exactly once");
  }

  @Test
  @DisplayName("a rotated token presented again revokes every remember-me token of the subject — the thief's successor included")
  void replayRevokesTheSubjectsTokens() {
    StoreBackedRememberMeService service = service(new InMemoryRememberMeTokenStore());
    String stolen = service.issue(ALICE, TTL).plainToken();
    String otherDevice = service.issue(ALICE, TTL).plainToken();
    String bobs = service.issue(BOB, TTL).plainToken();

    // The thief redeems the copied cookie first ...
    String thiefs = service.rotate(stolen).orElseThrow().plainToken();
    // ... and the owner comes back with the original an hour later.
    clock.advance(Duration.ofHours(1));
    assertTrue(service.rotate(stolen).isEmpty());

    assertTrue(service.validate(thiefs).isEmpty(), "the successor obtained by the thief must die");
    assertTrue(service.validate(otherDevice).isEmpty());
    assertTrue(service.validate(bobs).isPresent(), "another subject is not affected");
  }

  @Test
  @DisplayName("validate recognises a replayed token as well")
  void validateDetectsReplay() {
    StoreBackedRememberMeService service = service(new InMemoryRememberMeTokenStore());
    String original = service.issue(ALICE, TTL).plainToken();
    String successor = service.rotate(original).orElseThrow().plainToken();

    clock.advance(Duration.ofMinutes(10));
    assertTrue(service.validate(original).isEmpty());

    assertTrue(service.validate(successor).isEmpty());
  }

  @Test
  @DisplayName("a second presentation within the tolerance is refused without revoking anything")
  void parallelRequestOfTheSameClientIsTolerated() {
    StoreBackedRememberMeService service = service(new InMemoryRememberMeTokenStore());
    String original = service.issue(ALICE, TTL).plainToken();
    String successor = service.rotate(original).orElseThrow().plainToken();

    clock.advance(StoreBackedRememberMeService.ROTATION_RACE_TOLERANCE.minusMillis(1));
    assertTrue(service.rotate(original).isEmpty(), "the consumed token is refused in any case");
    assertTrue(service.validate(successor).isPresent(),
        "a browser's parallel request must not sign the user out everywhere");

    clock.advance(Duration.ofMillis(1));
    assertTrue(service.rotate(original).isEmpty());
    assertTrue(service.validate(successor).isEmpty(), "outside the tolerance it is a replay");
  }

  @Test
  @DisplayName("of many concurrent rotations of one token exactly one obtains a successor")
  void concurrentRotationYieldsOneSuccessor() throws Exception {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    StoreBackedRememberMeService service = service(store);
    String original = service.issue(ALICE, TTL).plainToken();
    int threads = 16;
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      List<Future<Optional<StoreBackedRememberMeService.IssuedToken>>> results = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        Callable<Optional<StoreBackedRememberMeService.IssuedToken>> task = () -> {
          start.await();
          return service.rotate(original);
        };
        results.add(pool.submit(task));
      }
      start.countDown();
      List<StoreBackedRememberMeService.IssuedToken> successors = new ArrayList<>();
      for (Future<Optional<StoreBackedRememberMeService.IssuedToken>> result : results) {
        result.get(10, TimeUnit.SECONDS).ifPresent(successors::add);
      }
      assertEquals(1, successors.size());
      assertTrue(service.validate(successors.getFirst().plainToken()).isPresent(),
          "the losers ran inside the tolerance and must not have revoked the winner");
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("expired, unknown, blank and foreign-tenant tokens are refused and yield no successor")
  void rotateNegativeCases() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    StoreBackedRememberMeService service = service(store);
    String token = service.issue(ALICE, Duration.ofMinutes(5)).plainToken();
    StoreBackedRememberMeService otherTenant = new StoreBackedRememberMeService(
        store, new Sha256TokenHasher(), new TenantId("acme"), clock, () -> "x-" + counter.incrementAndGet());

    assertTrue(service.rotate(null).isEmpty());
    assertTrue(service.rotate(" ").isEmpty());
    assertTrue(service.rotate("never-issued").isEmpty());
    assertTrue(otherTenant.rotate(token).isEmpty());
    assertTrue(service.validate(token).isPresent(), "a refused rotation spends nothing");

    clock.advance(Duration.ofMinutes(5));
    assertTrue(service.rotate(token).isEmpty());
  }

  @Test
  @DisplayName("revokeAll and purgeExpired also drop the trail of rotated tokens")
  void trailGoesWithTheTokens() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    StoreBackedRememberMeService service = service(store);
    Sha256TokenHasher hasher = new Sha256TokenHasher();
    String first = service.issue(ALICE, Duration.ofMinutes(5)).plainToken();
    service.rotate(first).orElseThrow();
    String firstHash = hasher.hash(first.toCharArray());
    assertEquals(T0, store.findRotated(firstHash).orElseThrow().rotatedAt());

    service.revokeAll(ALICE);
    assertTrue(store.findRotated(firstHash).isEmpty());

    String second = service.issue(BOB, Duration.ofMinutes(5)).plainToken();
    service.rotate(second).orElseThrow();
    clock.advance(Duration.ofMinutes(5));
    service.purgeExpired();
    assertTrue(store.findRotated(hasher.hash(second.toCharArray())).isEmpty());
  }

  @Test
  @DisplayName("a store that keeps the default methods still rotates; it cannot recognise a replay")
  void storeWithoutTrailStillRotates() {
    StoreBackedRememberMeService service = service(new StoreWithoutRotationTrail());
    String original = service.issue(ALICE, TTL).plainToken();

    String successor = service.rotate(original).orElseThrow().plainToken();
    clock.advance(Duration.ofHours(1));

    assertTrue(service.rotate(original).isEmpty(), "the consumed token is dead in any store");
    assertTrue(service.validate(successor).isPresent(),
        "without a trail the replay goes unnoticed — the documented limit of the default");
    assertFalse(service.rotate(successor).isEmpty());
  }
}
