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

import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Contract every {@link RememberMeTokenStore} implementation must
 * satisfy.
 *
 * <p>The tests whose name starts with {@code JS-SEC-128} cover the rotation
 * trail added in 00.84.00 — {@link RememberMeTokenStore#markRotated} and
 * {@link RememberMeTokenStore#findRotated}. It is what lets
 * {@code StoreBackedRememberMeService.rotate} recognise a token that was
 * already exchanged and is presented again. A store that implements the trail
 * passes; a store that still inherits the default methods does not, because
 * the defaults keep no trail. Such a store overrides
 * {@link #implementsRotationTrail()} to return {@code false} until it has
 * caught up, which skips these tests and documents the gap in its own test
 * class — with it, rotation works and a replayed token is merely unknown.</p>
 */
@DisplayName("RememberMeTokenStore — contract")
public interface RememberMeTokenStoreContract {

  /**
   * @return a fresh, empty {@code RememberMeTokenStore}
   */
  RememberMeTokenStore newStore();

  /**
   * @return {@code true} (the default) when the store under test keeps the
   *     trail of rotated tokens (JS-SEC-128); {@code false} skips its tests
   */
  default boolean implementsRotationTrail() {
    return true;
  }

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(3600);
  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");

  /**
   * Builds a sample token record.
   *
   * @param hash    token hash
   * @param tenant  tenant scope
   * @param subject subject
   * @return new record
   */
  default RememberMeTokenRecord token(String hash, TenantId tenant, SubjectId subject) {
    return new RememberMeTokenRecord(hash, tenant, subject, T0, EXPIRY);
  }

  @Test
  @DisplayName("save persists; findByHash retrieves; deleteByHash drops")
  default void crudByHash() {
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord r = token("h1", TenantId.DEFAULT, ALICE);
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
    assertTrue(store.deleteByHash("h1"));
    assertTrue(store.findByHash("h1").isEmpty());
  }

  @Test
  @DisplayName("save upserts on the hash key")
  default void saveUpserts() {
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord first = token("h1", TenantId.DEFAULT, ALICE);
    store.save(first);
    RememberMeTokenRecord later = new RememberMeTokenRecord(
        "h1", TenantId.DEFAULT, ALICE, T0, EXPIRY.plusSeconds(60));
    store.save(later);
    assertEquals(Optional.of(later), store.findByHash("h1"));
  }

  @Test
  @DisplayName("findByHash / deleteByHash reject blank")
  default void blankHashRejected() {
    RememberMeTokenStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(null));
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class, () -> store.deleteByHash(""));
  }

  @Test
  @DisplayName("save rejects null; deleteByHash returns false for unknown")
  default void saveDeleteRejections() {
    RememberMeTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertFalse(store.deleteByHash("ghost"));
  }

  @Test
  @DisplayName("deleteBySubject removes every (tenant, subject) token")
  default void deleteBySubjectDrops() {
    RememberMeTokenStore store = newStore();
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h2", TenantId.DEFAULT, ALICE));
    store.save(token("h3", TenantId.DEFAULT, BOB));

    assertEquals(2, store.deleteBySubject(TenantId.DEFAULT, ALICE));
    assertTrue(store.findByHash("h1").isEmpty());
    assertTrue(store.findByHash("h3").isPresent());
  }

  @Test
  @DisplayName("deleteBySubject is tenant-scoped")
  default void deleteBySubjectTenantScoped() {
    RememberMeTokenStore store = newStore();
    TenantId acme = new TenantId("acme");
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h2", acme, ALICE));

    assertEquals(1, store.deleteBySubject(acme, ALICE));
    assertTrue(store.findByHash("h1").isPresent());
  }

  @Test
  @DisplayName("deleteBySubject rejects nulls / on unknown returns 0")
  default void deleteBySubjectRejections() {
    RememberMeTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.deleteBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null));
    assertEquals(0, store.deleteBySubject(TenantId.DEFAULT, new SubjectId("ghost")));
  }

  @Test
  @DisplayName("purgeExpired drops every token whose expiresAt is at or before now")
  default void purgeExpiredAtOrBefore() {
    RememberMeTokenStore store = newStore();
    Instant early = T0.plusSeconds(60);
    Instant late = T0.plusSeconds(3600);
    store.save(new RememberMeTokenRecord("early", TenantId.DEFAULT, ALICE, T0, early));
    store.save(new RememberMeTokenRecord("late", TenantId.DEFAULT, ALICE, T0, late));

    assertEquals(1, store.purgeExpired(early));
    assertTrue(store.findByHash("early").isEmpty());
    assertTrue(store.findByHash("late").isPresent());
  }

  @Test
  @DisplayName("purgeExpired rejects null / on empty returns 0")
  default void purgeExpiredRejections() {
    RememberMeTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.purgeExpired(null));
    assertEquals(0, store.purgeExpired(EXPIRY));
  }

  // ── JS-SEC-128: rotation and its trail ─────────────────────────────

  @Test
  @DisplayName("JS-SEC-128: markRotated retires the live record and leaves a trail with the record and the instant")
  default void markRotatedLeavesATrail() {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord live = token("h1", TenantId.DEFAULT, ALICE);
    store.save(live);
    assertTrue(store.findRotated("h1").isEmpty(), "a live token has no trail");

    Instant rotatedAt = T0.plusSeconds(120);
    assertTrue(store.markRotated("h1", rotatedAt));

    assertTrue(store.findByHash("h1").isEmpty(), "the consumed token is no longer live");
    RememberMeTokenStore.RotatedToken trail = store.findRotated("h1").orElseThrow();
    assertEquals(live, trail.record());
    assertEquals(rotatedAt, trail.rotatedAt());
  }

  @Test
  @DisplayName("JS-SEC-128: a token can be rotated once - the second claim fails and the trail keeps the first instant")
  default void markRotatedClaimsOnce() {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    assertTrue(store.markRotated("h1", T0.plusSeconds(60)));
    assertFalse(store.markRotated("h1", T0.plusSeconds(90)));
    assertEquals(T0.plusSeconds(60), store.findRotated("h1").orElseThrow().rotatedAt());
  }

  @Test
  @DisplayName("JS-SEC-128: a hash that never was a token, or was merely deleted, has no trail")
  default void onlyRotationLeavesATrail() {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    assertFalse(store.markRotated("ghost", T0.plusSeconds(60)));
    assertTrue(store.findRotated("ghost").isEmpty());

    store.save(token("revoked", TenantId.DEFAULT, ALICE));
    assertTrue(store.deleteByHash("revoked"));
    assertTrue(store.findRotated("revoked").isEmpty(),
        "a revoked token presented again is unknown, not a replay");
    assertFalse(store.markRotated("revoked", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("JS-SEC-128: deleteBySubject takes the subject's trail with it and leaves other subjects' trails alone")
  default void deleteBySubjectDropsTheTrail() {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    TenantId acme = new TenantId("acme");
    store.save(token("alice-old", TenantId.DEFAULT, ALICE));
    store.save(token("alice-acme-old", acme, ALICE));
    store.save(token("bob-old", TenantId.DEFAULT, BOB));
    assertTrue(store.markRotated("alice-old", T0.plusSeconds(60)));
    assertTrue(store.markRotated("alice-acme-old", T0.plusSeconds(60)));
    assertTrue(store.markRotated("bob-old", T0.plusSeconds(60)));
    store.save(token("alice-new", TenantId.DEFAULT, ALICE));

    assertEquals(1, store.deleteBySubject(TenantId.DEFAULT, ALICE),
        "the count is the number of live tokens removed");
    assertTrue(store.findRotated("alice-old").isEmpty());
    assertTrue(store.findRotated("alice-acme-old").isPresent(), "another tenant");
    assertTrue(store.findRotated("bob-old").isPresent(), "another subject");
  }

  @Test
  @DisplayName("JS-SEC-128: purgeExpired drops the trail once the consumed token would have expired")
  default void purgeExpiredDropsTheTrail() {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    Instant early = T0.plusSeconds(600);
    store.save(new RememberMeTokenRecord("short", TenantId.DEFAULT, ALICE, T0, early));
    store.save(token("long", TenantId.DEFAULT, ALICE));
    assertTrue(store.markRotated("short", T0.plusSeconds(60)));
    assertTrue(store.markRotated("long", T0.plusSeconds(60)));

    assertEquals(0, store.purgeExpired(early.minusSeconds(1)));
    assertTrue(store.findRotated("short").isPresent(), "not expired yet");

    assertEquals(0, store.purgeExpired(early), "trails are not counted as purged tokens");
    assertTrue(store.findRotated("short").isEmpty());
    assertTrue(store.findRotated("long").isPresent());
  }

  @Test
  @DisplayName("JS-SEC-128: of 32 parallel presentations of one token exactly one wins the rotation")
  default void markRotatedIsAtomicUnderConcurrency() throws Exception {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    int threads = 32;
    int rounds = 10;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      for (int round = 0; round < rounds; round++) {
        String hash = "token-" + round;
        store.save(token(hash, TenantId.DEFAULT, ALICE));
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> outcomes = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
          Callable<Boolean> presentation = () -> {
            ready.countDown();
            start.await();
            return store.markRotated(hash, T0.plusSeconds(60));
          };
          outcomes.add(pool.submit(presentation));
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS), "callers did not start");
        start.countDown();
        int winners = 0;
        for (Future<Boolean> outcome : outcomes) {
          if (outcome.get(30, TimeUnit.SECONDS)) {
            winners++;
          }
        }
        assertEquals(1, winners, "round " + round + ": exactly one presentation may obtain a successor");
        assertTrue(store.findByHash(hash).isEmpty());
        assertTrue(store.findRotated(hash).isPresent());
      }
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("JS-SEC-128: markRotated / findRotated reject invalid arguments")
  default void rotationRejectsInvalidArguments() {
    assumeTrue(implementsRotationTrail());
    RememberMeTokenStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.markRotated("", T0));
    assertThrows(IllegalArgumentException.class, () -> store.markRotated(null, T0));
    assertThrows(NullPointerException.class, () -> store.markRotated("h1", null));
    assertThrows(IllegalArgumentException.class, () -> store.findRotated(""));
    assertThrows(IllegalArgumentException.class, () -> store.findRotated(null));
  }
}
