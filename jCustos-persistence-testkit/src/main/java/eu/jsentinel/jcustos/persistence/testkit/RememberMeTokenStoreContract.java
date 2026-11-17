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
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
 *
 * <p>The tests whose name starts with {@code JS-SEC-129} cover the atomic
 * operations added in 00.84.00 — {@link RememberMeTokenStore#rotate},
 * {@link RememberMeTokenStore#saveUnlessInvalidated} and the marking
 * {@link RememberMeTokenStore#deleteBySubject(TenantId, SubjectId, Instant)}.
 * A store that inherits the defaults overrides
 * {@link #implementsAtomicRotation()} to return {@code false}.</p>
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

  /**
   * @return {@code true} (the default) when the store under test overrides
   *     the atomic operations of JS-SEC-129; {@code false} skips their tests
   * @since 00.84.00
   */
  default boolean implementsAtomicRotation() {
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
    assertThrows(IllegalArgumentException.class, () -> assertNotNull(store.findRotated("")));
    assertThrows(IllegalArgumentException.class, () -> assertNotNull(store.findRotated(null)));
  }

  // ── JS-SEC-129: atomic rotation and the "invalid before" mark ────────

  @Test
  @DisplayName("JS-SEC-129: rotate retires the old token, leaves its trail and stores the successor")
  default void rotateIsClaimTrailAndSuccessor() {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord old = token("old", TenantId.DEFAULT, ALICE);
    store.save(old);
    Instant now = T0.plusSeconds(60);
    RememberMeTokenRecord successor =
        new RememberMeTokenRecord("next", TenantId.DEFAULT, ALICE, now, EXPIRY);

    assertTrue(store.rotate("old", successor, now));

    assertTrue(store.findByHash("old").isEmpty());
    assertEquals(Optional.of(successor), store.findByHash("next"));
    RememberMeTokenStore.RotatedToken trail = store.findRotated("old").orElseThrow();
    assertEquals(old, trail.record());
    assertEquals(now, trail.rotatedAt());

    RememberMeTokenRecord second =
        new RememberMeTokenRecord("next-2", TenantId.DEFAULT, ALICE, now, EXPIRY);
    assertFalse(store.rotate("old", second, now), "a token is rotated once");
    assertTrue(store.findByHash("next-2").isEmpty(), "nothing is stored for the loser");
  }

  @Test
  @DisplayName("JS-SEC-129: rotate refuses an unknown or expired token and changes nothing")
  default void rotateRefusesDeadTokens() {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    Instant expiry = T0.plusSeconds(600);
    store.save(new RememberMeTokenRecord("short", TenantId.DEFAULT, ALICE, T0, expiry));
    RememberMeTokenRecord successor =
        new RememberMeTokenRecord("next", TenantId.DEFAULT, ALICE, expiry, EXPIRY.plusSeconds(1));

    assertFalse(store.rotate("ghost", successor, expiry));
    assertFalse(store.rotate("short", successor, expiry));
    assertTrue(store.findByHash("next").isEmpty());
    assertTrue(store.findRotated("short").isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-129: deleteBySubject with an instant leaves a mark that refuses older records")
  default void invalidBeforeMarkRefusesOlderRecords() {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h-bob", TenantId.DEFAULT, BOB));
    Instant revokedAt = T0.plusSeconds(100);

    assertEquals(1, store.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt));

    RememberMeTokenRecord older = new RememberMeTokenRecord("older", TenantId.DEFAULT, ALICE,
        revokedAt.minusMillis(1), EXPIRY);
    assertFalse(store.saveUnlessInvalidated(older),
        "a record created before the revocation must not be stored after it");
    assertTrue(store.findByHash("older").isEmpty());

    RememberMeTokenRecord atMark =
        new RememberMeTokenRecord("at-mark", TenantId.DEFAULT, ALICE, revokedAt, EXPIRY);
    assertTrue(store.saveUnlessInvalidated(atMark), "a record created at the mark is new");

    assertTrue(store.saveUnlessInvalidated(token("bob-2", TenantId.DEFAULT, BOB)));
    assertTrue(store.saveUnlessInvalidated(token("acme-alice", new TenantId("acme"), ALICE)));
    assertTrue(store.findByHash("h-bob").isPresent());
  }

  @Test
  @DisplayName("JS-SEC-129: rotate refuses a successor older than the mark without spending the old token")
  default void rotateChecksTheMark() {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    Instant revokedAt = T0.plusSeconds(100);
    store.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt);
    store.save(new RememberMeTokenRecord("current", TenantId.DEFAULT, ALICE, revokedAt, EXPIRY));

    RememberMeTokenRecord stale = new RememberMeTokenRecord("stale", TenantId.DEFAULT, ALICE,
        revokedAt.minusSeconds(1), EXPIRY);
    assertFalse(store.rotate("current", stale, revokedAt.plusSeconds(1)));
    assertTrue(store.findByHash("stale").isEmpty());
    assertTrue(store.findByHash("current").isPresent());

    RememberMeTokenRecord fresh = new RememberMeTokenRecord("fresh", TenantId.DEFAULT, ALICE,
        revokedAt.plusSeconds(1), EXPIRY);
    assertTrue(store.rotate("current", fresh, revokedAt.plusSeconds(1)));
  }

  @Test
  @DisplayName("JS-SEC-129: an earlier instant does not move the mark back")
  default void markOnlyMovesForward() {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    store.deleteBySubject(TenantId.DEFAULT, ALICE, T0.plusSeconds(100));
    store.deleteBySubject(TenantId.DEFAULT, ALICE, T0.plusSeconds(10));

    assertFalse(store.saveUnlessInvalidated(new RememberMeTokenRecord("between",
        TenantId.DEFAULT, ALICE, T0.plusSeconds(50), EXPIRY)));
  }

  @Test
  @DisplayName("JS-SEC-129: a revocation racing a rotation never leaves a live token of the subject")
  default void revocationAndRotationDoNotInterleave() throws Exception {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      for (int round = 0; round < 200; round++) {
        String old = "old-" + round;
        String next = "next-" + round;
        Instant now = T0.plusSeconds(round);
        store.save(new RememberMeTokenRecord(old, TenantId.DEFAULT, ALICE, now, EXPIRY));
        RememberMeTokenRecord successor =
            new RememberMeTokenRecord(next, TenantId.DEFAULT, ALICE, now, EXPIRY);
        CountDownLatch start = new CountDownLatch(1);
        Future<Boolean> rotation = pool.submit(() -> {
          start.await();
          return store.rotate(old, successor, now);
        });
        Future<Integer> revocation = pool.submit(() -> {
          start.await();
          return store.deleteBySubject(TenantId.DEFAULT, ALICE, now);
        });
        start.countDown();
        rotation.get(30, TimeUnit.SECONDS);
        revocation.get(30, TimeUnit.SECONDS);
        assertTrue(store.findByHash(old).isEmpty(), "round " + round);
        assertTrue(store.findByHash(next).isEmpty(),
            "round " + round + ": the successor must not survive the revocation");
      }
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("JS-SEC-129: invalid arguments of the atomic operations are rejected")
  default void atomicOperationsRejectInvalidArguments() {
    assumeTrue(implementsAtomicRotation());
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord record = token("h1", TenantId.DEFAULT, ALICE);
    assertThrows(IllegalArgumentException.class, () -> store.rotate("", record, T0));
    assertThrows(IllegalArgumentException.class, () -> store.rotate("h1", record, T0),
        "the successor must not reuse the old hash");
    assertThrows(NullPointerException.class, () -> store.rotate("h0", null, T0));
    assertThrows(NullPointerException.class, () -> store.rotate("h0", record, null));
    assertThrows(NullPointerException.class, () -> store.saveUnlessInvalidated(null));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, ALICE, null));
  }
}
