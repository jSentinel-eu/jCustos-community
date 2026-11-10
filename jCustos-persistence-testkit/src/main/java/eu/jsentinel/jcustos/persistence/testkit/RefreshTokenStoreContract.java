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

import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
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
 * Contract every {@link RefreshTokenStore} implementation must
 * satisfy.
 *
 * <p>The tests whose name starts with {@code JS-SEC-129} cover the atomic
 * operations added in 00.84.00 — {@link RefreshTokenStore#rotate},
 * {@link RefreshTokenStore#saveUnlessInvalidated} and the marking
 * {@link RefreshTokenStore#deleteBySubject(TenantId, SubjectId, Instant)}. A
 * store that implements them passes; a store that still inherits the default
 * methods does not, because the defaults keep the races of the earlier
 * releases. Such a store overrides {@link #implementsAtomicRotation()} to
 * return {@code false} until it has caught up, which skips these tests and
 * documents the gap in its own test class.</p>
 */
@DisplayName("RefreshTokenStore — contract")
public interface RefreshTokenStoreContract {

  /**
   * @return a fresh, empty {@code RefreshTokenStore}
   */
  RefreshTokenStore newStore();

  /**
   * @return {@code true} (the default) when the store under test overrides
   *     the atomic operations of JS-SEC-129; {@code false} skips their tests
   */
  default boolean implementsAtomicRotation() {
    return true;
  }

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(3600);
  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");

  /**
   * Builds a sample fresh token record.
   *
   * @param hash    token hash
   * @param subject subject
   * @return new record
   */
  default RefreshTokenRecord token(String hash, SubjectId subject) {
    return new RefreshTokenRecord(
        hash, TenantId.DEFAULT, subject, T0, EXPIRY,
        Optional.empty(), Optional.empty());
  }

  @Test
  @DisplayName("save + findByHash round-trip")
  default void saveAndFind() {
    RefreshTokenStore store = newStore();
    RefreshTokenRecord r = token("h1", ALICE);
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
  }

  @Test
  @DisplayName("markReplaced links predecessor → successor; second call returns false")
  default void markReplacedLifecycle() {
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    assertTrue(store.markReplaced("h1", "h2", T0.plusSeconds(60)));
    assertEquals(Optional.of("h2"),
        store.findByHash("h1").orElseThrow().replacedByHash());
    assertFalse(store.markReplaced("h1", "h3", T0.plusSeconds(120)));
    assertFalse(store.markReplaced("ghost", "h-new", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("markRevoked flips a not-yet-revoked record; idempotent")
  default void markRevokedIdempotent() {
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    assertTrue(store.markRevoked("h1", T0.plusSeconds(60)));
    assertTrue(store.findByHash("h1").orElseThrow().isRevoked());
    assertFalse(store.markRevoked("h1", T0.plusSeconds(120)));
  }

  @Test
  @DisplayName("deleteBySubject drops every record of the subject")
  default void deleteBySubject() {
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    store.save(token("h2", ALICE));
    store.markReplaced("h2", "h3", T0.plusSeconds(60));
    store.save(token("h4", BOB));

    assertEquals(2, store.deleteBySubject(TenantId.DEFAULT, ALICE));
    assertTrue(store.findByHash("h4").isPresent());
  }

  @Test
  @DisplayName("purgeExpired drops every record at or before now")
  default void purgeExpired() {
    RefreshTokenStore store = newStore();
    RefreshTokenRecord shortLived = new RefreshTokenRecord(
        "h-short", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(60),
        Optional.empty(), Optional.empty());
    store.save(shortLived);
    store.save(token("h-long", ALICE));

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("h-long").isPresent());
  }

  @Test
  @DisplayName("JS-SEC-129: rotate claims the old record and stores the successor together")
  default void rotateClaimsAndStores() {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    RefreshTokenRecord successor = token("h2", ALICE);

    assertTrue(store.rotate("h1", successor, T0.plusSeconds(60)));

    assertEquals(Optional.of("h2"), store.findByHash("h1").orElseThrow().replacedByHash());
    assertEquals(Optional.of(successor), store.findByHash("h2"));
  }

  @Test
  @DisplayName("JS-SEC-129: rotate refuses a replaced, revoked, expired or unknown record and stores no successor")
  default void rotateRefusesInactiveRecord() {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    Instant now = T0.plusSeconds(60);

    store.save(token("replaced", ALICE));
    assertTrue(store.rotate("replaced", token("r-1", ALICE), now));
    assertFalse(store.rotate("replaced", token("r-2", ALICE), now), "already replaced");
    assertTrue(store.findByHash("r-2").isEmpty());
    assertEquals(Optional.of("r-1"),
        store.findByHash("replaced").orElseThrow().replacedByHash(),
        "a refused rotation must not overwrite the existing link");

    store.save(token("revoked", ALICE));
    assertTrue(store.markRevoked("revoked", T0.plusSeconds(30)));
    assertFalse(store.rotate("revoked", token("v-1", ALICE), now),
        "a revoked record must not be rotated (the lost logout of JS-SEC-129)");
    assertTrue(store.findByHash("v-1").isEmpty());
    assertFalse(store.findByHash("revoked").orElseThrow().isReplaced());

    store.save(new RefreshTokenRecord("expired", TenantId.DEFAULT, ALICE, T0,
        T0.plusSeconds(60), Optional.empty(), Optional.empty()));
    assertFalse(store.rotate("expired", token("e-1", ALICE), now), "expired at now");
    assertTrue(store.findByHash("e-1").isEmpty());

    assertFalse(store.rotate("ghost", token("g-1", ALICE), now));
    assertTrue(store.findByHash("g-1").isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-129: of concurrent rotations of one record exactly one wins, and only its successor exists")
  default void concurrentRotateHasOneWinner() throws Exception {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    int threads = 12;
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      List<Future<Boolean>> outcomes = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        String successorHash = "s-" + i;
        Callable<Boolean> task = () -> {
          start.await();
          return store.rotate("h1", token(successorHash, ALICE), T0.plusSeconds(60));
        };
        outcomes.add(pool.submit(task));
      }
      start.countDown();
      List<String> winners = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        if (outcomes.get(i).get(30, TimeUnit.SECONDS)) {
          winners.add("s-" + i);
        }
      }
      assertEquals(1, winners.size(), "exactly one rotation may claim the record");
      for (int i = 0; i < threads; i++) {
        assertEquals(winners.contains("s-" + i), store.findByHash("s-" + i).isPresent(),
            "only the winner's successor may be stored (s-" + i + ")");
      }
      assertEquals(Optional.of(winners.getFirst()),
          store.findByHash("h1").orElseThrow().replacedByHash());
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("JS-SEC-129: deleteBySubject with an instant leaves a mark that refuses older records")
  default void invalidBeforeMarkRefusesOlderRecords() {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    store.save(token("h-bob", BOB));
    Instant revokedAt = T0.plusSeconds(100);

    assertEquals(1, store.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt));

    RefreshTokenRecord older = new RefreshTokenRecord("older", TenantId.DEFAULT, ALICE,
        revokedAt.minusMillis(1), EXPIRY, Optional.empty(), Optional.empty());
    assertFalse(store.saveUnlessInvalidated(older),
        "a record created before the revocation must not be stored after it");
    assertTrue(store.findByHash("older").isEmpty());

    RefreshTokenRecord atMark = new RefreshTokenRecord("at-mark", TenantId.DEFAULT, ALICE,
        revokedAt, EXPIRY, Optional.empty(), Optional.empty());
    assertTrue(store.saveUnlessInvalidated(atMark), "a record created at the mark is new");
    assertTrue(store.findByHash("at-mark").isPresent());

    // Other subjects and other tenants carry no mark.
    assertTrue(store.saveUnlessInvalidated(token("bob-2", BOB)));
    assertTrue(store.saveUnlessInvalidated(new RefreshTokenRecord("acme-alice",
        new TenantId("acme"), ALICE, T0, EXPIRY, Optional.empty(), Optional.empty())));
    assertTrue(store.findByHash("h-bob").isPresent());
  }

  @Test
  @DisplayName("JS-SEC-129: rotate refuses a successor that is older than the subject's mark, without spending the old record")
  default void rotateChecksTheMark() {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    Instant revokedAt = T0.plusSeconds(100);
    store.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt);
    RefreshTokenRecord current = new RefreshTokenRecord("current", TenantId.DEFAULT, ALICE,
        revokedAt, EXPIRY, Optional.empty(), Optional.empty());
    assertTrue(store.saveUnlessInvalidated(current));

    RefreshTokenRecord stale = new RefreshTokenRecord("stale", TenantId.DEFAULT, ALICE,
        revokedAt.minusSeconds(1), EXPIRY, Optional.empty(), Optional.empty());
    assertFalse(store.rotate("current", stale, revokedAt.plusSeconds(1)));
    assertTrue(store.findByHash("stale").isEmpty());
    assertFalse(store.findByHash("current").orElseThrow().isReplaced());

    RefreshTokenRecord fresh = new RefreshTokenRecord("fresh", TenantId.DEFAULT, ALICE,
        revokedAt.plusSeconds(1), EXPIRY, Optional.empty(), Optional.empty());
    assertTrue(store.rotate("current", fresh, revokedAt.plusSeconds(1)));
  }

  @Test
  @DisplayName("JS-SEC-129: an earlier instant does not move the mark back")
  default void markOnlyMovesForward() {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    store.deleteBySubject(TenantId.DEFAULT, ALICE, T0.plusSeconds(100));
    store.deleteBySubject(TenantId.DEFAULT, ALICE, T0.plusSeconds(10));

    assertFalse(store.saveUnlessInvalidated(new RefreshTokenRecord("between",
        TenantId.DEFAULT, ALICE, T0.plusSeconds(50), EXPIRY,
        Optional.empty(), Optional.empty())));
  }

  @Test
  @DisplayName("JS-SEC-129: invalid arguments of the atomic operations are rejected")
  default void atomicOperationsRejectInvalidArguments() {
    assumeTrue(implementsAtomicRotation());
    RefreshTokenStore store = newStore();
    assertThrows(IllegalArgumentException.class,
        () -> store.rotate("", token("h2", ALICE), T0));
    assertThrows(NullPointerException.class, () -> store.rotate("h1", null, T0));
    assertThrows(NullPointerException.class,
        () -> store.rotate("h1", token("h2", ALICE), null));
    assertThrows(IllegalArgumentException.class,
        () -> store.rotate("h1", token("h1", ALICE), T0),
        "a successor must not reuse the hash it replaces");
    assertThrows(NullPointerException.class, () -> store.saveUnlessInvalidated(null));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, ALICE, null));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(null, ALICE, T0));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null, T0));
  }

  @Test
  @DisplayName("invalid arguments are rejected uniformly")
  default void invalidArgumentsRejected() {
    RefreshTokenStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(IllegalArgumentException.class,
        () -> store.markReplaced("", "h2", T0.plusSeconds(60)));
    assertThrows(IllegalArgumentException.class,
        () -> store.markReplaced("h1", "", T0.plusSeconds(60)));
    assertThrows(NullPointerException.class,
        () -> store.markReplaced("h1", "h2", null));
    assertThrows(IllegalArgumentException.class,
        () -> store.markRevoked("", T0.plusSeconds(60)));
    assertThrows(NullPointerException.class, () -> store.markRevoked("h1", null));
    assertThrows(NullPointerException.class, () -> store.deleteBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null));
    assertThrows(NullPointerException.class, () -> store.purgeExpired(null));
  }
}
