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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore;
import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore.PresentedHash;
import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore.RotationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Contract every {@link RefreshTokenFamilyStore} implementation must satisfy.
 *
 * <p>The tests without a prefix cover rotation and reuse detection as they stand
 * since 00.77: the current hash rotates, any other hash revokes the family, and
 * {@link RefreshTokenFamilyStore#classify} never changes anything — not even its
 * {@code default}.</p>
 *
 * <p>The tests whose name starts with {@code R9} cover the issued-hash history added
 * in 00.84.10: {@link RefreshTokenFamilyStore#classify} tells the current hash, a
 * hash the family issued and rotated away, and a hash it never issued apart. It is
 * what lets the authorisation server of the enterprise edition refuse a made-up
 * secret under a known family id without revoking the family. A store that
 * overrides {@code classify} passes; a store that still inherits the
 * {@code default} does not, because the default keeps no history. Such a store
 * overrides {@link #implementsIssuedHashHistory()} to return {@code false} until
 * it has caught up, which skips these tests and documents the gap in its own test
 * class.</p>
 *
 * <p>A store backed by durable storage also overrides {@link #reopen}: the restart
 * test then proves that the history survives a restart, which is the point of
 * keeping it in the store.</p>
 *
 * @since 00.84.10
 */
@ExperimentalJCustosApi
@DisplayName("RefreshTokenFamilyStore — contract")
public interface RefreshTokenFamilyStoreContract {

  /**
   * @return a fresh, empty {@code RefreshTokenFamilyStore}
   */
  RefreshTokenFamilyStore newStore();

  /**
   * @return {@code true} (the default) when the store under test overrides
   *     {@link RefreshTokenFamilyStore#classify} (R9); {@code false} skips its tests
   */
  default boolean implementsIssuedHashHistory() {
    return true;
  }

  /**
   * Simulates a restart. A store backed by durable storage closes {@code store} and
   * returns a new instance over the same storage. The default returns {@code store}
   * itself, which only covers a store that lives as long as its process.
   *
   * @param store the store the test wrote to
   * @return the store to read from after the "restart"
   */
  default RefreshTokenFamilyStore reopen(RefreshTokenFamilyStore store) {
    return store;
  }

  String FAMILY = "family-a";
  String OTHER_FAMILY = "family-b";

  /**
   * The hash of a synthetic refresh token, as the callers compute it: hex SHA-256.
   *
   * @param token synthetic token value
   * @return lower-case hex SHA-256 of its UTF-8 bytes
   */
  default String hash(String token) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  /**
   * Records {@code FAMILY} with {@code t0} and rotates it {@code rotations} times to
   * {@code t1 … t<rotations>}.
   *
   * @param store     the store under test
   * @param rotations number of rotations
   */
  default void issueAndRotate(RefreshTokenFamilyStore store, int rotations) {
    store.recordIssued(FAMILY, hash("t0"));
    for (int i = 1; i <= rotations; i++) {
      assertEquals(RotationResult.ROTATED,
          store.consumeAndRotate(FAMILY, hash("t" + (i - 1)), hash("t" + i)), "rotation " + i);
    }
  }

  // ── rotation and reuse detection (00.77) ───────────────────────────

  @Test
  @DisplayName("the current hash rotates; replaying the rotated one revokes the whole family")
  default void rotateThenReplayRevokes() {
    RefreshTokenFamilyStore store = newStore();
    store.recordIssued(FAMILY, hash("t0"));
    assertEquals(RotationResult.ROTATED, store.detectReuse(FAMILY, hash("t0")),
        "the pre-check of the current hash neither rotates nor revokes");
    assertEquals(RotationResult.ROTATED, store.consumeAndRotate(FAMILY, hash("t0"), hash("t1")));
    assertEquals(RotationResult.REUSE_DETECTED,
        store.consumeAndRotate(FAMILY, hash("t0"), hash("t2")), "replay of t0");
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse(FAMILY, hash("t1")),
        "the whole family is revoked");
  }

  @Test
  @DisplayName("detectReuse and consumeAndRotate still revoke on any hash that is not current")
  default void anyNonCurrentHashRevokes() {
    RefreshTokenFamilyStore store = newStore();
    store.recordIssued(FAMILY, hash("t0"));
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse(FAMILY, hash("made-up")));
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse(FAMILY, hash("t0")));

    store.recordIssued(OTHER_FAMILY, hash("o0"));
    assertEquals(RotationResult.REUSE_DETECTED,
        store.consumeAndRotate(OTHER_FAMILY, hash("made-up"), hash("o1")));
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse(OTHER_FAMILY, hash("o0")));
  }

  @Test
  @DisplayName("revokeFamily ends one family and leaves the others alone")
  default void revokeFamilyIsPerFamily() {
    RefreshTokenFamilyStore store = newStore();
    store.recordIssued(FAMILY, hash("t0"));
    store.recordIssued(OTHER_FAMILY, hash("o0"));
    store.revokeFamily(FAMILY);
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse(FAMILY, hash("t0")));
    assertEquals(RotationResult.ROTATED, store.detectReuse(OTHER_FAMILY, hash("o0")));
  }

  @Test
  @DisplayName("a rotation to the same hash (the token was kept) leaves it current")
  default void rotationToTheSameHash() {
    RefreshTokenFamilyStore store = newStore();
    store.recordIssued(FAMILY, hash("t0"));
    assertEquals(RotationResult.ROTATED, store.consumeAndRotate(FAMILY, hash("t0"), hash("t0")));
    assertEquals(RotationResult.ROTATED, store.detectReuse(FAMILY, hash("t0")));
  }

  @Test
  @DisplayName("classify changes nothing - not for the current, an earlier, a made-up hash or an unknown family")
  default void classifyHasNoSideEffect() {
    RefreshTokenFamilyStore store = newStore();
    issueAndRotate(store, 2);
    for (String token : List.of("t0", "t1", "t2", "made-up")) {
      assertNotNull(store.classify(FAMILY, hash(token)), token);
    }
    assertNotNull(store.classify("no-such-family", hash("t2")));
    assertEquals(RotationResult.ROTATED, store.detectReuse(FAMILY, hash("t2")),
        "the family is still alive and t2 still current");
    assertEquals(RotationResult.ROTATED, store.consumeAndRotate(FAMILY, hash("t2"), hash("t3")));
  }

  @Test
  @DisplayName("classify rejects null arguments")
  default void classifyRejectsNull() {
    RefreshTokenFamilyStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.classify(null, hash("t0")));
    assertThrows(NullPointerException.class, () -> store.classify(FAMILY, null));
  }

  @Test
  @DisplayName("of 16 parallel rotations of the current hash exactly one succeeds")
  default void rotationIsAtomic() throws Exception {
    RefreshTokenFamilyStore store = newStore();
    int threads = 16;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      for (int round = 0; round < 10; round++) {
        String family = "race-" + round;
        store.recordIssued(family, hash(family + "-t0"));
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<RotationResult>> outcomes = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
          String next = hash(family + "-next-" + i);
          Callable<RotationResult> rotation = () -> {
            ready.countDown();
            start.await();
            return store.consumeAndRotate(family, hash(family + "-t0"), next);
          };
          outcomes.add(pool.submit(rotation));
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS), "callers did not start");
        start.countDown();
        int rotated = 0;
        for (Future<RotationResult> outcome : outcomes) {
          if (outcome.get(30, TimeUnit.SECONDS) == RotationResult.ROTATED) {
            rotated++;
          }
        }
        assertEquals(1, rotated, "round " + round + ": exactly one presentation may rotate");
      }
    } finally {
      pool.shutdownNow();
    }
  }

  // ── R9: the issued-hash history (00.84.10) ─────────────────────────

  @Test
  @DisplayName("R9: classify tells the current, an earlier issued and a never-issued hash apart")
  default void classifiesIssuedHashes() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore store = newStore();
    store.recordIssued(FAMILY, hash("t0"));
    assertEquals(PresentedHash.CURRENT, store.classify(FAMILY, hash("t0")));
    assertEquals(PresentedHash.UNKNOWN, store.classify(FAMILY, hash("made-up")));

    assertEquals(RotationResult.ROTATED, store.consumeAndRotate(FAMILY, hash("t0"), hash("t1")));
    assertEquals(PresentedHash.CURRENT, store.classify(FAMILY, hash("t1")));
    assertEquals(PresentedHash.PREVIOUSLY_ISSUED, store.classify(FAMILY, hash("t0")));
    assertEquals(PresentedHash.UNKNOWN, store.classify(FAMILY, hash("made-up")));
  }

  @Test
  @DisplayName("R9: a hash of one family is unknown to another, and an unknown family knows no hash")
  default void historyIsPerFamily() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore store = newStore();
    issueAndRotate(store, 1);
    store.recordIssued(OTHER_FAMILY, hash("o0"));
    assertEquals(PresentedHash.UNKNOWN, store.classify(OTHER_FAMILY, hash("t0")));
    assertEquals(PresentedHash.UNKNOWN, store.classify(OTHER_FAMILY, hash("t1")));
    assertEquals(PresentedHash.UNKNOWN, store.classify("no-such-family", hash("t1")));
  }

  @Test
  @DisplayName("R9: the history holds at least ISSUED_HASH_HISTORY hashes, the current one included")
  default void historyHoldsTheDocumentedMinimum() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore store = newStore();
    int rotations = RefreshTokenFamilyStore.ISSUED_HASH_HISTORY - 1;
    issueAndRotate(store, rotations);
    assertEquals(PresentedHash.CURRENT, store.classify(FAMILY, hash("t" + rotations)));
    for (int i = 0; i < rotations; i++) {
      assertEquals(PresentedHash.PREVIOUSLY_ISSUED, store.classify(FAMILY, hash("t" + i)), "t" + i);
    }
  }

  @Test
  @DisplayName("R9: classifying a made-up hash many times never revokes the family")
  default void madeUpHashesDoNotRevoke() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore store = newStore();
    issueAndRotate(store, 3);
    for (int i = 0; i < 100; i++) {
      assertEquals(PresentedHash.UNKNOWN, store.classify(FAMILY, hash("made-up-" + i)));
    }
    assertEquals(PresentedHash.CURRENT, store.classify(FAMILY, hash("t3")));
    assertEquals(RotationResult.ROTATED, store.consumeAndRotate(FAMILY, hash("t3"), hash("t4")));
    assertEquals(PresentedHash.PREVIOUSLY_ISSUED, store.classify(FAMILY, hash("t3")));
  }

  @Test
  @DisplayName("R9: a revoked family has no current hash")
  default void revokedFamilyHasNoCurrentHash() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore store = newStore();
    issueAndRotate(store, 2);
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse(FAMILY, hash("t0")), "reuse");
    for (String token : List.of("t0", "t1", "t2")) {
      assertNotEquals(PresentedHash.CURRENT, store.classify(FAMILY, hash(token)), token);
    }

    store.recordIssued(OTHER_FAMILY, hash("o0"));
    assertEquals(PresentedHash.CURRENT, store.classify(OTHER_FAMILY, hash("o0")));
    store.revokeFamily(OTHER_FAMILY);
    assertNotEquals(PresentedHash.CURRENT, store.classify(OTHER_FAMILY, hash("o0")));
  }

  @Test
  @DisplayName("R9: a rotation to the same hash keeps it current")
  default void rotationToTheSameHashStaysCurrent() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore store = newStore();
    store.recordIssued(FAMILY, hash("t0"));
    assertEquals(RotationResult.ROTATED, store.consumeAndRotate(FAMILY, hash("t0"), hash("t0")));
    assertEquals(PresentedHash.CURRENT, store.classify(FAMILY, hash("t0")));
  }

  @Test
  @DisplayName("R9: after a restart the history is still there - an earlier hash is reuse, a made-up one is unknown")
  default void historySurvivesARestart() {
    assumeTrue(implementsIssuedHashHistory());
    RefreshTokenFamilyStore before = newStore();
    issueAndRotate(before, 3);
    before.recordIssued(OTHER_FAMILY, hash("o0"));

    RefreshTokenFamilyStore after = reopen(before);
    assertEquals(PresentedHash.CURRENT, after.classify(FAMILY, hash("t3")));
    assertEquals(PresentedHash.PREVIOUSLY_ISSUED, after.classify(FAMILY, hash("t1")));
    assertEquals(PresentedHash.UNKNOWN, after.classify(FAMILY, hash("made-up")));
    assertEquals(PresentedHash.CURRENT, after.classify(OTHER_FAMILY, hash("o0")));
    assertEquals(RotationResult.ROTATED, after.consumeAndRotate(FAMILY, hash("t3"), hash("t4")));
    assertEquals(PresentedHash.PREVIOUSLY_ISSUED, after.classify(FAMILY, hash("t3")));
  }
}
