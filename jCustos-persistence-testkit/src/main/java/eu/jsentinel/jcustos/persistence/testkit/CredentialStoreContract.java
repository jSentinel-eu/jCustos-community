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
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Contract every {@link CredentialStore} implementation must satisfy.
 *
 * <p>The SPI has no insert operation - credentials are created by the
 * application's own registration path - so the contract asks the store under
 * test to be created with its rows: {@link #newStore(CredentialRecord...)}.</p>
 *
 * <p>The tests whose name starts with {@code JS-SEC-161} cover the rotation
 * proof added in 00.84.00: the store persists
 * {@link CredentialRecord#secretChangedAt()} and
 * {@link CredentialRecord#compromisedSince()}, a status change moves the
 * compromise marker as {@link CredentialRecord#withStatus} does, a new secret
 * written with {@link CredentialStore#replaceSecretIfCurrent} records the
 * change and clears the marker, a rehash keeps both, and
 * {@link CredentialStore#updateStatusIfUnchanged} compares the whole record.
 * Without them {@code CredentialLifecycleService} cannot refuse to re-enable a
 * credential whose compromised secret was never replaced. A store that still
 * inherits the SPI defaults overrides {@link #implementsRotationProof()} to
 * return {@code false} until it has caught up, which skips these tests and
 * documents the gap in its own test class.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
@DisplayName("CredentialStore — contract")
public interface CredentialStoreContract {

  /**
   * @param rows the records the store holds when the test starts
   * @return a fresh store holding exactly {@code rows}
   */
  CredentialStore newStore(CredentialRecord... rows);

  /**
   * @return {@code true} (the default) when the store under test keeps the
   *     rotation proof of JS-SEC-161; {@code false} skips its tests
   */
  default boolean implementsRotationProof() {
    return true;
  }

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant T1 = T0.plusSeconds(60);
  Instant T2 = T0.plusSeconds(120);
  Instant T3 = T0.plusSeconds(180);

  /**
   * @param username user name
   * @param status   status
   * @return a fresh record at version 1, secret set at {@link #T0}
   */
  default CredentialRecord row(String username, CredentialStatus status) {
    return CredentialRecord.initial(username, "encoded-" + username + "-v0", status, T0);
  }

  @Test
  @DisplayName("findByUsername returns the stored row; an unknown name is empty")
  default void findReturnsTheRow() {
    CredentialRecord alice = row("alice", CredentialStatus.ACTIVE);
    CredentialStore store = newStore(alice);
    assertEquals(alice.encodedHash(), store.findByUsername("alice").orElseThrow().encodedHash());
    assertEquals(CredentialStatus.ACTIVE, store.findByUsername("alice").orElseThrow().status());
    assertTrue(store.findByUsername("nobody").isEmpty());
  }

  @Test
  @DisplayName("updateHashIfCurrent swaps on a matching witness and is Stale or NotFound otherwise")
  default void hashCompareAndSwap() {
    CredentialStore store = newStore(row("alice", CredentialStatus.ACTIVE));
    assertSame(CredentialUpdateResult.Stale.INSTANCE,
        store.updateHashIfCurrent("alice", "not-the-witness", "encoded-x", T1));
    assertSame(CredentialUpdateResult.NotFound.INSTANCE,
        store.updateHashIfCurrent("nobody", "w", "encoded-x", T1));

    CredentialUpdateResult.Updated updated = assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.updateHashIfCurrent("alice", "encoded-alice-v0", "encoded-alice-v1", T1));
    assertEquals("encoded-alice-v1", updated.newRecord().encodedHash());
    assertEquals("encoded-alice-v1", store.findByUsername("alice").orElseThrow().encodedHash());
    assertTrue(store.findByUsername("alice").orElseThrow().version() > 1L);
  }

  @Test
  @DisplayName("updateStatusIfCurrent swaps on a matching status and is Stale or NotFound otherwise")
  default void statusCompareAndSwap() {
    CredentialStore store = newStore(row("alice", CredentialStatus.ACTIVE));
    assertSame(CredentialUpdateResult.Stale.INSTANCE,
        store.updateStatusIfCurrent("alice", CredentialStatus.LOCKED, CredentialStatus.ACTIVE, T1));
    assertSame(CredentialUpdateResult.NotFound.INSTANCE,
        store.updateStatusIfCurrent("nobody", CredentialStatus.ACTIVE, CredentialStatus.LOCKED, T1));
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.updateStatusIfCurrent("alice", CredentialStatus.ACTIVE, CredentialStatus.LOCKED, T1));
    assertEquals(CredentialStatus.LOCKED, store.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("of 16 concurrent hash swaps with one witness exactly one wins")
  default void hashSwapIsAtomic() throws Exception {
    CredentialStore store = newStore(row("alice", CredentialStatus.ACTIVE));
    int threads = 16;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      CountDownLatch ready = new CountDownLatch(threads);
      CountDownLatch start = new CountDownLatch(1);
      List<Future<CredentialUpdateResult>> outcomes = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        String next = "encoded-alice-" + i;
        Callable<CredentialUpdateResult> swap = () -> {
          ready.countDown();
          start.await();
          return store.updateHashIfCurrent("alice", "encoded-alice-v0", next, T1);
        };
        outcomes.add(pool.submit(swap));
      }
      assertTrue(ready.await(10, TimeUnit.SECONDS), "callers did not start");
      start.countDown();
      int winners = 0;
      for (Future<CredentialUpdateResult> outcome : outcomes) {
        if (outcome.get(30, TimeUnit.SECONDS) instanceof CredentialUpdateResult.Updated) {
          winners++;
        }
      }
      assertEquals(1, winners);
    } finally {
      pool.shutdownNow();
    }
  }

  // ── JS-SEC-161: rotation proof ──────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-161: the store declares that it keeps the rotation proof")
  default void declaresTheProof() {
    assumeTrue(implementsRotationProof());
    assertTrue(newStore().recordsSecretRotation());
  }

  @Test
  @DisplayName("JS-SEC-161: both components are persisted as handed in")
  default void componentsArePersisted() {
    assumeTrue(implementsRotationProof());
    CredentialRecord seeded = new CredentialRecord("alice", "encoded-alice-v0",
        CredentialStatus.DISABLED, 3L, T0, T2, T1, T2);
    CredentialStore store = newStore(seeded);
    CredentialRecord read = store.findByUsername("alice").orElseThrow();
    assertEquals(T1, read.secretChangedAt());
    assertEquals(T2, read.compromisedSince());
    assertTrue(read.secretRotationRequired());
  }

  @Test
  @DisplayName("JS-SEC-161: entering COMPROMISED sets the marker, leaving it keeps the marker")
  default void statusChangesMoveTheMarker() {
    assumeTrue(implementsRotationProof());
    CredentialStore store = newStore(row("alice", CredentialStatus.ACTIVE));
    store.updateStatusIfCurrent("alice", CredentialStatus.ACTIVE, CredentialStatus.COMPROMISED, T1);
    assertEquals(T1, store.findByUsername("alice").orElseThrow().compromisedSince());

    store.updateStatusIfCurrent("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, T2);
    CredentialRecord disabled = store.findByUsername("alice").orElseThrow();
    assertEquals(CredentialStatus.DISABLED, disabled.status());
    assertEquals(T1, disabled.compromisedSince(), "the marker outlives the status");
    assertTrue(disabled.secretRotationRequired());
  }

  @Test
  @DisplayName("JS-SEC-161: replaceSecretIfCurrent records the change and clears the marker; a rehash does neither")
  default void newSecretClearsTheMarkerRehashDoesNot() {
    assumeTrue(implementsRotationProof());
    CredentialStore store = newStore(new CredentialRecord("alice", "encoded-alice-v0",
        CredentialStatus.MUST_CHANGE, 2L, T0, T1, T0, T1));

    assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.updateHashIfCurrent("alice", "encoded-alice-v0", "encoded-alice-rehashed", T2));
    CredentialRecord rehashed = store.findByUsername("alice").orElseThrow();
    assertEquals(T1, rehashed.compromisedSince(), "a rehash is the same secret");
    assertEquals(T0, rehashed.secretChangedAt());

    assertSame(CredentialUpdateResult.Stale.INSTANCE,
        store.replaceSecretIfCurrent("alice", "encoded-alice-v0", "encoded-alice-v1", T3));
    assertSame(CredentialUpdateResult.NotFound.INSTANCE,
        store.replaceSecretIfCurrent("nobody", "w", "encoded-x", T3));
    CredentialUpdateResult.Updated changed = assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.replaceSecretIfCurrent("alice", "encoded-alice-rehashed", "encoded-alice-v1", T3));
    assertEquals(T3, changed.newRecord().secretChangedAt());

    CredentialRecord read = store.findByUsername("alice").orElseThrow();
    assertEquals("encoded-alice-v1", read.encodedHash());
    assertEquals(T3, read.secretChangedAt());
    assertNull(read.compromisedSince());
    assertFalse(read.secretRotationRequired());
  }

  @Test
  @DisplayName("JS-SEC-161: updateStatusIfUnchanged compares the whole record, not only the status")
  default void statusUpdateComparesTheWholeRecord() {
    assumeTrue(implementsRotationProof());
    CredentialStore store = newStore(row("alice", CredentialStatus.DISABLED));
    CredentialRecord judged = store.findByUsername("alice").orElseThrow();
    store.updateStatusIfCurrent("alice", CredentialStatus.DISABLED, CredentialStatus.COMPROMISED, T1);
    store.updateStatusIfCurrent("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, T2);

    assertSame(CredentialUpdateResult.Stale.INSTANCE,
        store.updateStatusIfUnchanged(judged, CredentialStatus.ACTIVE, T3),
        "DISABLED again, but not the record that was judged");
    assertEquals(CredentialStatus.DISABLED, store.findByUsername("alice").orElseThrow().status());

    CredentialRecord current = store.findByUsername("alice").orElseThrow();
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.updateStatusIfUnchanged(current, CredentialStatus.LOCKED, T3));
    assertEquals(CredentialStatus.LOCKED, store.findByUsername("alice").orElseThrow().status());
    assertEquals(T1, store.findByUsername("alice").orElseThrow().compromisedSince());
  }
}
