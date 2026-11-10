/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.store;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryCredentialStoreTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");
  private static final Instant T1 = Instant.parse("2026-06-01T12:00:05Z");
  private static final Instant T2 = Instant.parse("2026-06-01T12:00:10Z");

  private InMemoryCredentialStore newStoreWithAlice() {
    InMemoryCredentialStore store = new InMemoryCredentialStore();
    store.register(CredentialRecord.initial(
        "alice", "encoded-v0", CredentialStatus.ACTIVE, T0));
    return store;
  }

  @Test
  @DisplayName("register stores a fresh record at version 1")
  void registerWorks() {
    InMemoryCredentialStore store = newStoreWithAlice();
    CredentialRecord stored = store.findByUsername("alice").orElseThrow();
    assertEquals("alice", stored.username());
    assertEquals("encoded-v0", stored.encodedHash());
    assertEquals(CredentialStatus.ACTIVE, stored.status());
    assertEquals(1L, stored.version());
  }

  @Test
  @DisplayName("register rejects a duplicate username")
  void registerRejectsDuplicate() {
    InMemoryCredentialStore store = newStoreWithAlice();
    assertThrows(IllegalStateException.class, () ->
        store.register(CredentialRecord.initial(
            "alice", "encoded-v0", CredentialStatus.ACTIVE, T0)));
  }

  @Test
  @DisplayName("Successful CAS hash update returns Updated and bumps version + updatedAt")
  void successfulCasHashUpdate() {
    InMemoryCredentialStore store = newStoreWithAlice();
    CredentialUpdateResult result = store.updateHashIfCurrent(
        "alice", "encoded-v0", "encoded-v1", T1);
    CredentialUpdateResult.Updated updated = assertInstanceOf(
        CredentialUpdateResult.Updated.class, result);
    assertEquals("encoded-v1", updated.newRecord().encodedHash());
    assertEquals(2L, updated.newRecord().version());
    assertEquals(T1, updated.newRecord().updatedAt());
    assertEquals(T0, updated.newRecord().createdAt(),
        "createdAt must not change on update");
  }

  @Test
  @DisplayName("Stale witness yields Stale and does not modify the record")
  void staleHashUpdate() {
    InMemoryCredentialStore store = newStoreWithAlice();
    CredentialUpdateResult result = store.updateHashIfCurrent(
        "alice", "wrong-witness", "encoded-v1", T1);
    assertSame(CredentialUpdateResult.Stale.INSTANCE, result);
    assertEquals("encoded-v0",
        store.findByUsername("alice").orElseThrow().encodedHash());
  }

  @Test
  @DisplayName("NotFound when the username is unknown")
  void notFoundUsername() {
    InMemoryCredentialStore store = newStoreWithAlice();
    assertSame(CredentialUpdateResult.NotFound.INSTANCE,
        store.updateHashIfCurrent("bob", "x", "y", T1));
    assertSame(CredentialUpdateResult.NotFound.INSTANCE,
        store.updateStatusIfCurrent("bob",
            CredentialStatus.ACTIVE, CredentialStatus.LOCKED, T1));
  }

  @Test
  @DisplayName("updateStatusIfCurrent applies the new status and bumps version")
  void successfulStatusUpdate() {
    InMemoryCredentialStore store = newStoreWithAlice();
    CredentialUpdateResult.Updated updated = (CredentialUpdateResult.Updated)
        store.updateStatusIfCurrent("alice",
            CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE, T1);
    assertEquals(CredentialStatus.MUST_CHANGE, updated.newRecord().status());
    assertEquals(2L, updated.newRecord().version());
  }

  @Test
  @DisplayName("Stale status CAS yields Stale and does not modify the record")
  void staleStatusUpdate() {
    InMemoryCredentialStore store = newStoreWithAlice();
    assertSame(CredentialUpdateResult.Stale.INSTANCE,
        store.updateStatusIfCurrent("alice",
            CredentialStatus.LOCKED, CredentialStatus.ACTIVE, T1));
    assertEquals(CredentialStatus.ACTIVE,
        store.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("Concurrent rehash attempts with the same witness have exactly one winner")
  void concurrentRehashOneWinner() throws InterruptedException {
    InMemoryCredentialStore store = newStoreWithAlice();
    int threads = 8;
    CountDownLatch start = new CountDownLatch(1);
    AtomicInteger winners = new AtomicInteger();
    AtomicInteger stales = new AtomicInteger();

    Thread[] workers = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      String witness = "encoded-v0";
      String newHash = "encoded-by-thread-" + i;
      workers[i] = new Thread(() -> {
        try {
          start.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          return;
        }
        CredentialUpdateResult r = store.updateHashIfCurrent(
            "alice", witness, newHash, T1);
        if (r instanceof CredentialUpdateResult.Updated) {
          winners.incrementAndGet();
        } else if (r instanceof CredentialUpdateResult.Stale) {
          stales.incrementAndGet();
        }
      });
      workers[i].setDaemon(true);
      workers[i].start();
    }
    start.countDown();
    for (Thread w : workers) {
      w.join(5_000);
    }
    assertEquals(1, winners.get(),
        "exactly one rehash must win the race");
    assertEquals(threads - 1, stales.get(),
        "every other thread must observe Stale");
    assertEquals(2L,
        store.findByUsername("alice").orElseThrow().version(),
        "version must reflect a single successful update");
  }

  @Test
  @DisplayName("CredentialRecord.toString never exposes the encoded hash")
  void recordToStringRedacts() {
    CredentialRecord r = CredentialRecord.initial(
        "alice", "very-secret-hash", CredentialStatus.ACTIVE, T0);
    String text = r.toString();
    assertFalse(text.contains("very-secret-hash"));
    assertTrue(text.contains("<redacted>"));
    assertTrue(text.contains("alice"));
  }

  @Test
  @DisplayName("CredentialRecord invariants reject blank username/hash and version < 1")
  void recordInvariants() {
    assertThrows(IllegalArgumentException.class, () ->
        new CredentialRecord(" ", "h", CredentialStatus.ACTIVE, 1L, T0, T0));
    assertThrows(IllegalArgumentException.class, () ->
        new CredentialRecord("a", " ", CredentialStatus.ACTIVE, 1L, T0, T0));
    assertThrows(IllegalArgumentException.class, () ->
        new CredentialRecord("a", "h", CredentialStatus.ACTIVE, 0L, T0, T0));
    assertThrows(NullPointerException.class, () ->
        new CredentialRecord("a", "h", null, 1L, T0, T0));
  }

  @Test
  @DisplayName("CAS updates leave createdAt intact across successive updates")
  void createdAtImmutable() {
    InMemoryCredentialStore store = newStoreWithAlice();
    store.updateHashIfCurrent("alice", "encoded-v0", "encoded-v1", T1);
    store.updateStatusIfCurrent("alice",
        CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE, T2);
    CredentialRecord finalRecord = store.findByUsername("alice").orElseThrow();
    assertEquals(T0, finalRecord.createdAt());
    assertEquals(T2, finalRecord.updatedAt());
    assertEquals(3L, finalRecord.version());
  }

  // ── JS-SEC-123 (CWE-178): one account per canonical name ────────

  @Test
  @DisplayName("JS-SEC-123: alice and ALICE cannot be two accounts")
  void spellingsOfOneNameAreOneAccount() {
    InMemoryCredentialStore store = newStoreWithAlice();

    assertThrows(IllegalStateException.class, () ->
            store.register(CredentialRecord.initial(
                "ALICE", "encoded-attacker", CredentialStatus.ACTIVE, T0)),
        "a second account that differs only in case would share alice's failure counter");
    assertThrows(IllegalStateException.class, () ->
        store.register(CredentialRecord.initial(
            " Alice ", "encoded-attacker", CredentialStatus.ACTIVE, T0)));
    assertEquals(1, store.size());

    CredentialRecord found = store.findByUsername("ALICE").orElseThrow();
    assertEquals("alice", found.username(), "the record keeps the spelling it was registered with");
    assertEquals("encoded-v0", found.encodedHash());
  }

  @Test
  @DisplayName("JS-SEC-123: updates address the account through any spelling")
  void updatesUseTheCanonicalKey() {
    InMemoryCredentialStore store = newStoreWithAlice();

    assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.updateHashIfCurrent("ALICE", "encoded-v0", "encoded-v1", T1));
    assertEquals("encoded-v1", store.findByUsername("alice").orElseThrow().encodedHash());
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        store.updateStatusIfCurrent(" Alice ", CredentialStatus.ACTIVE, CredentialStatus.DISABLED, T2));
    assertEquals(CredentialStatus.DISABLED, store.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("JS-SEC-123: with exact() every spelling is its own account, as before 00.84.00")
  void exactCanonicalizerKeepsSpellingsApart() {
    InMemoryCredentialStore store = new InMemoryCredentialStore(
        eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer.exact());
    store.register(CredentialRecord.initial("alice", "encoded-a", CredentialStatus.ACTIVE, T0));
    store.register(CredentialRecord.initial("ALICE", "encoded-b", CredentialStatus.ACTIVE, T0));

    assertEquals(2, store.size());
    assertEquals("encoded-b", store.findByUsername("ALICE").orElseThrow().encodedHash());
    assertTrue(store.findByUsername("Alice").isEmpty());
  }
}
