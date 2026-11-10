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
package eu.jsentinel.jcustos.replay.impl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryNonceStore")
class InMemoryNonceStoreTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("bind + single-use consume round-trip")
  void bindConsumeRoundTrip() {
    InMemoryNonceStore store = new InMemoryNonceStore(() -> T0);
    store.bind("req-1", "nonce-abc", Duration.ofMinutes(10));
    assertEquals(Optional.of("nonce-abc"), store.consume("req-1"));
    assertTrue(store.consume("req-1").isEmpty(), "consume is single-use");
  }

  @Test
  @DisplayName("JS-SEC-150: a store full of live bindings accepts a new key and evicts the earliest-expiring one")
  void fullOfLiveEvictsEarliestExpiring() {
    // Up to 00.83.x this bind threw replay/nonce-store-capacity-exceeded (JS-SEC-051) — an
    // anonymous caller who kept the store full blocked every flow of every user.
    int cap = 20;
    InMemoryNonceStore store = new InMemoryNonceStore(() -> T0, cap);
    store.bind("short-lived", "n-short", Duration.ofMinutes(1));
    for (int i = 1; i < cap; i++) {
      store.bind("k-" + i, "n-" + i, Duration.ofMinutes(10));
    }
    assertEquals(cap, store.trackedKeyCount());

    store.bind("overflow", "n-new", Duration.ofMinutes(10));

    assertEquals(cap, store.trackedKeyCount(), "the size stays at the bound");
    assertEquals(Optional.of("n-new"), store.consume("overflow"), "the newest binding is consumable");
    assertTrue(store.consume("short-lived").isEmpty(), "the earliest-expiring binding was evicted");
    assertEquals(Optional.of("n-1"), store.consume("k-1"), "a longer-lived binding survived");
  }

  @Test
  @DisplayName("JS-SEC-150: re-binding an existing key at capacity replaces it and evicts nothing")
  void rebindAtCapacityEvictsNothing() {
    int cap = 5;
    InMemoryNonceStore store = new InMemoryNonceStore(() -> T0, cap);
    for (int i = 0; i < cap; i++) {
      store.bind("k-" + i, "n-" + i, Duration.ofMinutes(10));
    }
    store.bind("k-3", "n-3-new", Duration.ofMinutes(10));
    assertEquals(cap, store.trackedKeyCount());
    assertEquals(Optional.of("n-3-new"), store.consume("k-3"));
    assertEquals(Optional.of("n-0"), store.consume("k-0"));
  }

  @Test
  @DisplayName("JS-SEC-051 / JS-SEC-150: a full-but-expired map is reclaimed batch by batch, without a full scan")
  void fullOfExpiredIsReclaimed() {
    int cap = 20;
    AtomicReference<Instant> now = new AtomicReference<>(T0);
    InMemoryNonceStore store = new InMemoryNonceStore(now::get, cap);
    for (int i = 0; i < cap; i++) {
      store.bind("k-" + i, "n", Duration.ofSeconds(1));
    }
    now.set(T0.plusSeconds(60)); // every binding is now expired
    store.bind("fresh-0", "n", Duration.ofMinutes(10));
    assertTrue(store.trackedKeyCount() < cap, "the first bind already reclaims a batch of expired bindings");
    // JS-SEC-150: the purge is amortised — a few more binds reclaim the rest
    store.bind("fresh-1", "n", Duration.ofMinutes(10));
    store.bind("fresh-2", "n", Duration.ofMinutes(10));
    assertEquals(3, store.trackedKeyCount(), "all expired bindings were reclaimed, the live ones kept");
    assertEquals(Optional.of("n"), store.consume("fresh-0"));
  }
}
