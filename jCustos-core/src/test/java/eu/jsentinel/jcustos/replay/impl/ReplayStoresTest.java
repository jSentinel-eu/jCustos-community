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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.replay.api.ReplayError;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Replay stores — JtiStore single-use + NonceStore TTL/consume")
class ReplayStoresTest {

  private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-06-27T12:00:00Z"));

  @Test
  @DisplayName("a fresh jti records; a replay within the window is rejected")
  void jtiReplayRejected() {
    InMemoryJtiStore store = new InMemoryJtiStore(100, now::get);
    Instant exp = now.get().plusSeconds(60);
    assertTrue(store.record("jti-1", exp).toOptional().isPresent(), "first record succeeds");
    ReplayError err = store.record("jti-1", exp).fold(ok -> null, e -> e);
    assertEquals("replay/jti-already-seen", err.code());
  }

  @Test
  @DisplayName("a jti may be recorded again once its window has expired")
  void jtiReRecordableAfterExpiry() {
    InMemoryJtiStore store = new InMemoryJtiStore(100, now::get);
    store.record("jti-2", now.get().plusSeconds(60)).toOptional().orElseThrow();
    now.set(now.get().plusSeconds(120)); // past expiry
    assertTrue(store.record("jti-2", now.get().plusSeconds(60)).toOptional().isPresent());
  }

  @Test
  @DisplayName("NonceStore consume is single-use and TTL-checked")
  void nonceSingleUseAndTtl() {
    InMemoryNonceStore store = new InMemoryNonceStore(now::get);
    store.bind("req-1", "n-abc", Duration.ofSeconds(30));
    assertEquals(Optional.of("n-abc"), store.consume("req-1"));
    assertTrue(store.consume("req-1").isEmpty(), "second consume is empty (single-use)");

    store.bind("req-2", "n-xyz", Duration.ofSeconds(30));
    now.set(now.get().plusSeconds(60)); // past TTL
    assertTrue(store.consume("req-2").isEmpty(), "expired nonce is not returned");
  }

  @Test
  @DisplayName("an unknown request key consumes to empty")
  void unknownKeyEmpty() {
    assertFalse(new InMemoryNonceStore(now::get).consume("nope").isPresent());
  }

  @Test
  @DisplayName("on overflow the soonest-to-expire jti is evicted, not a long-lived one (R012)")
  void overflowEvictsSoonestToExpire() {
    InMemoryJtiStore store = new InMemoryJtiStore(2, now::get);
    store.record("jti-long", now.get().plusSeconds(3600)).toOptional().orElseThrow();
    store.record("jti-short", now.get().plusSeconds(10)).toOptional().orElseThrow();
    // third record at capacity → evicts the soonest-to-expire entry (jti-short).
    store.record("jti-other", now.get().plusSeconds(3600)).toOptional().orElseThrow();

    // jti-long must still be remembered → re-recording it within its window is a replay.
    assertTrue(store.record("jti-long", now.get().plusSeconds(3600)).isFailure(),
        "long-lived jti must survive the overflow");
    // jti-short was evicted → it records fresh again.
    assertTrue(store.record("jti-short", now.get().plusSeconds(10)).toOptional().isPresent());
  }

  @Test
  @DisplayName("JS-SEC-148: a 50 000-character jti is recorded as a digest — replay still detected, no long string kept")
  void longJtiIsStoredAsDigest() {
    InMemoryJtiStore store = new InMemoryJtiStore(100, now::get);
    String huge = "j".repeat(50_000);
    Instant exp = now.get().plusSeconds(60);

    assertTrue(store.record(huge, exp).toOptional().isPresent(), "first record succeeds");
    assertEquals("replay/jti-already-seen", store.record(huge, exp).fold(ok -> null, e -> e).code(),
        "the second record of the same jti is still a replay");
    // a jti that differs only in its last character is a different jti
    assertTrue(store.record("j".repeat(49_999) + "k", exp).toOptional().isPresent());

    // constant entry size: SHA-256, base64url without padding = 43 characters, whatever came in
    assertEquals(2, store.trackedKeys().size());
    for (String key : store.trackedKeys()) {
      assertEquals(43, key.length(), "the store must keep the digest, not the jti");
    }
    assertFalse(store.trackedKeys().contains(huge));
  }

  @Test
  @DisplayName("JS-SEC-148: a short jti is not kept in clear text either")
  void shortJtiIsNotStoredInClearText() {
    InMemoryJtiStore store = new InMemoryJtiStore(100, now::get);
    store.record("jti-plain", now.get().plusSeconds(60)).toOptional().orElseThrow();
    assertFalse(store.trackedKeys().contains("jti-plain"));
  }
}
