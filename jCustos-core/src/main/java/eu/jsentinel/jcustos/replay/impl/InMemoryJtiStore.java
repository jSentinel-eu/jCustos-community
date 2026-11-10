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

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.replay.api.JtiStore;
import eu.jsentinel.jcustos.replay.api.ReplayError;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * In-memory {@link JtiStore} (V00.79): a sliding window of seen {@code jti}s, bounded by
 * a capacity (default 100k). A {@code jti} seen within its validity window is a replay;
 * once a {@code jti}'s {@code expiresAt} has passed it may be recorded again (its proof's
 * window is over). When the capacity bound is hit, expired entries are purged first and,
 * if still full, the entry with the <strong>soonest expiry</strong> (shortest remaining
 * replay window) is evicted — never the least-recently-used one. This <em>mitigates</em>
 * the flood-evict-replay weakness of the old LRU policy (a flooding attacker now evicts the
 * entry closest to expiry, i.e. the one with the least remaining replay value) but does
 * <strong>not</strong> fully close it on a single JVM (JS-SEC-008): a sustained flood of
 * freshly-issued proofs can still evict a victim's still-live {@code jti} within its window.
 * A production DPoP resource server must therefore use a shared atomic {@code SET-NX + TTL}
 * store (Redis / JDBC) — that is the real replay defense. The naive
 * fail-closed-reject-on-full alternative is intentionally avoided: it turns the narrow
 * replay window into a trivial full DoS. For a single JVM only — a multi-node deployment
 * needs a shared store. Thread-safe (synchronised).
 *
 * <p><strong>JS-SEC-148 (CWE-770):</strong> the store keeps the SHA-256 digest of a {@code jti},
 * never the {@code jti} itself. The capacity bound counts entries, not bytes, so a caller-chosen
 * {@code jti} of several thousand characters used to turn 100 000 entries into several hundred
 * megabytes of heap. Every entry now has the same small size whatever the caller sends, and the
 * identifier is no longer held in clear text.
 */
@ExperimentalJCustosApi
public final class InMemoryJtiStore implements JtiStore {

  /** Default capacity bound on retained {@code jti}s. */
  public static final int DEFAULT_MAX_ENTRIES = 100_000;

  private final int maxEntries;
  private final Supplier<Instant> clock;
  /** Keyed by the SHA-256 digest of the jti (JS-SEC-148) — never by the jti itself. */
  private final Map<String, Instant> seen = new HashMap<>();

  public InMemoryJtiStore() {
    this(DEFAULT_MAX_ENTRIES, Instant::now);
  }

  public InMemoryJtiStore(int maxEntries, Supplier<Instant> clock) {
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.maxEntries = maxEntries;
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public synchronized Result<Boolean, ReplayError> record(String jti, Instant expiresAt) {
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Instant now = clock.get();
    // JS-SEC-148 (CWE-770): constant entry size — record the digest, not the caller-chosen value.
    String key = digestOf(jti);
    Instant existing = seen.get(key);
    if (existing != null && existing.isAfter(now)) {
      return Result.failure(ReplayError.replayDetected());
    }
    if (!seen.containsKey(key) && seen.size() >= maxEntries) {
      evictOne(now);
    }
    seen.put(key, expiresAt);
    return Result.success(Boolean.TRUE);
  }

  /** Package-visible for tests: the keys the store retains (JS-SEC-148 — digests, 43 characters). */
  synchronized Set<String> trackedKeys() {
    return Set.copyOf(seen.keySet());
  }

  private static String digestOf(String jti) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(jti.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required but unavailable", e);
    }
  }

  private void evictOne(Instant now) {
    // Purge everything already expired (free to drop — its replay window is over).
    seen.values().removeIf(exp -> !exp.isAfter(now));
    if (seen.size() < maxEntries) {
      return;
    }
    // Still full: drop the entry with the smallest expiresAt (shortest remaining window).
    seen.entrySet().stream()
        .min(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .ifPresent(seen::remove);
  }
}
