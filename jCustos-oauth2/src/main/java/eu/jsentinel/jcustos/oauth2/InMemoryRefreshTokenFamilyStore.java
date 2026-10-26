/**import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore;

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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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

import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * In-process {@link RefreshTokenFamilyStore} (V00.77). Holds only the current
 * refresh-token <em>hash</em> per family. {@link #consumeAndRotate} is atomic
 * under {@code synchronized}: presenting the current hash rotates the family to
 * the new hash; presenting anything else (an already-rotated token being
 * replayed, or a revoked family) revokes the family and reports
 * {@link RotationResult#REUSE_DETECTED}.
 *
 * @since 00.77.00
 */
public final class InMemoryRefreshTokenFamilyStore implements RefreshTokenFamilyStore {

  /** Default retention of a revoked family id before it is forgotten. */
  public static final Duration DEFAULT_REVOKED_RETENTION = Duration.ofDays(7);

  // Insertion-ordered so the family seen first is the eviction candidate (JS-SEC-078,
  // CWE-770: family ids arrive from clients and were never bounded before 00.84.00).
  private final LinkedHashMap<String, String> currentHashByFamily = new LinkedHashMap<>();
  /** revoked family id → instant it may be forgotten. */
  private final LinkedHashMap<String, Instant> revokedFamilies = new LinkedHashMap<>();
  private final int maxFamilies;
  private final Duration revokedRetention;
  private final Clock clock;

  /** Bounded to {@link CapacityBound#DEFAULT_MAX_ENTRIES} families, revoked ids kept for seven days. */
  public InMemoryRefreshTokenFamilyStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES, DEFAULT_REVOKED_RETENTION, Clock.systemUTC());
  }

  /**
   * @param maxFamilies      upper bound on tracked families (current and revoked each);
   *                         at the bound the family seen first is evicted
   * @param revokedRetention how long a revoked family id is remembered so a replay
   *                         is still answered with {@code REUSE_DETECTED}
   * @param clock            time source for the retention
   * @since 00.84.00
   */
  public InMemoryRefreshTokenFamilyStore(int maxFamilies, Duration revokedRetention, Clock clock) {
    this.maxFamilies = CapacityBound.requirePositiveCapacity(maxFamilies);
    this.revokedRetention = Objects.requireNonNull(revokedRetention, "revokedRetention");
    if (revokedRetention.isZero() || revokedRetention.isNegative()) {
      throw new IllegalArgumentException("revokedRetention must be strictly positive");
    }
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /** @return number of families with a current token (test and diagnostics hook). */
  public synchronized int trackedFamilyCount() {
    return currentHashByFamily.size();
  }

  /** @return number of revoked family ids still remembered. */
  public synchronized int revokedFamilyCount() {
    expireRevoked();
    return revokedFamilies.size();
  }

  @Override
  public synchronized void recordIssued(String familyId, String tokenHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(tokenHash, "tokenHash");
    revokedFamilies.remove(familyId);
    if (!currentHashByFamily.containsKey(familyId) && currentHashByFamily.size() >= maxFamilies) {
      String oldest = currentHashByFamily.keySet().iterator().next();
      currentHashByFamily.remove(oldest);
    }
    currentHashByFamily.put(familyId, tokenHash);
  }

  @Override
  public synchronized RotationResult consumeAndRotate(String familyId, String presentedHash, String newHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(presentedHash, "presentedHash");
    Objects.requireNonNull(newHash, "newHash");
    if (isRevokedNow(familyId)) {
      return RotationResult.REUSE_DETECTED;
    }
    String current = currentHashByFamily.get(familyId);
    if (current != null && current.equals(presentedHash)) {
      currentHashByFamily.put(familyId, newHash);
      return RotationResult.ROTATED;
    }
    // an already-rotated or unknown token was replayed — theft signal (BCP 9700)
    revokeFamily(familyId);
    return RotationResult.REUSE_DETECTED;
  }

  @Override
  public synchronized RotationResult detectReuse(String familyId, String presentedHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(presentedHash, "presentedHash");
    if (isRevokedNow(familyId)) {
      return RotationResult.REUSE_DETECTED;
    }
    String current = currentHashByFamily.get(familyId);
    if (current != null && current.equals(presentedHash)) {
      return RotationResult.ROTATED; // current — safe to forward, no rotation yet
    }
    // an already-rotated or unknown token was replayed — revoke before the AS call
    revokeFamily(familyId);
    return RotationResult.REUSE_DETECTED;
  }

  @Override
  public synchronized void revokeFamily(String familyId) {
    Objects.requireNonNull(familyId, "familyId");
    currentHashByFamily.remove(familyId);
    expireRevoked();
    if (!revokedFamilies.containsKey(familyId) && revokedFamilies.size() >= maxFamilies) {
      String oldest = revokedFamilies.keySet().iterator().next();
      revokedFamilies.remove(oldest);
    }
    revokedFamilies.put(familyId, clock.instant().plus(revokedRetention));
  }

  /** @return whether {@code familyId} is revoked and still within its retention (test/diagnostic aid). */
  public synchronized boolean isRevoked(String familyId) {
    return isRevokedNow(familyId);
  }

  private boolean isRevokedNow(String familyId) {
    expireRevoked();
    return revokedFamilies.containsKey(familyId);
  }

  /** Forgets revoked ids whose retention has passed; insertion order makes this a prefix scan. */
  private void expireRevoked() {
    Instant now = clock.instant();
    Iterator<Map.Entry<String, Instant>> it = revokedFamilies.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<String, Instant> entry = it.next();
      if (entry.getValue().isAfter(now)) {
        break;
      }
      it.remove();
    }
  }
}
