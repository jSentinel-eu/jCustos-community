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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Persistent store for {@link RememberMeTokenRecord}s — backs the
 * planned "remember me" / persistent-login flow (V00.70 Phase 7).
 * <p>
 * Tokens are looked up by their <strong>hash</strong>: an auth flow
 * receives the plain token from a client cookie, hashes it, and
 * queries this store. The plain value never enters the store, so
 * an attacker who exfiltrates the store cannot impersonate the
 * subject.
 *
 * <h2>Rotation (JS-SEC-128, CWE-613)</h2>
 * <p>{@link StoreBackedRememberMeService#rotate} replaces a token on every
 * use. Two operations were added for it in 00.84.00 as default methods:
 * {@link #markRotated} claims the presented token, and {@link #findRotated}
 * answers whether a hash that is no longer live was consumed by a rotation —
 * the signal that a consumed token is being presented again. The defaults
 * keep existing implementations working: rotation itself works with any
 * store, but a store that keeps the default of {@link #findRotated} cannot
 * recognise a replayed token. The shipped in-memory store implements both.</p>
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
public interface RememberMeTokenStore {

  /**
   * Looks up a token record by its hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return the record, if present
   */
  Optional<RememberMeTokenRecord> findByHash(String tokenHash);

  /**
   * Persists or replaces the supplied token record (keyed on
   * {@link RememberMeTokenRecord#tokenHash()}).
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(RememberMeTokenRecord record);

  /**
   * Removes the record for the given hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return {@code true} if a record was removed,
   *         {@code false} when no such token existed
   */
  boolean deleteByHash(String tokenHash);

  /**
   * Atomically retires the live record under {@code tokenHash} because its
   * token was exchanged for a successor, and remembers — until the record's
   * expiry — that this hash was consumed by a rotation.
   *
   * <p>Of several concurrent calls for the same hash exactly one returns
   * {@code true}; that caller issues the successor. A hash removed by
   * {@link #deleteByHash}, {@link #deleteBySubject} or {@link #purgeExpired}
   * leaves no trail.</p>
   *
   * <p>The default claims through {@link #deleteByHash} and keeps no trail.</p>
   *
   * @param tokenHash hash of the presented token; non-blank
   * @param at        rotation instant; non-null
   * @return {@code true} when this call retired a live record
   * @since 00.84.00
   */
  default boolean markRotated(String tokenHash, Instant at) {
    Objects.requireNonNull(at, "at must not be null");
    return deleteByHash(tokenHash);
  }

  /**
   * Looks up the trail {@link #markRotated} left for {@code tokenHash}.
   *
   * <p>The default returns empty: the store keeps no trail, and a token
   * that was rotated away is indistinguishable from one that never
   * existed.</p>
   *
   * @param tokenHash token hash; non-blank
   * @return the consumed record and the instant of its rotation, if known
   * @since 00.84.00
   */
  default Optional<RotatedToken> findRotated(String tokenHash) {
    return Optional.empty();
  }

  /**
   * Trail of a token that was consumed by a rotation.
   *
   * @param record    the record as it was when it was retired; carries the
   *                  hash only, never the plain token
   * @param rotatedAt the instant of the rotation
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  record RotatedToken(RememberMeTokenRecord record, Instant rotatedAt) {

    /** Validates the components. */
    public RotatedToken {
      Objects.requireNonNull(record, "record must not be null");
      Objects.requireNonNull(rotatedAt, "rotatedAt must not be null");
    }
  }

  /**
   * Drops every token issued to {@code subjectId} within
   * {@code tenant}. Used by "log out everywhere" flows.
   *
   * @param tenant    tenant scope; must not be {@code null}
   * @param subjectId subject; must not be {@code null}
   * @return number of records removed
   */
  int deleteBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Drops every token whose {@code expiresAt} is at or before
   * {@code now}. Idempotent.
   *
   * @param now retention boundary; must not be {@code null}
   * @return number of records purged
   */
  int purgeExpired(Instant now);
}
