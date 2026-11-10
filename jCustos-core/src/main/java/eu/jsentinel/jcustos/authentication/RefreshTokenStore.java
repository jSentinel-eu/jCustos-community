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
 * Persistent store for {@link RefreshTokenRecord}s — backs the
 * planned rotating-refresh-token flow (V00.70 Phase 7b).
 * <p>
 * Hash-only lookups. A rotation is one call of
 * {@link #rotate(String, RefreshTokenRecord, Instant)}, which claims
 * the consumed record and stores its successor in one step.
 * Replayed/already-rotated tokens are detected by inspecting
 * {@link RefreshTokenRecord#replacedByHash()} at validation time;
 * {@link TokenService} revokes the chain.
 *
 * <h2>Atomicity (JS-SEC-129, CWE-367, CWE-613)</h2>
 * <p>Three operations were added in 00.84.00 as default methods:
 * {@link #rotate}, {@link #saveUnlessInvalidated} and
 * {@link #deleteBySubject(TenantId, SubjectId, Instant)}. Their defaults
 * are built from the older single-record operations and keep the
 * behaviour — and the races — of the releases before: a revocation that
 * lands between the claim and the storing of the successor is lost. The
 * shipped stores override all three with one critical section each.
 * <strong>A store that keeps the defaults should override them</strong>;
 * the defaults exist so that such a store still compiles and works, not
 * because they are sufficient.</p>
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
public interface RefreshTokenStore {

  /**
   * Looks up a record by its hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return the record, if present
   */
  Optional<RefreshTokenRecord> findByHash(String tokenHash);

  /**
   * Persists or replaces the supplied record. Keyed on
   * {@link RefreshTokenRecord#tokenHash()}.
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(RefreshTokenRecord record);

  /**
   * Links {@code oldHash} as replaced by {@code newHash} at {@code at}.
   * No-op when {@code oldHash} already carries a successor.
   *
   * @param oldHash hash of the consumed token; non-blank
   * @param newHash hash of the successor; non-blank
   * @param at      rotation instant; non-null (recorded as the
   *                consumed record's {@code revokedAt} is left
   *                untouched — replacement is tracked through
   *                {@code replacedByHash} only)
   * @return {@code true} if the link was set on a record that
   *         previously had no successor; {@code false} otherwise
   */
  boolean markReplaced(String oldHash, String newHash, Instant at);

  /**
   * Rotates a token: claims the record under {@code oldHash} and stores
   * {@code successor}, as one atomic step (JS-SEC-129, CWE-367).
   *
   * <p>The claim succeeds only when, at the moment of the call, the old
   * record exists and is neither replaced nor revoked nor expired at
   * {@code now}, and {@code successor} is not older than the subject's
   * invalidation mark (see {@link #deleteBySubject(TenantId, SubjectId, Instant)}).
   * On success the old record carries
   * {@code replacedByHash = successor.tokenHash()} and the successor is
   * stored; no other thread can observe one without the other. On refusal
   * nothing is changed and the successor is not stored.</p>
   *
   * <p><strong>The default is not atomic.</strong> It calls
   * {@link #markReplaced}, re-reads the old record and stores the successor
   * with {@link #save}. It refuses a record that was revoked or had expired
   * before the claim, but a {@link #markRevoked} or {@link #deleteBySubject}
   * that lands between its claim and its save is lost — the behaviour before
   * 00.84.00. It is kept so that existing implementations continue to work
   * and is deprecated as an implementation: override this method.</p>
   *
   * @param oldHash   hash of the presented token; non-blank
   * @param successor the record that replaces it; non-null, with a hash
   *                  different from {@code oldHash}
   * @param now       reference instant for the expiry check; non-null
   * @return {@code true} when this call claimed the old record and stored
   *     the successor
   * @since 00.84.00
   */
  default boolean rotate(String oldHash, RefreshTokenRecord successor, Instant now) {
    Objects.requireNonNull(successor, "successor must not be null");
    Objects.requireNonNull(now, "now must not be null");
    if (!markReplaced(oldHash, successor.tokenHash(), now)) {
      return false;
    }
    Optional<RefreshTokenRecord> claimed = findByHash(oldHash);
    if (claimed.isEmpty() || claimed.get().isRevoked() || claimed.get().isExpired(now)) {
      // Revoked, expired or deleted before the claim: the claim spent a dead
      // token; do not give it a successor.
      return false;
    }
    save(successor);
    return true;
  }

  /**
   * Stores {@code record} unless the subject's tokens were invalidated at a
   * later instant than the record was created (JS-SEC-129, CWE-613).
   *
   * <p>{@link #deleteBySubject(TenantId, SubjectId, Instant)} leaves an
   * "invalid before" mark for the subject. A record whose
   * {@link RefreshTokenRecord#createdAt()} lies before that mark belongs to
   * an operation that started before the revocation and is refused; a record
   * created at or after the mark is stored. Check and store are one atomic
   * step.</p>
   *
   * <p>The default stores unconditionally and returns {@code true} — a store
   * that keeps it has no mark and behaves as before 00.84.00.</p>
   *
   * @param record record to persist; non-null
   * @return {@code true} when the record was stored, {@code false} when the
   *     subject's invalidation mark refused it
   * @since 00.84.00
   */
  default boolean saveUnlessInvalidated(RefreshTokenRecord record) {
    save(record);
    return true;
  }

  /**
   * Marks the record for {@code tokenHash} revoked at {@code at}.
   * No-op when the record is already revoked.
   *
   * @param tokenHash token hash; non-blank
   * @param at        revocation instant; non-null
   * @return {@code true} if a not-yet-revoked record was marked
   */
  boolean markRevoked(String tokenHash, Instant at);

  /**
   * Drops every token (active, replaced or revoked) issued to
   * {@code subjectId} within {@code tenant}.
   *
   * @param tenant    tenant scope; non-null
   * @param subjectId subject; non-null
   * @return number of records removed
   */
  int deleteBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Drops every token of {@code subjectId} within {@code tenant} and marks
   * the subject's tokens "invalid before {@code invalidBefore}"
   * (JS-SEC-129, CWE-613): {@link #rotate} and
   * {@link #saveUnlessInvalidated} refuse a record created before that
   * instant, so that an operation which read its clock before the
   * revocation cannot store a token after it. Deletion and mark are one
   * atomic step; a later mark replaces an earlier one, an earlier one is
   * ignored. The mark survives a restart in a persistent store.
   *
   * <p>The default deletes without leaving a mark, which is the behaviour
   * before 00.84.00.</p>
   *
   * @param tenant        tenant scope; non-null
   * @param subjectId     subject; non-null
   * @param invalidBefore the revocation instant; non-null
   * @return number of records removed
   * @since 00.84.00
   */
  default int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
    Objects.requireNonNull(invalidBefore, "invalidBefore must not be null");
    return deleteBySubject(tenant, subjectId);
  }

  /**
   * Drops every record whose {@link RefreshTokenRecord#expiresAt()}
   * is at or before {@code now}.
   *
   * @param now retention boundary; non-null
   * @return number of records purged
   */
  int purgeExpired(Instant now);
}
