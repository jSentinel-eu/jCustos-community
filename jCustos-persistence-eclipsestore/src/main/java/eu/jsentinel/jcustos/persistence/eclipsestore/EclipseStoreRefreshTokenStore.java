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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.RefreshTokenScope;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link RefreshTokenStore}.
 *
 * <p>Every mutation runs under the storage write lock, so the multi-record
 * operations of JS-SEC-129 — {@link #rotate}, {@link #saveUnlessInvalidated}
 * and the marking {@link #deleteBySubject(TenantId, SubjectId, Instant)} — are
 * atomic against each other and against {@link #markRevoked}; what one
 * operation changes is stored in one transaction.</p>
 *
 * <p>JS-SEC-125 (CWE-770): at most
 * {@link EclipseStoreJCustosStorage#maxEntries()} records, replaced and
 * revoked ones included. At the bound expired records go first; if none is
 * expired the record stored first is dropped — a token whose record is gone
 * is refused as unknown. The "invalid before" marks are one entry per subject
 * that was ever revoked wholesale and are not bounded: a dropped mark would
 * let a token from an overtaken operation through.</p>
 *
 * <h2>Replay anchors at the bound (JS-SEC-129, CWE-294)</h2>
 * <p>A record that was rotated and has not expired is what turns a second
 * presentation of its token into a replay, after which {@code TokenService}
 * revokes the successors. At the bound such a record can be the one stored
 * first: a holder of a stolen token who rotates it some hundred thousand times
 * pushes the owner's rotated record out, and when the owner presents the token
 * again it is merely unknown - the thief's chain survives. Keeping those
 * records instead would let the same loop fill the store and refuse every new
 * sign-in. The store therefore still drops the record, but never silently:
 * every such eviction is counted ({@link #replayAnchorsEvicted()}) and logged
 * as {@code persistence/refresh-token-replay-anchor-evicted} - the first one
 * and then one line per {@value #ANCHOR_EVICTIONS_PER_LOG_LINE}. An
 * installation that sees it raises the bound
 * ({@code EclipseStoreJCustosStorage.openAt(Path, int)}) or shortens the
 * refresh-token lifetime. A token that is unknown because of such an eviction
 * cannot be told apart from one that never existed; its family is not
 * revoked.</p>
 */
final class EclipseStoreRefreshTokenStore implements RefreshTokenStore, HasLogger {

  /** One replay-anchor warning for the first eviction and for every further block of this many. */
  static final long ANCHOR_EVICTIONS_PER_LOG_LINE = 1_000;

  private final EclipseStoreJCustosStorage storage;
  /** Rotated, unexpired records dropped at the bound by this adapter; guarded by the write lock. */
  private long replayAnchorsEvicted;

  EclipseStoreRefreshTokenStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  /**
   * @return how many rotated records that had not yet expired this adapter
   *     dropped to stay within its bound - each of them a token whose replay is
   *     no longer recognised (JS-SEC-129)
   */
  long replayAnchorsEvicted() {
    return storage.read(() -> replayAnchorsEvicted);
  }

  @Override
  public Optional<RefreshTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    return storage.read(() -> Optional.ofNullable(storage.tables().refreshTokens.get(tokenHash)));
  }

  @Override
  public void save(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.update(() -> put(record));
  }

  @Override
  public boolean saveUnlessInvalidated(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    return storage.write(() -> {
      if (isInvalidated(record)) {
        return false;
      }
      put(record);
      return true;
    });
  }

  @Override
  public boolean rotate(String oldHash, RefreshTokenRecord successor, Instant now) {
    requireNonBlank(oldHash);
    requireNonNull(successor, "successor must not be null");
    requireNonNull(now, "now must not be null");
    if (oldHash.equals(successor.tokenHash())) {
      throw new IllegalArgumentException("successor must not reuse the old hash");
    }
    // JS-SEC-129 (CWE-367): claim and successor in one critical section and one
    // transaction. The claim judges the record as it is now — a revoke, a
    // rotation, the expiry or a subject-wide deletion in the meantime refuse it.
    return storage.write(() -> {
      RefreshTokenRecord prev = storage.tables().refreshTokens.get(oldHash);
      if (prev == null || !prev.isActive(now) || isInvalidated(successor)) {
        return false;
      }
      // the claim first: making room for the successor must not find the table
      // one entry larger than it was
      storage.tables().refreshTokens.put(oldHash, prev.withReplacedBy(successor.tokenHash()));
      put(successor);
      return true;
    });
  }

  /** Caller holds the write lock. Stores {@code record}, making room at the bound. */
  private void put(RefreshTokenRecord record) {
    StoredTable<String, RefreshTokenRecord> tokens = storage.tables().refreshTokens;
    Instant now = storage.now();
    noteReplayAnchorsToBeEvicted(tokens, record.tokenHash(), now);
    int evicted = tokens.makeRoomFor(record.tokenHash(), storage.maxEntries(), now);
    if (evicted > 0 && tokens.evictionLogDue()) {
      logger().warn("persistence/refresh-token-store-capacity: the refresh-token store is at its"
          + " bound of {} records; the oldest record is dropped for every new token",
          storage.maxEntries());
    }
    tokens.put(record.tokenHash(), record);
  }

  /**
   * Caller holds the write lock. Looks at what {@link StoredTable#makeRoomFor} is about to
   * evict for {@code incoming} - after the dead records, the records stored first - and counts
   * and reports every rotated record among them that has not expired (JS-SEC-129, CWE-294).
   */
  private void noteReplayAnchorsToBeEvicted(StoredTable<String, RefreshTokenRecord> tokens,
                                            String incoming, Instant now) {
    int maxEntries = storage.maxEntries();
    if (tokens.size() < maxEntries || tokens.containsKey(incoming)) {
      return;
    }
    tokens.dropDead(now); // what makeRoomFor drops first; dead records are no anchors
    int toEvict = tokens.size() - maxEntries + 1;
    if (toEvict <= 0) {
      return;
    }
    // At the bound one record goes per new token; more only after a reopen with a lower bound.
    Iterable<String> heads = toEvict == 1 ? List.of(tokens.eldestKey()) : tokens.keys();
    int anchors = 0;
    int seen = 0;
    for (String hash : heads) {
      if (seen++ >= toEvict) {
        break;
      }
      RefreshTokenRecord victim = tokens.get(hash);
      if (victim != null && victim.isReplaced() && !victim.isExpired(now)) {
        anchors++;
      }
    }
    if (anchors == 0) {
      return;
    }
    long before = replayAnchorsEvicted;
    replayAnchorsEvicted += anchors;
    if (before == 0
        || before / ANCHOR_EVICTIONS_PER_LOG_LINE != replayAnchorsEvicted / ANCHOR_EVICTIONS_PER_LOG_LINE) {
      logger().warn("persistence/refresh-token-replay-anchor-evicted: the refresh-token store is at"
          + " its bound of {} records and dropped a rotated token that has not expired ({} so far);"
          + " a replay of such a token is refused as unknown instead of revoking its successors."
          + " Raise the bound or shorten the refresh-token lifetime.", maxEntries,
          replayAnchorsEvicted);
    }
  }

  /** Caller holds the write lock. */
  private boolean isInvalidated(RefreshTokenRecord record) {
    Instant mark = storage.tables().refreshTokenInvalidBefore
        .get(scope(record.tenant(), record.subjectId()));
    return mark != null && record.createdAt().isBefore(mark);
  }

  private static RefreshTokenScope scope(TenantId tenant, SubjectId subjectId) {
    return new RefreshTokenScope(tenant.value(), subjectId.value());
  }

  @Override
  public boolean markReplaced(String oldHash, String newHash, Instant at) {
    requireNonBlank(oldHash);
    if (newHash == null || newHash.isBlank()) {
      throw new IllegalArgumentException("newHash must not be blank");
    }
    requireNonNull(at, "at must not be null");
    return storage.write(() -> {
      RefreshTokenRecord prev = storage.tables().refreshTokens.get(oldHash);
      if (prev == null || prev.isReplaced()) {
        return false;
      }
      storage.tables().refreshTokens.put(oldHash, prev.withReplacedBy(newHash));
      return true;
    });
  }

  @Override
  public boolean markRevoked(String tokenHash, Instant at) {
    requireNonBlank(tokenHash);
    requireNonNull(at, "at must not be null");
    return storage.write(() -> {
      RefreshTokenRecord prev = storage.tables().refreshTokens.get(tokenHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      storage.tables().refreshTokens.put(tokenHash, prev.withRevokedAt(at));
      return true;
    });
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    return storage.write(() -> removeTokensOf(tenant, subjectId));
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(invalidBefore, "invalidBefore must not be null");
    // JS-SEC-129 (CWE-613): deletion and "invalid before" mark under the same
    // write lock as rotate and saveUnlessInvalidated; the mark is persisted so
    // that it also holds across a restart.
    return storage.write(() -> {
      StoredTable<RefreshTokenScope, Instant> marks = storage.tables().refreshTokenInvalidBefore;
      RefreshTokenScope key = scope(tenant, subjectId);
      Instant known = marks.get(key);
      if (known == null || invalidBefore.isAfter(known)) {
        marks.put(key, invalidBefore);
      }
      return removeTokensOf(tenant, subjectId);
    });
  }

  /** Caller holds the write lock. */
  private int removeTokensOf(TenantId tenant, SubjectId subjectId) {
    return storage.tables().refreshTokens.removeIf((hash, record) ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return storage.write(() ->
        storage.tables().refreshTokens.removeIf((hash, record) -> record.isExpired(now)));
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("oldHash must not be blank");
    }
  }
}
