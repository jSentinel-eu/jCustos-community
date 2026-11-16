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
 */
final class EclipseStoreRefreshTokenStore implements RefreshTokenStore, HasLogger {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreRefreshTokenStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
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
    int evicted = tokens.makeRoomFor(record.tokenHash(), storage.maxEntries(), storage.now());
    if (evicted > 0 && tokens.evictionLogDue()) {
      logger().warn("persistence/refresh-token-store-capacity: the refresh-token store is at its"
          + " bound of {} records; the oldest record is dropped for every new token",
          storage.maxEntries());
    }
    tokens.put(record.tokenHash(), record);
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
