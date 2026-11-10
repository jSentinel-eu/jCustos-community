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

import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.RefreshTokenScope;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link RefreshTokenStore}.
 *
 * <p>Every mutation runs under the storage write lock, so the multi-record
 * operations of JS-SEC-129 — {@link #rotate}, {@link #saveUnlessInvalidated}
 * and the marking {@link #deleteBySubject(TenantId, SubjectId, Instant)} — are
 * atomic against each other and against {@link #markRevoked}.</p>
 */
final class EclipseStoreRefreshTokenStore implements RefreshTokenStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreRefreshTokenStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<RefreshTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().refreshTokens.get(tokenHash));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void save(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.lock().writeLock().lock();
    try {
      storage.root().refreshTokens.put(record.tokenHash(), record);
      storage.manager().store(storage.root().refreshTokens);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean saveUnlessInvalidated(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.lock().writeLock().lock();
    try {
      if (isInvalidated(record)) {
        return false;
      }
      storage.root().refreshTokens.put(record.tokenHash(), record);
      storage.manager().store(storage.root().refreshTokens);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
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
    // store call. The claim judges the record as it is now — a revoke, a
    // rotation, the expiry or a subject-wide deletion in the meantime refuse it.
    storage.lock().writeLock().lock();
    try {
      RefreshTokenRecord prev = storage.root().refreshTokens.get(oldHash);
      if (prev == null || !prev.isActive(now) || isInvalidated(successor)) {
        return false;
      }
      storage.root().refreshTokens.put(oldHash, prev.withReplacedBy(successor.tokenHash()));
      storage.root().refreshTokens.put(successor.tokenHash(), successor);
      storage.manager().store(storage.root().refreshTokens);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  /** Caller holds the write lock. */
  private boolean isInvalidated(RefreshTokenRecord record) {
    Map<RefreshTokenScope, Instant> marks = storage.root().refreshTokenInvalidBefore;
    if (marks == null) {
      return false; // root stored before 00.84.00 and never revoked wholesale since
    }
    Instant mark = marks.get(scope(record.tenant(), record.subjectId()));
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
    storage.lock().writeLock().lock();
    try {
      RefreshTokenRecord prev = storage.root().refreshTokens.get(oldHash);
      if (prev == null || prev.isReplaced()) {
        return false;
      }
      storage.root().refreshTokens.put(oldHash, prev.withReplacedBy(newHash));
      storage.manager().store(storage.root().refreshTokens);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean markRevoked(String tokenHash, Instant at) {
    requireNonBlank(tokenHash);
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      RefreshTokenRecord prev = storage.root().refreshTokens.get(tokenHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      storage.root().refreshTokens.put(tokenHash, prev.withRevokedAt(at));
      storage.manager().store(storage.root().refreshTokens);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    storage.lock().writeLock().lock();
    try {
      int before = storage.root().refreshTokens.size();
      storage.root().refreshTokens.values().removeIf(record ->
          record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
      int removed = before - storage.root().refreshTokens.size();
      if (removed > 0) {
        storage.manager().store(storage.root().refreshTokens);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(invalidBefore, "invalidBefore must not be null");
    // JS-SEC-129 (CWE-613): deletion and "invalid before" mark under the same
    // write lock as rotate and saveUnlessInvalidated; the mark is persisted so
    // that it also holds across a restart.
    storage.lock().writeLock().lock();
    try {
      EclipseStoreJCustosRoot root = storage.root();
      if (root.refreshTokenInvalidBefore == null) {
        // Root written by a version before 00.84.00: create the map and attach
        // it to the root before it is used.
        root.refreshTokenInvalidBefore = new LinkedHashMap<>();
        storage.manager().store(root);
      }
      RefreshTokenScope key = scope(tenant, subjectId);
      Instant known = root.refreshTokenInvalidBefore.get(key);
      if (known == null || invalidBefore.isAfter(known)) {
        root.refreshTokenInvalidBefore.put(key, invalidBefore);
        storage.manager().store(root.refreshTokenInvalidBefore);
      }
      int before = root.refreshTokens.size();
      root.refreshTokens.values().removeIf(record ->
          record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
      int removed = before - root.refreshTokens.size();
      if (removed > 0) {
        storage.manager().store(root.refreshTokens);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    storage.lock().writeLock().lock();
    try {
      int before = storage.root().refreshTokens.size();
      storage.root().refreshTokens.values().removeIf(record -> record.isExpired(now));
      int removed = before - storage.root().refreshTokens.size();
      if (removed > 0) {
        storage.manager().store(storage.root().refreshTokens);
      }
      return removed;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("oldHash must not be blank");
    }
  }
}
