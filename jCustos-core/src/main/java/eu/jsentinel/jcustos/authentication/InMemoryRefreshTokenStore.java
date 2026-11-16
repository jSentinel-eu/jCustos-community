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
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RefreshTokenStore} backed by a
 * {@link ConcurrentHashMap}. Reads are lock-free; every mutation runs
 * under one lock, because a rotation touches two records and a
 * subject-wide revocation touches many — per-key atomicity is not enough
 * to keep a revocation from slipping between the claim of a token and the
 * storing of its successor (JS-SEC-129, CWE-367).
 */
@ExperimentalJCustosApi
public final class InMemoryRefreshTokenStore implements RefreshTokenStore {

  private final ConcurrentHashMap<String, RefreshTokenRecord> tokens =
      new ConcurrentHashMap<>();
  /**
   * (tenant, subject) → instant before which the subject's tokens are invalid
   * (JS-SEC-129). One entry per subject that was ever revoked wholesale, so
   * the map is bounded by the number of subjects.
   */
  private final ConcurrentHashMap<SubjectScope, Instant> invalidBefore =
      new ConcurrentHashMap<>();
  /** Key of the invalidation mark. */
  private record SubjectScope(TenantId tenant, SubjectId subjectId) {
  }

  /** Serialises every mutation; see the class comment. */
  private final ReentrantLock mutation = new ReentrantLock();

  /** Creates an empty store. */
  public InMemoryRefreshTokenStore() {
  }

  @Override
  public Optional<RefreshTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(tokens.get(tokenHash));
  }

  @Override
  public void save(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    mutation.lock();
    try {
      tokens.put(record.tokenHash(), record);
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean saveUnlessInvalidated(RefreshTokenRecord record) {
    requireNonNull(record, "record must not be null");
    mutation.lock();
    try {
      if (isInvalidated(record)) {
        return false;
      }
      tokens.put(record.tokenHash(), record);
      return true;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean rotate(String oldHash, RefreshTokenRecord successor, Instant now) {
    requireNonBlank(oldHash, "oldHash");
    requireNonNull(successor, "successor must not be null");
    requireNonNull(now, "now must not be null");
    if (oldHash.equals(successor.tokenHash())) {
      throw new IllegalArgumentException("successor must not reuse the old hash");
    }
    // JS-SEC-129 (CWE-367): claim and successor in one critical section. The
    // claim looks at the record as it is NOW — revoked, replaced, expired or
    // deleted in the meantime all refuse it.
    mutation.lock();
    try {
      RefreshTokenRecord prev = tokens.get(oldHash);
      if (prev == null || !prev.isActive(now) || isInvalidated(successor)) {
        return false;
      }
      tokens.put(oldHash, prev.withReplacedBy(successor.tokenHash()));
      tokens.put(successor.tokenHash(), successor);
      return true;
    } finally {
      mutation.unlock();
    }
  }

  /**
   * Caller holds {@link #mutation}. A record created at the instant of the mark
   * is not invalidated - see {@link RefreshTokenStore#saveUnlessInvalidated}.
   */
  private boolean isInvalidated(RefreshTokenRecord record) {
    Instant mark = invalidBefore.get(
        new SubjectScope(record.tenant(), record.subjectId()));
    return mark != null && record.createdAt().isBefore(mark);
  }

  @Override
  public boolean markReplaced(String oldHash, String newHash, Instant at) {
    requireNonBlank(oldHash, "oldHash");
    requireNonBlank(newHash, "newHash");
    requireNonNull(at, "at must not be null");
    mutation.lock();
    try {
      RefreshTokenRecord prev = tokens.get(oldHash);
      if (prev == null || prev.isReplaced()) {
        return false;
      }
      tokens.put(oldHash, prev.withReplacedBy(newHash));
      return true;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean markRevoked(String tokenHash, Instant at) {
    requireNonBlank(tokenHash, "tokenHash");
    requireNonNull(at, "at must not be null");
    mutation.lock();
    try {
      RefreshTokenRecord prev = tokens.get(tokenHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      tokens.put(tokenHash, prev.withRevokedAt(at));
      return true;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    mutation.lock();
    try {
      return removeBySubject(tenant, subjectId);
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(invalidBefore, "invalidBefore must not be null");
    // JS-SEC-129 (CWE-613): deletion and mark under the same lock as rotate and
    // saveUnlessInvalidated, so an operation that read its clock earlier cannot
    // store a token for this subject afterwards.
    mutation.lock();
    try {
      this.invalidBefore.merge(new SubjectScope(tenant, subjectId), invalidBefore,
          (known, candidate) -> candidate.isAfter(known) ? candidate : known);
      return removeBySubject(tenant, subjectId);
    } finally {
      mutation.unlock();
    }
  }

  /** Caller holds {@link #mutation}. */
  private int removeBySubject(TenantId tenant, SubjectId subjectId) {
    int before = tokens.size();
    tokens.values().removeIf(record ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
    return before - tokens.size();
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    mutation.lock();
    try {
      int before = tokens.size();
      tokens.values().removeIf(record -> record.isExpired(now));
      return before - tokens.size();
    } finally {
      mutation.unlock();
    }
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
