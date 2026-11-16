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
import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.RememberMeTokenScope;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link RememberMeTokenStore}.
 *
 * <h2>Rotation trail (JS-SEC-128, CWE-613, CWE-294)</h2>
 * <p>{@link #markRotated} retires the live record and leaves a trail under
 * the same hash, in one step under the storage's write lock and in one
 * transaction, so that of several presentations of one token exactly one
 * obtains the successor. {@link #findRotated} answers from that trail; it is
 * persisted, so a token that was exchanged before a restart is still
 * recognised as replayed after it. A trail lives until the consumed record
 * would have expired, goes with the subject's tokens in
 * {@link #deleteBySubject}, and is dropped by {@link #purgeExpired}.</p>
 *
 * <h2>Atomic rotation and revocation (JS-SEC-129, CWE-367, CWE-613)</h2>
 * <p>{@link #rotate} claims the live record, leaves its trail and stores the
 * successor under one write lock and in one transaction;
 * {@link #deleteBySubject(TenantId, SubjectId, Instant)} leaves a persisted
 * "invalid before" mark for the subject, which {@link #rotate} and
 * {@link #saveUnlessInvalidated} respect. A revocation can no longer land
 * between the claim and the successor and be undone by it. The marks are one
 * entry per subject that was ever revoked wholesale and are not bounded, like
 * those of the refresh-token store.</p>
 *
 * <h2>Bounds (JS-SEC-125, CWE-770)</h2>
 * <p>Live records and trails are two tables of at most
 * {@link EclipseStoreJCustosStorage#maxEntries()} entries each. At the bound
 * expired entries go first; if none is expired the entry stored first is
 * dropped. A dropped live record means that its holder has to log in again;
 * a dropped trail means that a replay of that one token is refused as
 * unknown instead of being recognised as a replay.</p>
 */
final class EclipseStoreRememberMeTokenStore implements RememberMeTokenStore, HasLogger {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreRememberMeTokenStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    return storage.read(() -> Optional.ofNullable(storage.tables().rememberMeTokens.get(tokenHash)));
  }

  @Override
  public void save(RememberMeTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.update(() -> putLive(record));
  }

  @Override
  public boolean saveUnlessInvalidated(RememberMeTokenRecord record) {
    requireNonNull(record, "record must not be null");
    return storage.write(() -> {
      if (isInvalidated(record)) {
        return false;
      }
      putLive(record);
      return true;
    });
  }

  /** Caller holds the write lock. Stores a live record, making room at the bound. */
  private void putLive(RememberMeTokenRecord record) {
    StoredTable<String, RememberMeTokenRecord> tokens = storage.tables().rememberMeTokens;
    int evicted = tokens.makeRoomFor(record.tokenHash(), storage.maxEntries(), storage.now());
    if (evicted > 0 && tokens.evictionLogDue()) {
      logger().warn("persistence/remember-me-store-capacity: the remember-me store is at its"
          + " bound of {} live tokens; the oldest token is dropped for every new one",
          storage.maxEntries());
    }
    tokens.put(record.tokenHash(), record);
  }

  @Override
  public boolean deleteByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    return storage.write(() -> storage.tables().rememberMeTokens.remove(tokenHash) != null);
  }

  @Override
  public boolean markRotated(String tokenHash, Instant at) {
    requireNonBlank(tokenHash);
    requireNonNull(at, "at must not be null");
    // JS-SEC-128: claim and trail under one write lock and in one transaction. Whoever
    // presents the token second finds no live record and, through findRotated, the trail.
    return storage.write(() -> {
      RememberMeTokenRecord live = storage.tables().rememberMeTokens.remove(tokenHash);
      if (live == null) {
        return false;
      }
      putTrail(tokenHash, new RotatedToken(live, at));
      return true;
    });
  }

  @Override
  public boolean rotate(String oldHash, RememberMeTokenRecord successor, Instant now) {
    requireNonBlank(oldHash);
    requireNonNull(successor, "successor must not be null");
    requireNonNull(now, "now must not be null");
    if (oldHash.equals(successor.tokenHash())) {
      throw new IllegalArgumentException("successor must not reuse the old hash");
    }
    // JS-SEC-129 (CWE-367, CWE-613): claim, trail and successor under one write lock and in
    // one transaction. A revocation in the meantime - the token gone, or a mark younger than
    // the successor - refuses the claim; one that follows removes the successor.
    return storage.write(() -> {
      StoredTable<String, RememberMeTokenRecord> tokens = storage.tables().rememberMeTokens;
      RememberMeTokenRecord live = tokens.get(oldHash);
      if (live == null || live.isExpired(now) || isInvalidated(successor)) {
        return false;
      }
      tokens.remove(oldHash);
      putTrail(oldHash, new RotatedToken(live, now));
      putLive(successor);
      return true;
    });
  }

  /** Caller holds the write lock. Stores a trail, making room at the bound. */
  private void putTrail(String tokenHash, RotatedToken trail) {
    StoredTable<String, RotatedToken> rotated = storage.tables().rememberMeRotated;
    int evicted = rotated.makeRoomFor(tokenHash, storage.maxEntries(), storage.now());
    if (evicted > 0 && rotated.evictionLogDue()) {
      logger().warn("persistence/remember-me-trail-capacity: the trail of rotated remember-me"
          + " tokens is at its bound of {} entries; the oldest trail is dropped for every"
          + " rotation, a replay of that token is then refused without being recognised",
          storage.maxEntries());
    }
    rotated.put(tokenHash, trail);
  }

  /** Caller holds the write lock. */
  private boolean isInvalidated(RememberMeTokenRecord record) {
    Instant mark = storage.tables().rememberMeInvalidBefore
        .get(scope(record.tenant(), record.subjectId()));
    return mark != null && record.createdAt().isBefore(mark);
  }

  private static RememberMeTokenScope scope(TenantId tenant, SubjectId subjectId) {
    return new RememberMeTokenScope(tenant.value(), subjectId.value());
  }

  @Override
  public Optional<RotatedToken> findRotated(String tokenHash) {
    requireNonBlank(tokenHash);
    return storage.read(() -> Optional.ofNullable(storage.tables().rememberMeRotated.get(tokenHash)));
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    return storage.write(() -> removeSubject(tenant, subjectId));
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(invalidBefore, "invalidBefore must not be null");
    // JS-SEC-129 (CWE-613): deletion and "invalid before" mark under the same write lock as
    // rotate and saveUnlessInvalidated; the mark is persisted, so it holds across a restart.
    return storage.write(() -> {
      StoredTable<RememberMeTokenScope, Instant> marks = storage.tables().rememberMeInvalidBefore;
      RememberMeTokenScope key = scope(tenant, subjectId);
      Instant known = marks.get(key);
      if (known == null || invalidBefore.isAfter(known)) {
        marks.put(key, invalidBefore);
      }
      return removeSubject(tenant, subjectId);
    });
  }

  /** Caller holds the write lock. */
  private int removeSubject(TenantId tenant, SubjectId subjectId) {
    int removed = storage.tables().rememberMeTokens.removeIf((hash, record) ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
    storage.tables().rememberMeRotated.removeIf((hash, trail) ->
        trail.record().tenant().equals(tenant) && trail.record().subjectId().equals(subjectId));
    return removed;
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return storage.write(() -> {
      int removed = storage.tables().rememberMeTokens
          .removeIf((hash, record) -> record.isExpired(now));
      storage.tables().rememberMeRotated
          .removeIf((hash, trail) -> trail.record().isExpired(now));
      return removed;
    });
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("tokenHash must not be blank");
    }
  }
}
