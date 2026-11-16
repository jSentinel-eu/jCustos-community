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
    storage.update(() -> {
      StoredTable<String, RememberMeTokenRecord> tokens = storage.tables().rememberMeTokens;
      int evicted = tokens.makeRoomFor(record.tokenHash(), storage.maxEntries(), storage.now());
      if (evicted > 0 && tokens.evictionLogDue()) {
        logger().warn("persistence/remember-me-store-capacity: the remember-me store is at its"
            + " bound of {} live tokens; the oldest token is dropped for every new one",
            storage.maxEntries());
      }
      tokens.put(record.tokenHash(), record);
    });
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
      StoredTable<String, RotatedToken> rotated = storage.tables().rememberMeRotated;
      int evicted = rotated.makeRoomFor(tokenHash, storage.maxEntries(), storage.now());
      if (evicted > 0 && rotated.evictionLogDue()) {
        logger().warn("persistence/remember-me-trail-capacity: the trail of rotated remember-me"
            + " tokens is at its bound of {} entries; the oldest trail is dropped for every"
            + " rotation, a replay of that token is then refused without being recognised",
            storage.maxEntries());
      }
      rotated.put(tokenHash, new RotatedToken(live, at));
      return true;
    });
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
    return storage.write(() -> {
      int removed = storage.tables().rememberMeTokens.removeIf((hash, record) ->
          record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
      storage.tables().rememberMeRotated.removeIf((hash, trail) ->
          trail.record().tenant().equals(tenant) && trail.record().subjectId().equals(subjectId));
      return removed;
    });
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
