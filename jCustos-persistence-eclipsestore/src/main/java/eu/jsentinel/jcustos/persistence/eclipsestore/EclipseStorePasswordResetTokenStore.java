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

import eu.jsentinel.jcustos.accountlifecycle.InMemoryPasswordResetTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link PasswordResetTokenStore}.
 *
 * <p>JS-SEC-125 (CWE-770): a reset is requested by a caller who is not logged in, so the store is bounded like its in-memory
 * counterpart (JS-SEC-074) — at most
 * {@link EclipseStoreJCustosStorage#maxEntries()} records. At the bound
 * consumed and expired records are dropped; when every record is still open,
 * a further {@link #save} fails with
 * {@code accountlifecycle/password-reset-token-store-capacity-exceeded}. Open tokens are never
 * pushed out by new ones: that would let a flood of requests cancel a link
 * somebody is about to use.</p>
 */
final class EclipseStorePasswordResetTokenStore implements PasswordResetTokenStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStorePasswordResetTokenStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<PasswordResetTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash);
    return storage.read(() -> Optional.ofNullable(storage.tables().passwordResetTokens.get(tokenHash)));
  }

  @Override
  public void save(PasswordResetTokenRecord record) {
    requireNonNull(record, "record must not be null");
    storage.update(() -> {
      StoredTable<String, PasswordResetTokenRecord> tokens = storage.tables().passwordResetTokens;
      if (tokens.size() >= storage.maxEntries() && !tokens.containsKey(record.tokenHash())) {
        tokens.dropDead(storage.now()); // consumed and expired records
        if (tokens.size() >= storage.maxEntries()) {
          throw new IllegalStateException(CapacityBound.capacityExceededCode(
              InMemoryPasswordResetTokenStore.CAPACITY_NAMESPACE) + ": " + storage.maxEntries());
        }
      }
      tokens.put(record.tokenHash(), record);
    });
  }

  @Override
  public boolean markConsumed(String tokenHash, Instant at) {
    requireNonBlank(tokenHash);
    requireNonNull(at, "at must not be null");
    return storage.write(() -> {
      PasswordResetTokenRecord prev = storage.tables().passwordResetTokens.get(tokenHash);
      if (prev == null || prev.isConsumed()) {
        return false;
      }
      storage.tables().passwordResetTokens.put(tokenHash, prev.withConsumedAt(at));
      return true;
    });
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    return storage.write(() -> storage.tables().passwordResetTokens.removeIf((hash, record) ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId)));
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return storage.write(() ->
        storage.tables().passwordResetTokens.removeIf((hash, record) -> record.isExpired(now)));
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("tokenHash must not be blank");
    }
  }
}
