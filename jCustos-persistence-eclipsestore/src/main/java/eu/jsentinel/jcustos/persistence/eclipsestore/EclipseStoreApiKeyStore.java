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

import eu.jsentinel.jcustos.authentication.ApiKeyRecord;
import eu.jsentinel.jcustos.authentication.ApiKeyStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link ApiKeyStore}. Keys are issued by an
 * authenticated action, not by a request of an anonymous caller, so the
 * store is not bounded; {@link #purgeExpired(Instant)} retires expired keys.
 * {@link #markUsed} writes the record's slot only (JS-SEC-125).
 */
final class EclipseStoreApiKeyStore implements ApiKeyStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreApiKeyStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<ApiKeyRecord> findByHash(String keyHash) {
    requireNonBlank(keyHash);
    return storage.read(() -> Optional.ofNullable(storage.tables().apiKeys.get(keyHash)));
  }

  @Override
  public void save(ApiKeyRecord record) {
    requireNonNull(record, "record must not be null");
    storage.update(() -> storage.tables().apiKeys.put(record.keyHash(), record));
  }

  @Override
  public List<ApiKeyRecord> listBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    return storage.read(() -> {
      List<ApiKeyRecord> result = new ArrayList<>();
      for (ApiKeyRecord record : storage.tables().apiKeys.values()) {
        if (record.tenant().equals(tenant) && record.subjectId().equals(subjectId)) {
          result.add(record);
        }
      }
      return List.copyOf(result);
    });
  }

  @Override
  public boolean markUsed(String keyHash, Instant at) {
    requireNonBlank(keyHash);
    requireNonNull(at, "at must not be null");
    return storage.write(() -> {
      ApiKeyRecord prev = storage.tables().apiKeys.get(keyHash);
      if (prev == null) {
        return false;
      }
      storage.tables().apiKeys.put(keyHash, prev.withLastUsedAt(at));
      return true;
    });
  }

  @Override
  public boolean revoke(String keyHash, Instant at) {
    requireNonBlank(keyHash);
    requireNonNull(at, "at must not be null");
    return storage.write(() -> {
      ApiKeyRecord prev = storage.tables().apiKeys.get(keyHash);
      if (prev == null || prev.isRevoked()) {
        return false;
      }
      storage.tables().apiKeys.put(keyHash, prev.withRevokedAt(at));
      return true;
    });
  }

  @Override
  public boolean deleteByHash(String keyHash) {
    requireNonBlank(keyHash);
    return storage.write(() -> storage.tables().apiKeys.remove(keyHash) != null);
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return storage.write(() ->
        storage.tables().apiKeys.removeIf((hash, record) -> record.isExpired(now)));
  }

  private static void requireNonBlank(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("keyHash must not be blank");
    }
  }
}
