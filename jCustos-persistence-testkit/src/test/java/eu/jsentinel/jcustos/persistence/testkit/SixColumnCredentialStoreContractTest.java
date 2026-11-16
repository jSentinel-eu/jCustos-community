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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Runs {@link CredentialStoreContract} against a store written to the SPI of
 * the releases before 00.84.00: it keeps six columns per credential and
 * inherits {@code replaceSecretIfCurrent}, {@code updateStatusIfUnchanged} and
 * {@code recordsSecretRotation} from the defaults. It opts out of the
 * rotation-proof tests ({@link #implementsRotationProof()}), which proves that
 * the base contract does not demand more than such a store delivers and that
 * the opt-out skips exactly the JS-SEC-161 tests.
 */
class SixColumnCredentialStoreContractTest implements CredentialStoreContract {

  @Override
  public CredentialStore newStore(CredentialRecord... rows) {
    SixColumnStore store = new SixColumnStore();
    for (CredentialRecord row : rows) {
      store.rows.put(row.username(), SixColumnStore.sixColumns(row));
    }
    return store;
  }

  @Override
  public boolean implementsRotationProof() {
    return false;
  }

  @Test
  @DisplayName("the defaults keep no proof: the store says so and a new secret records nothing")
  void defaultsKeepNoProof() {
    CredentialStore store = newStore(row("alice", CredentialStatus.MUST_CHANGE));
    assertFalse(store.recordsSecretRotation(), "the gap the opt-out documents");
    store.replaceSecretIfCurrent("alice", "encoded-alice-v0", "encoded-alice-v1", T1);
    assertNull(store.findByUsername("alice").orElseThrow().secretChangedAt());
  }

  private static final class SixColumnStore implements CredentialStore {

    private final ConcurrentHashMap<String, CredentialRecord> rows = new ConcurrentHashMap<>();

    static CredentialRecord sixColumns(CredentialRecord record) {
      return new CredentialRecord(record.username(), record.encodedHash(), record.status(),
          record.version(), record.createdAt(), record.updatedAt());
    }

    @Override
    public Optional<CredentialRecord> findByUsername(String username) {
      return Optional.ofNullable(rows.get(requireNonNull(username, "username")));
    }

    @Override
    public synchronized CredentialUpdateResult updateHashIfCurrent(
        String username, String expected, String next, Instant when) {
      CredentialRecord current = rows.get(username);
      if (current == null) {
        return CredentialUpdateResult.NotFound.INSTANCE;
      }
      if (!current.encodedHash().equals(expected)) {
        return CredentialUpdateResult.Stale.INSTANCE;
      }
      CredentialRecord updated = sixColumns(current.withHash(next, when));
      rows.put(username, updated);
      return new CredentialUpdateResult.Updated(updated);
    }

    @Override
    public synchronized CredentialUpdateResult updateStatusIfCurrent(
        String username, CredentialStatus expected, CredentialStatus next, Instant when) {
      CredentialRecord current = rows.get(username);
      if (current == null) {
        return CredentialUpdateResult.NotFound.INSTANCE;
      }
      if (current.status() != expected) {
        return CredentialUpdateResult.Stale.INSTANCE;
      }
      CredentialRecord updated = sixColumns(current.withStatus(next, when));
      rows.put(username, updated);
      return new CredentialUpdateResult.Updated(updated);
    }
  }
}
