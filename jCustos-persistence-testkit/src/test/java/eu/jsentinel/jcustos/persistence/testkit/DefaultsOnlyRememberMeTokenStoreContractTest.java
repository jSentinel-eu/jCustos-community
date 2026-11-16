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

import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs {@link RememberMeTokenStoreContract} against a store that implements
 * only the five methods of the releases before 00.84.00 and inherits
 * {@code markRotated} and {@code findRotated} from the SPI defaults. It opts
 * out of the rotation-trail tests ({@link #implementsRotationTrail()}), which
 * proves that the base contract does not demand more than the defaults
 * deliver and that the opt-out skips exactly the JS-SEC-128 tests.
 */
class DefaultsOnlyRememberMeTokenStoreContractTest implements RememberMeTokenStoreContract {

  @Override
  public RememberMeTokenStore newStore() {
    return new DefaultsOnlyStore();
  }

  @Override
  public boolean implementsRotationTrail() {
    return false;
  }

  @Test
  @DisplayName("the defaults rotate without a trail: the claim succeeds once, a replay is unknown")
  void defaultsRotateWithoutTrail() {
    RememberMeTokenStore store = newStore();
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    assertTrue(store.markRotated("h1", T0.plusSeconds(60)));
    assertFalse(store.markRotated("h1", T0.plusSeconds(61)));
    assertTrue(store.findByHash("h1").isEmpty());
    assertTrue(store.findRotated("h1").isEmpty(), "the gap the opt-out documents");
  }

  private static final class DefaultsOnlyStore implements RememberMeTokenStore {

    private final ConcurrentHashMap<String, RememberMeTokenRecord> tokens = new ConcurrentHashMap<>();

    @Override
    public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
      return Optional.ofNullable(tokens.get(requireNonBlank(tokenHash)));
    }

    @Override
    public void save(RememberMeTokenRecord record) {
      requireNonNull(record, "record must not be null");
      tokens.put(record.tokenHash(), record);
    }

    @Override
    public boolean deleteByHash(String tokenHash) {
      return tokens.remove(requireNonBlank(tokenHash)) != null;
    }

    @Override
    public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
      requireNonNull(tenant, "tenant must not be null");
      requireNonNull(subjectId, "subjectId must not be null");
      int before = tokens.size();
      tokens.values().removeIf(record ->
          record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
      return before - tokens.size();
    }

    @Override
    public int purgeExpired(Instant now) {
      requireNonNull(now, "now must not be null");
      int before = tokens.size();
      tokens.values().removeIf(record -> record.isExpired(now));
      return before - tokens.size();
    }

    private static String requireNonBlank(String value) {
      if (value == null || value.isBlank()) {
        throw new IllegalArgumentException("tokenHash must not be blank");
      }
      return value;
    }
  }
}
