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

import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore;
import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore.PresentedHash;
import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore.RotationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Runs {@link RefreshTokenFamilyStoreContract} against a store that implements only
 * the four methods of the releases before 00.84.10 and inherits
 * {@link RefreshTokenFamilyStore#classify} from the SPI default. It opts out of the
 * issued-hash history tests ({@link #implementsIssuedHashHistory()}), which proves
 * that the base contract does not demand more than the default delivers and that the
 * opt-out skips exactly the R9 tests.
 */
class DefaultsOnlyRefreshTokenFamilyStoreContractTest implements RefreshTokenFamilyStoreContract {

  @Override
  public RefreshTokenFamilyStore newStore() {
    return new DefaultsOnlyStore();
  }

  @Override
  public boolean implementsIssuedHashHistory() {
    return false;
  }

  @Test
  @DisplayName("the default classifies every hash as UNDETERMINED: the gap the opt-out documents")
  void defaultIsUndetermined() {
    RefreshTokenFamilyStore store = newStore();
    issueAndRotate(store, 1);
    assertEquals(PresentedHash.UNDETERMINED, store.classify(FAMILY, hash("t1")));
    assertEquals(PresentedHash.UNDETERMINED, store.classify(FAMILY, hash("t0")));
    assertEquals(PresentedHash.UNDETERMINED, store.classify(FAMILY, hash("made-up")));
    assertEquals(RotationResult.ROTATED, store.detectReuse(FAMILY, hash("t1")));
  }

  /** The family store as an implementer wrote it before 00.84.10. */
  private static final class DefaultsOnlyStore implements RefreshTokenFamilyStore {

    private final Map<String, String> current = new HashMap<>();
    private final Set<String> revoked = new HashSet<>();

    @Override
    public synchronized void recordIssued(String familyId, String tokenHash) {
      Objects.requireNonNull(tokenHash, "tokenHash");
      revoked.remove(Objects.requireNonNull(familyId, "familyId"));
      current.put(familyId, tokenHash);
    }

    @Override
    public synchronized RotationResult consumeAndRotate(String familyId, String presentedHash,
                                                        String newHash) {
      Objects.requireNonNull(newHash, "newHash");
      if (detectReuse(familyId, presentedHash) == RotationResult.REUSE_DETECTED) {
        return RotationResult.REUSE_DETECTED;
      }
      current.put(familyId, newHash);
      return RotationResult.ROTATED;
    }

    @Override
    public synchronized RotationResult detectReuse(String familyId, String presentedHash) {
      Objects.requireNonNull(presentedHash, "presentedHash");
      if (!revoked.contains(Objects.requireNonNull(familyId, "familyId"))
          && presentedHash.equals(current.get(familyId))) {
        return RotationResult.ROTATED;
      }
      revokeFamily(familyId);
      return RotationResult.REUSE_DETECTED;
    }

    @Override
    public synchronized void revokeFamily(String familyId) {
      current.remove(Objects.requireNonNull(familyId, "familyId"));
      revoked.add(familyId);
    }
  }
}
