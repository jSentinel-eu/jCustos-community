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

import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-129: the table of remember-me "invalid before" marks was added to the stored layout
 * after storages had been written in it. A storage written by 00.84.00 before the table existed
 * opens, keeps its remember-me tokens and receives the table on first open; a mark written
 * afterwards survives a restart. The storage is a test resource written with the classes of
 * commit 4ad59859.
 */
@DisplayName("JS-SEC-129 — a storage written before the remember-me marks receives them")
class RememberMeMarkLayoutCompatibilityTest {

  private static final Instant T0 = LegacyStorageFixtures.T0;
  private static final SubjectId ALICE = new SubjectId("alice");

  @TempDir
  Path tempDir;

  @Test
  @DisplayName("the storage opens, keeps its tokens, and a mark written now survives a restart")
  void marksTableIsCreatedAndPersisted() throws Exception {
    LegacyStorageFixtures.copyTo(LegacyStorageFixtures.WRITTEN_BY_00_84_00_BEFORE_REMEMBER_ME_MARKS,
        tempDir);
    Instant revokedAt = T0.plusSeconds(100);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertNotNull(storage.tables().rememberMeInvalidBefore, "created for the earlier layout");
      assertEquals(0, storage.tables().rememberMeInvalidBefore.size());
      RememberMeTokenStore rememberMe = storage.rememberMeTokenStore();
      assertTrue(rememberMe.findByHash("rm-hash-alice").isPresent());
      assertTrue(rememberMe.findByHash("rm-hash-bob").isPresent());
      assertEquals(T0.plusSeconds(80), storage.tables().refreshTokenInvalidBefore
          .get(new EclipseStoreJCustosRoot.RefreshTokenScope("acme", "bob")),
          "the refresh-token mark of the fixture is untouched");

      assertEquals(1, rememberMe.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt));
    }

    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RememberMeTokenStore rememberMe = reopened.rememberMeTokenStore();
      assertEquals(revokedAt, reopened.tables().rememberMeInvalidBefore
          .get(new EclipseStoreJCustosRoot.RememberMeTokenScope("default", "alice")));
      assertFalse(rememberMe.saveUnlessInvalidated(new RememberMeTokenRecord("older",
          TenantId.DEFAULT, ALICE, revokedAt.minusSeconds(1), revokedAt.plusSeconds(3_600))),
          "the mark refuses an overtaken token after the restart");
      assertTrue(rememberMe.saveUnlessInvalidated(new RememberMeTokenRecord("newer",
          TenantId.DEFAULT, ALICE, revokedAt.plusSeconds(1), revokedAt.plusSeconds(3_600))));
      assertTrue(rememberMe.findByHash("rm-hash-bob").isPresent());
    }
  }
}
