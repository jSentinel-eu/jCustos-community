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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Restart-persistence tests for the refresh-token operations of JS-SEC-129
 * (CWE-367, CWE-613): the "invalid before" mark and a rotation must survive a
 * close/reopen, and a root written before 00.84.00 — without the mark map —
 * must keep working.
 */
@DisplayName("EclipseStoreRefreshTokenStore — JS-SEC-129 survives restart")
class EclipseStoreRefreshTokenRevocationRestartTest {

  @TempDir
  Path tempDir;

  private static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");
  private static final Instant EXPIRY = T0.plusSeconds(3600);
  private static final SubjectId ALICE = new SubjectId("alice");

  private static RefreshTokenRecord token(String hash, Instant createdAt) {
    return new RefreshTokenRecord(hash, TenantId.DEFAULT, ALICE, createdAt, EXPIRY,
        Optional.empty(), Optional.empty());
  }

  @Test
  @DisplayName("the invalid-before mark survives a close/reopen")
  void markSurvivesRestart() {
    Instant revokedAt = T0.plusSeconds(100);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RefreshTokenStore store = storage.refreshTokenStore();
      store.save(token("h1", T0));
      assertEquals(1, store.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt));
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RefreshTokenStore store = reopened.refreshTokenStore();
      assertTrue(store.findByHash("h1").isEmpty());
      assertFalse(store.saveUnlessInvalidated(token("older", revokedAt.minusSeconds(1))),
          "a record from before the revocation must still be refused after a restart");
      assertTrue(store.saveUnlessInvalidated(token("newer", revokedAt.plusSeconds(1))));
    }
  }

  @Test
  @DisplayName("a rotation survives a close/reopen: old record linked, successor present")
  void rotationSurvivesRestart() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RefreshTokenStore store = storage.refreshTokenStore();
      store.save(token("h1", T0));
      assertTrue(store.rotate("h1", token("h2", T0.plusSeconds(60)), T0.plusSeconds(60)));
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RefreshTokenStore store = reopened.refreshTokenStore();
      assertEquals(Optional.of("h2"), store.findByHash("h1").orElseThrow().replacedByHash());
      assertTrue(store.findByHash("h2").orElseThrow().isActive(T0.plusSeconds(120)));
      assertFalse(store.rotate("h1", token("h3", T0.plusSeconds(120)), T0.plusSeconds(120)));
    }
  }

  @Test
  @DisplayName("a storage written by 00.83.00 (no mark map in its root) rotates, and keeps the mark of its first revocation")
  void rootWithoutMarkMap() throws Exception {
    // The real thing instead of a simulation: a storage directory the released 00.83.00
    // artefacts wrote. Its root has no refreshTokenInvalidBefore field at all.
    LegacyStorageFixtures.copyTo(LegacyStorageFixtures.WRITTEN_BY_00_83_00, tempDir);
    Instant t0 = LegacyStorageFixtures.T0;
    Instant revokedAt = t0.plusSeconds(1_000);
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RefreshTokenStore store = reopened.refreshTokenStore();
      assertTrue(store.saveUnlessInvalidated(fixtureToken("h0", t0)),
          "no mark on disk: nothing is invalidated");
      assertTrue(store.rotate("rt-hash-2", fixtureToken("rt-hash-3", t0.plusSeconds(120)),
          t0.plusSeconds(120)));
      // rt-hash-1 (replaced), rt-hash-2 (now replaced), rt-hash-3 and h0 belong to alice
      assertEquals(4, store.deleteBySubject(TenantId.DEFAULT, ALICE, revokedAt));
      assertFalse(store.saveUnlessInvalidated(fixtureToken("older", revokedAt.minusSeconds(1))));
    }
    try (EclipseStoreJCustosStorage again = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertFalse(again.refreshTokenStore()
              .saveUnlessInvalidated(fixtureToken("older", revokedAt.minusSeconds(1))),
          "the mark of the first revocation must be on disk");
      assertTrue(again.refreshTokenStore()
          .saveUnlessInvalidated(fixtureToken("newer", revokedAt.plusSeconds(1))));
    }
  }

  private static RefreshTokenRecord fixtureToken(String hash, Instant createdAt) {
    return new RefreshTokenRecord(hash, TenantId.DEFAULT, ALICE, createdAt,
        createdAt.plusSeconds(86_400), Optional.empty(), Optional.empty());
  }
}
