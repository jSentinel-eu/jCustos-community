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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.lifecycle.InvalidStatusTransitionException;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-161: {@link CredentialRecord} gained two components in 00.84.00. An application that
 * keeps its credential rows in its own Eclipse-Store root still opens a storage written with
 * 00.83.00 - Eclipse Store maps the stored six components by name and leaves the new ones
 * {@code null} - and a row that was COMPROMISED there is not re-enabled without a new secret.
 * The storage is a test resource written with the released 00.83.00 artefacts.
 */
@DisplayName("JS-SEC-161 — credential records written by 00.83.00 load and stay fail-closed")
class LegacyCredentialRecordCompatibilityTest {

  private static final Instant T0 = LegacyStorageFixtures.T0;

  @TempDir
  Path tempDir;

  /** The audit sink of the lifecycle service; this test does not look at it. */
  private static final class Discard implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
      // not needed here
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  @Test
  @DisplayName("the rows load with the new components empty; COMPROMISED needs a rotation, through DISABLED as well")
  void legacyRowsLoadAndStayFailClosed() throws Exception {
    LegacyStorageFixtures.copyTo(LegacyStorageFixtures.CREDENTIAL_RECORDS_WRITTEN_BY_00_83_00,
        tempDir);
    List<CredentialRecord> rows;
    EmbeddedStorageManager manager = EmbeddedStorage.start(tempDir);
    try {
      @SuppressWarnings("unchecked")
      List<CredentialRecord> root = (List<CredentialRecord>) manager.root();
      rows = List.copyOf(root);
    } finally {
      manager.shutdown();
    }

    assertEquals(List.of("compromised", "disabled", "active"),
        rows.stream().map(CredentialRecord::username).toList());
    CredentialRecord compromised = rows.get(0);
    assertEquals(CredentialStatus.COMPROMISED, compromised.status());
    assertEquals(3L, compromised.version());
    assertEquals(T0.plusSeconds(60), compromised.updatedAt());
    assertNull(compromised.secretChangedAt(), "loaded, not constructed: no change time");
    assertNull(compromised.compromisedSince(), "loaded, not constructed: no marker either");
    assertTrue(compromised.secretRotationRequired(), "the status alone requires the rotation");
    assertEquals(false, rows.get(1).secretRotationRequired());
    assertEquals(false, rows.get(2).secretRotationRequired());

    InMemoryCredentialStore store = new InMemoryCredentialStore();
    rows.forEach(store::register);
    CredentialLifecycleService lifecycle = new CredentialLifecycleService(store, new Discard(),
        Clock.fixed(T0.plusSeconds(600), ZoneOffset.UTC));
    lifecycle.transition("compromised", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED,
        "incident");
    assertEquals(T0.plusSeconds(600),
        store.findByUsername("compromised").orElseThrow().compromisedSince(),
        "leaving COMPROMISED without a marker sets one");

    InvalidStatusTransitionException refused = assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("compromised", CredentialStatus.DISABLED,
            CredentialStatus.ACTIVE, "re-enable"));
    assertEquals(InvalidStatusTransitionException.Reason.SECRET_ROTATION_REQUIRED,
        refused.reason());
    assertInstanceOf(eu.jsentinel.jcustos.credential.store.CredentialUpdateResult.Updated.class,
        lifecycle.transition("disabled", CredentialStatus.DISABLED, CredentialStatus.ACTIVE,
            "re-enable"), "a row that was never compromised is re-enabled as before");
  }
}
