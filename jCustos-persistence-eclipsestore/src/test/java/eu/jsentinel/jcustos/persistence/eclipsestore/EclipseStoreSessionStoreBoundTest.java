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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613), exit review XR01: at its bound the Eclipse-Store session store must not
 * forget a revocation. Until the fix the record stored first went, whatever its status - a
 * revoked session whose record was the oldest came back on every node that had not seen the
 * record, after a restart above all. Real storages on a temp directory, a small bound and a
 * clock the test moves.
 */
@DisplayName("XR01 - the bounded session store keeps revoked records")
class EclipseStoreSessionStoreBoundTest {

  private static final Instant T0 = Instant.parse("2026-11-16T10:00:00Z");
  private static final SubjectId ALICE = new SubjectId("alice");

  /** A clock the test sets; the store judges the retention of revoked records against it. */
  private static final class TestClock extends Clock {
    private Instant now = T0;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  @TempDir
  Path tempDir;

  private final TestClock clock = new TestClock();

  private EclipseStoreJCustosStorage open(int bound) {
    return EclipseStoreJCustosStorage.openAt(tempDir, bound, clock);
  }

  private static SessionRecord session(String id, SessionStatus status) {
    return new SessionRecord(new SessionId(id), ALICE, TenantId.DEFAULT, T0, T0,
        JCustosVersion.INITIAL, status);
  }

  private static List<String> ids(SessionStore store) {
    return store.findAll().stream().map(record -> record.sessionId().value()).toList();
  }

  @Test
  @DisplayName("the oldest record is REVOKED: the oldest ACTIVE record makes room, the revocation survives a restart")
  void revokedRecordSurvivesTheBound() {
    try (EclipseStoreJCustosStorage storage = open(3)) {
      SessionStore store = storage.sessionStore();
      store.save(session("revoked", SessionStatus.REVOKED));
      store.save(session("a1", SessionStatus.ACTIVE));
      store.save(session("a2", SessionStatus.ACTIVE));

      store.save(session("a3", SessionStatus.ACTIVE));
      store.save(session("a4", SessionStatus.ACTIVE));

      assertEquals(List.of("revoked", "a3", "a4"), ids(store),
          "the active records go, oldest first; the revoked one stays although it is the oldest");
    }
    try (EclipseStoreJCustosStorage reopened = open(3)) {
      SessionRecord record = reopened.sessionStore().findById(new SessionId("revoked")).orElseThrow(
          () -> new AssertionError("a revoked session must stay revoked after a restart"));
      assertEquals(SessionStatus.REVOKED, record.status());
    }
  }

  @Test
  @DisplayName("an EXPIRED record makes room before any ACTIVE one")
  void expiredRecordGoesFirst() {
    try (EclipseStoreJCustosStorage storage = open(3)) {
      SessionStore store = storage.sessionStore();
      store.save(session("a0", SessionStatus.ACTIVE));
      store.save(session("expired", SessionStatus.EXPIRED));
      store.save(session("revoked", SessionStatus.REVOKED));

      store.save(session("new", SessionStatus.ACTIVE));

      assertEquals(List.of("a0", "revoked", "new"), ids(store));
    }
  }

  @Test
  @DisplayName("a store full of revoked records refuses the new session and keeps every revocation")
  void storeFullOfRevokedRecordsRefuses() {
    try (EclipseStoreJCustosStorage storage = open(2)) {
      SessionStore store = storage.sessionStore();
      store.save(session("r1", SessionStatus.REVOKED));
      store.save(session("r2", SessionStatus.REVOKED));

      IllegalStateException refused = assertThrows(IllegalStateException.class,
          () -> store.save(session("new", SessionStatus.ACTIVE)));

      assertTrue(refused.getMessage().startsWith("persistence/session-store-capacity-exceeded"),
          refused.getMessage());
      assertEquals(List.of("r1", "r2"), ids(store), "nothing was evicted and nothing added");
      // a known session is updated in place, the bound does not stand in the way
      store.save(session("r1", SessionStatus.REVOKED).withLastActivityAt(T0.plusSeconds(5)));
      assertEquals(T0.plusSeconds(5),
          store.findById(new SessionId("r1")).orElseThrow().lastActivityAt());
    }
  }

  @Test
  @DisplayName("a revoked record past its retention is expendable again")
  void revokedRecordPastRetentionMakesRoom() {
    try (EclipseStoreJCustosStorage storage = open(2)) {
      SessionStore store = storage.sessionStore();
      store.save(session("r1", SessionStatus.REVOKED));
      store.save(session("r2", SessionStatus.REVOKED).withLastActivityAt(T0.plus(Duration.ofDays(10))));

      clock.now = T0.plus(EclipseStoreSessionStore.REVOKED_RETENTION);
      store.save(session("new", SessionStatus.ACTIVE));

      assertEquals(List.of("r2", "new"), ids(store),
          "r1 is revoked for the full retention, r2 for twenty days less");
    }
  }
}
