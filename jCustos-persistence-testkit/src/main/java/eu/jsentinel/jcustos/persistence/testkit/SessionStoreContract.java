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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link SessionStore} implementation must satisfy.
 */
@DisplayName("SessionStore — contract")
public interface SessionStoreContract {

  /**
   * @return a fresh, empty {@code SessionStore}
   */
  SessionStore newStore();

  /**
   * Builds a sample session record.
   *
   * @param sid     session id
   * @param subject subject username
   * @param tenant  tenant scope
   * @return new {@code SessionRecord} in {@link SessionStatus#ACTIVE}
   */
  default SessionRecord sampleSession(String sid, String subject, TenantId tenant) {
    Instant now = Instant.parse("2026-01-01T00:00:00Z");
    return new SessionRecord(
        new SessionId(sid),
        new SubjectId(subject),
        tenant,
        now,
        now,
        JCustosVersion.INITIAL,
        SessionStatus.ACTIVE);
  }

  @Test
  @DisplayName("save persists a record that findById can retrieve")
  default void saveAndFind() {
    SessionStore store = newStore();
    SessionRecord record = sampleSession("sid-1", "alice", TenantId.DEFAULT);
    store.save(record);
    assertEquals(Optional.of(record), store.findById(new SessionId("sid-1")));
  }

  @Test
  @DisplayName("rekey moves the record to the surviving session id and drops the old one (JS-SEC-060)")
  default void rekeyMovesRecord() {
    SessionStore store = newStore();
    SessionRecord record = sampleSession("sid-old", "alice", TenantId.DEFAULT);
    store.save(record);

    assertTrue(store.rekey(new SessionId("sid-old"), new SessionId("sid-new")));

    assertEquals(Optional.empty(), store.findById(new SessionId("sid-old")), "old id must be gone");
    SessionRecord moved = store.findById(new SessionId("sid-new")).orElseThrow();
    assertEquals(record.subjectId(), moved.subjectId());
    assertEquals(record.createdAt(), moved.createdAt());
    assertEquals(record.status(), moved.status());
    assertEquals(1, store.findBySubject(TenantId.DEFAULT, new SubjectId("alice")).size(),
        "exactly one record must remain for the subject");

    assertFalse(store.rekey(new SessionId("missing"), new SessionId("sid-x")), "nothing to move");
    assertTrue(store.rekey(new SessionId("sid-new"), new SessionId("sid-new")), "same id is a no-op success");
    assertThrows(NullPointerException.class, () -> store.rekey(null, new SessionId("x")));
    assertThrows(NullPointerException.class, () -> store.rekey(new SessionId("x"), null));
  }

  @Test
  @DisplayName("save upserts on the SessionId")
  default void saveUpserts() {
    SessionStore store = newStore();
    SessionRecord first = sampleSession("sid-1", "alice", TenantId.DEFAULT);
    store.save(first);
    SessionRecord second = first.withStatus(SessionStatus.REVOKED);
    store.save(second);
    assertEquals(Optional.of(second), store.findById(new SessionId("sid-1")));
  }

  @Test
  @DisplayName("findById on an unknown id returns empty")
  default void findByIdMissing() {
    SessionStore store = newStore();
    assertTrue(store.findById(new SessionId("nope")).isEmpty());
  }

  @Test
  @DisplayName("save and findById reject null")
  default void saveFindRejectNulls() {
    SessionStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(NullPointerException.class, () -> store.findById(null));
  }

  @Test
  @DisplayName("findBySubject returns every session of (tenant, subject) in insertion order")
  default void findBySubjectInsertionOrder() {
    SessionStore store = newStore();
    SessionRecord first = sampleSession("sid-1", "alice", TenantId.DEFAULT);
    SessionRecord second = sampleSession("sid-2", "alice", TenantId.DEFAULT);
    SessionRecord other = sampleSession("sid-3", "bob", TenantId.DEFAULT);
    store.save(first);
    store.save(second);
    store.save(other);

    assertEquals(List.of(first, second),
        store.findBySubject(TenantId.DEFAULT, new SubjectId("alice")));
  }

  @Test
  @DisplayName("findBySubject is tenant-scoped")
  default void findBySubjectIsTenantScoped() {
    SessionStore store = newStore();
    TenantId acme = new TenantId("acme");
    store.save(sampleSession("sid-1", "alice", TenantId.DEFAULT));
    SessionRecord acmeSession = sampleSession("sid-2", "alice", acme);
    store.save(acmeSession);

    assertEquals(List.of(acmeSession),
        store.findBySubject(acme, new SubjectId("alice")));
  }

  @Test
  @DisplayName("findBySubject includes every status, not just ACTIVE")
  default void findBySubjectIncludesAllStatuses() {
    SessionStore store = newStore();
    SessionRecord active = sampleSession("sid-1", "alice", TenantId.DEFAULT);
    SessionRecord revoked = sampleSession("sid-2", "alice", TenantId.DEFAULT)
        .withStatus(SessionStatus.REVOKED);
    store.save(active);
    store.save(revoked);

    List<SessionRecord> alice =
        store.findBySubject(TenantId.DEFAULT, new SubjectId("alice"));

    assertEquals(2, alice.size());
    assertTrue(alice.contains(revoked));
  }

  @Test
  @DisplayName("findBySubject returns an immutable empty list when nothing matches")
  default void findBySubjectEmptyImmutable() {
    SessionStore store = newStore();
    List<SessionRecord> empty =
        store.findBySubject(TenantId.DEFAULT, new SubjectId("ghost"));
    assertTrue(empty.isEmpty());
    assertThrows(UnsupportedOperationException.class,
        () -> empty.add(sampleSession("x", "ghost", TenantId.DEFAULT)));
  }

  @Test
  @DisplayName("findBySubject rejects null")
  default void findBySubjectRejectsNulls() {
    SessionStore store = newStore();
    assertThrows(NullPointerException.class,
        () -> store.findBySubject(null, new SubjectId("alice")));
    assertThrows(NullPointerException.class,
        () -> store.findBySubject(TenantId.DEFAULT, null));
  }

  @Test
  @DisplayName("delete removes the record and returns true; unknown id returns false")
  default void deleteLifecycle() {
    SessionStore store = newStore();
    store.save(sampleSession("sid-1", "alice", TenantId.DEFAULT));
    assertTrue(store.delete(new SessionId("sid-1")));
    assertTrue(store.findById(new SessionId("sid-1")).isEmpty());
    assertFalse(store.delete(new SessionId("ghost")));
  }

  @Test
  @DisplayName("delete rejects null")
  default void deleteRejectsNull() {
    SessionStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.delete(null));
  }
}
