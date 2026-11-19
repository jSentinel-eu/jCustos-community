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
package eu.jsentinel.jcustos.session.vaadin;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.internal.SessionObjects;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ER30 follow-up, decision F21 (JS-SEC-097, CWE-1041, CWE-778): the subject id that
 * {@link VaadinSessionRevocation} audits follows one rule - the registered
 * {@code SubjectIdResolver}'s value, else the subject id of the session record, else the
 * identity handle of {@link CurrentSubject#subjectIdOf(Object)}; never empty while a subject
 * is bound. Real sessions of one Vaadin service, a real {@link InMemorySessionStore} and the
 * real {@link VaadinSessionSubjectStore}; the administrator revokes from a second session.
 */
@DisplayName("F21 — a revocation audits the resolver's id, else the record's, else the identity handle")
class VaadinSessionRevocationSubjectIdTest {

  /** The subject id the session inventory shows, deliberately unlike the subject. */
  private static final String RECORD_SUBJECT_ID = "7";

  private static final String BOB = "bob";

  private static final String HANDLE_PATTERN = "String@[0-9a-f]+";

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final InMemorySessionStore store = new InMemorySessionStore();
  private final VaadinSessionSubjectStore subjects = new VaadinSessionSubjectStore();

  private RequestPipeline pipeline;
  /** Strong references: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession bobSession;
  private SessionObjects admin;
  private SessionRecord bobRecord;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    SubjectStores.setSubjectStore(subjects);
    VaadinSessionRevocation.useSessionStore(store);

    pipeline = RequestPipeline.start(Clock.systemUTC(), UserView.class);
    bobSession = pipeline.session();
    pipeline.navigate(UserView.class);

    subjects.setCurrentSubject(BOB, String.class);
    bobRecord = record(pipeline.httpSessionId());
    store.save(bobRecord);
    audit.clear();
  }

  @AfterEach
  void stop() {
    try {
      pipeline.close();
    } finally {
      JCustosServiceResolver.resetAll();
      LoginListeners.reset();
      SubjectStores.reset();
      VaadinSessionRevocation.reset();
    }
  }

  // ── terminate / revoke: resolver, then record, then handle ─────

  @Test
  @DisplayName("with a resolver, revoke audits the resolver's id, not the record's")
  void revoke_withResolver_auditsTheResolvedId() {
    JCustosServiceResolver.<String>setSubjectIdResolver(subject -> SubjectId.of("resolved-" + subject));

    revokeAsAdministrator(bobRecord);

    assertEquals("resolved-bob", revokedSubjectId());
  }

  @Test
  @DisplayName("without a resolver, revoke audits the record's subject id - the id the session inventory shows")
  void revoke_withoutResolver_auditsTheRecordId() {
    assertNoResolver();

    revokeAsAdministrator(bobRecord);

    assertEquals(RECORD_SUBJECT_ID, revokedSubjectId());
  }

  @Test
  @DisplayName("a resolver that throws gives way to the record's subject id")
  void revoke_failingResolver_auditsTheRecordId() {
    JCustosServiceResolver.<String>setSubjectIdResolver(subject -> {
      throw new IllegalStateException("directory down for " + subject);
    });

    revokeAsAdministrator(bobRecord);

    assertEquals(RECORD_SUBJECT_ID, revokedSubjectId());
  }

  @Test
  @DisplayName("without a resolver and without a record id, terminate audits the identity handle, never an empty id")
  void terminate_withoutResolverAndRecordId_auditsTheHandle() {
    assertNoResolver();
    String handle = CurrentSubject.subjectIdOf(BOB);

    pipeline.releaseLock();
    assertTrue(VaadinSessionRevocation.terminate(bobRecord.sessionId(), null));
    pipeline.reacquireLock();

    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState());
    String audited = revokedSubjectId();
    assertEquals(handle, audited);
    assertTrue(audited.matches(HANDLE_PATTERN), audited);
  }

  // ── endCurrentSession: no record, so resolver, then handle ─────

  @Test
  @DisplayName("without a resolver, endCurrentSession audits the identity handle instead of an empty id")
  void endCurrentSession_withoutResolver_auditsTheHandle() {
    assertNoResolver();
    String handle = CurrentSubject.subjectIdOf(BOB);

    assertTrue(VaadinSessionRevocation.endCurrentSession("Login not confirmed"));

    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals("Login not confirmed", invalidated.reason());
    assertFalse(invalidated.subjectId().isEmpty(), "never an empty subject id while a subject is bound");
    assertEquals(handle, invalidated.subjectId());
    assertTrue(invalidated.subjectId().matches(HANDLE_PATTERN), invalidated.subjectId());
    assertEquals(SessionRef.of(bobRecord.sessionId().value()), invalidated.sessionId());
  }

  @Test
  @DisplayName("with a resolver, endCurrentSession audits the resolver's id")
  void endCurrentSession_withResolver_auditsTheResolvedId() {
    JCustosServiceResolver.<String>setSubjectIdResolver(subject -> SubjectId.of("resolved-" + subject));

    assertTrue(VaadinSessionRevocation.endCurrentSession("Login not confirmed"));

    assertEquals("resolved-bob", audit.single(SessionInvalidated.class).subjectId());
  }

  @Test
  @DisplayName("without a bound subject and without a record id there is nobody to name: the id stays empty")
  void endCurrentSession_withoutSubject_auditsNoId() {
    subjects.deleteCurrentSubject(String.class);

    assertTrue(VaadinSessionRevocation.endCurrentSession("Login not confirmed"));

    assertEquals("", audit.single(SessionInvalidated.class).subjectId());
  }

  // ── helpers ────────────────────────────────────────────────────

  private static void assertNoResolver() {
    assertTrue(JCustosServiceResolver.findSubjectIdResolver().isEmpty(),
        "the test needs a context without a SubjectIdResolver");
  }

  /** Revokes from a second session of the same service, as the session-management view does. */
  private void revokeAsAdministrator(SessionRecord record) {
    admin = pipeline.newSession();
    pipeline.releaseLock();
    CurrentInstance.clearAll();
    VaadinSession.setCurrent(admin.getSession());
    CurrentInstance.set(VaadinRequest.class, admin.getRequest());
    subjects.setCurrentSubject("alice", String.class);

    assertTrue(VaadinSessionRevocation.revoke(record), "bob's session lives on this node");

    CurrentInstance.clearAll();
    pipeline.reacquireLock();
    VaadinSession.setCurrent(bobSession);
    assertNotEquals(VaadinSessionState.OPEN, bobSession.getState(), "the revoked session is closed");
    assertEquals(SessionStatus.REVOKED, store.findById(record.sessionId()).orElseThrow().status());
  }

  private String revokedSubjectId() {
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    return invalidated.subjectId();
  }

  private static SessionRecord record(String sessionId) {
    Instant now = Instant.now();
    return new SessionRecord(SessionId.of(sessionId), SubjectId.of(RECORD_SUBJECT_ID),
        TenantId.DEFAULT, now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }

  @Route("f21-user")
  public static class UserView extends Div {
  }
}
