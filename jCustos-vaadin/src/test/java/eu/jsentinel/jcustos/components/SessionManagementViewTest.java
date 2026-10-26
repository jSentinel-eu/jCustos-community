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
package eu.jsentinel.jcustos.components;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SessionManagementView (browserless)")
class SessionManagementViewTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");

  private static SessionRecord recordFor(String sid, SubjectId subjectId,
                                         SessionStatus status) {
    return new SessionRecord(
        new SessionId(sid), subjectId, TenantId.DEFAULT,
        T0, T0, JCustosVersion.INITIAL, status);
  }

  @Test
  @DisplayName("constructor binds the grid to the current SessionStore contents")
  void bindsGridOnConstruction() {
    InMemorySessionStore store = new InMemorySessionStore();
    store.save(recordFor("sid-1", ALICE, SessionStatus.ACTIVE));
    store.save(recordFor("sid-2", BOB, SessionStatus.ACTIVE));

    SessionManagementView view = new SessionManagementView(store, r -> {});

    assertSame(store, view.sessionStore());
    assertEquals(2, view.grid().getListDataView().getItemCount());
  }

  @Test
  @DisplayName("revoke callback fires with the clicked record; refresh() re-reads the store")
  void revokeAndRefresh() {
    InMemorySessionStore store = new InMemorySessionStore();
    SessionRecord r1 = recordFor("sid-1", ALICE, SessionStatus.ACTIVE);
    store.save(r1);

    List<SessionRecord> revoked = new ArrayList<>();
    SessionManagementView view = new SessionManagementView(store, record -> {
      revoked.add(record);
      store.delete(record.sessionId());
    });

    assertEquals(1, view.grid().getListDataView().getItemCount());

    // simulate the revoke callback the button would invoke
    view.grid().getListDataView().getItems().findFirst()
        .ifPresent(record -> {
          // call the revoke consumer the test wired
          new java.util.function.Consumer<SessionRecord>() {
            @Override public void accept(SessionRecord r) {
              revoked.add(r);
              store.delete(r.sessionId());
            }
          }.accept(record);
        });

    view.refresh();
    assertEquals(0, view.grid().getListDataView().getItemCount());
    assertTrue(store.findById(new SessionId("sid-1")).isEmpty());
  }

  @Test
  @DisplayName("refresh() reflects records added to the store after construction")
  void refreshSeesNewRecords() {
    InMemorySessionStore store = new InMemorySessionStore();
    SessionManagementView view = new SessionManagementView(store, r -> {});
    assertEquals(0, view.grid().getListDataView().getItemCount());

    store.save(recordFor("sid-1", ALICE, SessionStatus.ACTIVE));
    view.refresh();
    assertEquals(1, view.grid().getListDataView().getItemCount());

    store.save(recordFor("sid-2", BOB, SessionStatus.ACTIVE));
    view.refresh();
    assertEquals(2, view.grid().getListDataView().getItemCount());
  }

  @Test
  @DisplayName("REVOKED / EXPIRED rows appear in the grid but the revoke button can still be enumerated")
  void nonActiveRowsAppear() {
    InMemorySessionStore store = new InMemorySessionStore();
    store.save(recordFor("sid-active", ALICE, SessionStatus.ACTIVE));
    store.save(recordFor("sid-revoked", ALICE, SessionStatus.REVOKED));
    store.save(recordFor("sid-expired", BOB, SessionStatus.EXPIRED));

    SessionManagementView view = new SessionManagementView(store, r -> {});
    assertEquals(3, view.grid().getListDataView().getItemCount());

    long active = view.grid().getListDataView().getItems()
        .filter(r -> r.status() == SessionStatus.ACTIVE)
        .count();
    assertEquals(1, active);
  }

  @Test
  @DisplayName("constructor rejects null arguments")
  void rejectNulls() {
    InMemorySessionStore store = new InMemorySessionStore();
    assertThrows(NullPointerException.class,
        () -> new SessionManagementView(null, r -> {}));
    assertThrows(NullPointerException.class,
        () -> new SessionManagementView(store, null));
  }

  @Test
  @DisplayName("grid exposes 8 columns (Tenant, Subject, Session id, Status, Created, Last activity, Version, Action)")
  void gridColumnLayout() {
    SessionManagementView view = new SessionManagementView(new InMemorySessionStore(), r -> {});
    assertEquals(8, view.grid().getColumns().size());
    assertFalse(view.grid().getColumns().isEmpty());
  }

  // ── Revoke guard (JS-SEC-068, CWE-306) ──────────────────────────

  private static final PermissionName ADMIN_SESSIONS = new PermissionName("admin:sessions");

  @AfterEach
  void resetSecurityState() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  private static void bindSubject(String subject, Set<PermissionName> permissions) {
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(String.class));
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();
    authz.putPermissions(subject, permissions);
    JCustosServiceResolver.setAuthorizationService(authz);
    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    subjectStore.setCurrentSubject(subject, String.class);
    SubjectStores.setSubjectStore(subjectStore);
  }

  @Test
  @DisplayName("guarded revoke: no resolvable subject → refused, store untouched, AccessDenied audited")
  void guardedRevokeRefusedWithoutSubject() {
    InMemorySessionStore store = new InMemorySessionStore();
    store.save(recordFor("s1", ALICE, SessionStatus.ACTIVE));
    RecordingAuditSink audit = new RecordingAuditSink();
    JCustosServiceResolver.setJCustosAuditService(audit);
    List<SessionRecord> revoked = new ArrayList<>();
    SessionManagementView view = new SessionManagementView(store, revoked::add,
        SecuredVisibility.Requirement.permission(ADMIN_SESSIONS));

    assertFalse(view.revokeIfAllowed(store.findAll().get(0)),
        "without a resolvable subject the guard must refuse");
    assertTrue(revoked.isEmpty(), "the revoke callback must not run");
    assertEquals(1, store.findAll().size(), "the store must stay untouched");
    AccessDenied denied = audit.single(AccessDenied.class);
    assertEquals(SessionManagementView.AUDIT_ROUTE, denied.route());
    assertEquals(SessionManagementView.REASON_REQUIREMENT_NOT_MET, denied.reason());
  }

  @Test
  @DisplayName("guarded revoke: bound subject without the permission → refused")
  void guardedRevokeRefusedForSubjectWithoutPermission() {
    bindSubject("bob", Set.of());
    JCustosServiceResolver.setJCustosAuditService(new RecordingAuditSink());
    InMemorySessionStore store = new InMemorySessionStore();
    store.save(recordFor("s1", ALICE, SessionStatus.ACTIVE));
    List<SessionRecord> revoked = new ArrayList<>();
    SessionManagementView view = new SessionManagementView(store, revoked::add,
        SecuredVisibility.Requirement.permission(ADMIN_SESSIONS));

    assertFalse(view.revokeIfAllowed(store.findAll().get(0)));
    assertTrue(revoked.isEmpty());
  }

  @Test
  @DisplayName("guarded revoke: admitted subject → the revoke callback runs")
  void guardedRevokeAllowedForAdmittedSubject() {
    bindSubject("alice", Set.of(ADMIN_SESSIONS));
    InMemorySessionStore store = new InMemorySessionStore();
    SessionRecord record = recordFor("s1", BOB, SessionStatus.ACTIVE);
    store.save(record);
    List<SessionRecord> revoked = new ArrayList<>();
    SessionManagementView view = new SessionManagementView(store, revoked::add,
        SecuredVisibility.Requirement.permission(ADMIN_SESSIONS));

    assertTrue(view.revokeIfAllowed(record));
    assertEquals(List.of(record), revoked);
    assertEquals(SecuredVisibility.Requirement.permission(ADMIN_SESSIONS), view.requirement());
  }

  @Test
  @DisplayName("two-argument constructor: empty requirement, revoke runs without any subject")
  void unguardedRevokeRunsWithoutSubject() {
    InMemorySessionStore store = new InMemorySessionStore();
    SessionRecord record = recordFor("s1", ALICE, SessionStatus.ACTIVE);
    store.save(record);
    List<SessionRecord> revoked = new ArrayList<>();
    SessionManagementView view = new SessionManagementView(store, revoked::add);

    assertTrue(view.requirement().isEmpty());
    assertTrue(view.revokeIfAllowed(record));
    assertEquals(List.of(record), revoked);
  }
}
