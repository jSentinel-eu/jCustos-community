/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.vaadin.routes;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.mocks.MockHttpSession;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.server.WrappedHttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613): the Revoke button of the session-management route ends the session
 * it is clicked for. Two real sessions of one Vaadin service: the administrator's is the
 * browserless test session and clicks through the real route and grid; the user's is a
 * second, plain {@link VaadinSession} of the same service, idle between two requests.
 */
@DisplayName("JS-SEC-131 — Revoke on the session-management route ends the user's session, not the administrator's")
class SessionManagementRevokeBrowserlessTest extends BrowserlessTest {

  private static final PermissionName ADMIN_SESSIONS = new PermissionName("admin:sessions");

  private final InMemorySessionStore store = new InMemorySessionStore();
  private final RecordingAuditSink audit = new RecordingAuditSink();

  /** Strong references: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession adminSession;
  private VaadinSession bobSession;
  private SessionRecord bobRecord;
  private SessionRecord adminRecord;

  @BeforeEach
  void bootstrapSecurity() {
    JCustosServiceResolver.resetAll();
    SessionManagementContext.reset();
    SubjectStores.reset();
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();
    authz.putPermissions("admin", Set.of(ADMIN_SESSIONS));
    authz.putPermissions("bob", Set.of());
    VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(authz)
        .sessions(s -> s.storeBacked(store))
        .sessionManagementView(Requirement.permission(ADMIN_SESSIONS))
        .install();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);

    adminSession = VaadinSession.getCurrent();
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);
    adminRecord = record(adminSession.getSession().getId(), "admin");
    store.save(adminRecord);

    bobSession = openSecondSession();
    bobRecord = record(bobSession.getSession().getId(), "bob");
    store.save(bobRecord);
    inSession(bobSession, () -> {
      bobSession.setAttribute(String.class, "bob");
      return null;
    });
    audit.clear();
  }

  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
    SessionManagementContext.reset();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("the bootstrap registers the store for the per-request revocation check")
  void bootstrap_registersTheStore() {
    assertSame(store, VaadinSessionRevocation.findSessionStore().orElseThrow(),
        "SessionLifetimeListener must be able to look the current session's record up");

    SessionManagementContext.reset();
    assertTrue(VaadinSessionRevocation.findSessionStore().isEmpty());
  }

  @Test
  @DisplayName("Revoke ends the user's live session at once and leaves the administrator logged in")
  void revokeClick_endsTheUsersSession() {
    SessionManagementRoute view = navigate(SessionManagementRoute.class);
    var grid = test(view.grid());
    assertEquals(2, grid.size());
    int bobRow = store.findAll().indexOf(bobRecord);
    Button revoke = (Button) grid.renderCellComponent(bobRow, "action");

    test(revoke).click();

    // the user's session is over without any request of the user
    assertNotEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState),
        "Revoke must end the live session, not only edit the store");
    assertNull(inSession(bobSession, () -> bobSession.getAttribute(String.class)), "the subject is dropped");
    assertTrue(store.findById(bobRecord.sessionId()).isEmpty(), "the record is removed");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals("bob", invalidated.subjectId(), "the audit names the revoked subject");
    assertEquals(bobRecord.sessionId().value(), invalidated.sessionId());
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());

    // the administrator's session is untouched
    assertSame(adminSession, VaadinSession.getCurrent());
    assertEquals(VaadinSessionState.OPEN, adminSession.getState());
    assertEquals(Optional.of("admin"), SubjectStores.subjectStore().currentSubject(String.class),
        "revoking somebody else must not log the administrator out");
    assertTrue(store.findById(adminRecord.sessionId()).isPresent());
    assertTrue(getCurrentView() instanceof SessionManagementRoute, "the administrator stays on the view");
  }

  @Test
  @DisplayName("a handler published by the application replaces the default")
  void publishedHandler_isUsed() {
    List<SessionRecord> handed = new ArrayList<>();
    SessionManagementContext.publish(store, handed::add, Requirement.permission(ADMIN_SESSIONS));

    SessionManagementContext.revoke().accept(bobRecord);

    assertEquals(List.of(bobRecord), handed);
    assertTrue(store.findById(bobRecord.sessionId()).isPresent(), "the application's handler decides");
    assertEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState));
    assertFalse(VaadinSessionRevocation.findSessionStore().isEmpty(),
        "the store check stays active whatever the handler does");
  }

  // ── helpers ────────────────────────────────────────────────────

  private static SessionRecord record(String sessionId, String subject) {
    Instant now = Instant.now();
    return new SessionRecord(SessionId.of(sessionId), SubjectId.of(subject), TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }

  /**
   * Another browser's session of the same service, as the servlet container leaves it
   * between two requests: registered, unlocked, known to the session-init listeners.
   */
  private static VaadinSession openSecondSession() {
    VaadinServletService service = (VaadinServletService) VaadinService.getCurrent();
    MockHttpSession http = MockHttpSession.Companion.create(service.getServlet().getServletContext());
    VaadinSession session = new VaadinSession(service);
    ReentrantLock lock = new ReentrantLock();
    lock.lock();
    try {
      http.setAttribute(service.getServiceName() + ".lock", lock);
      http.setAttribute(VaadinSession.class.getName() + "." + service.getServiceName(), session);
      session.refreshTransients(new WrappedHttpSession(http), service);
      MockVaadin.fireSessionInit(service, session, VaadinRequest.getCurrent());
    } finally {
      lock.unlock();
    }
    return session;
  }

  /** Reads or writes state of another session under that session's lock. */
  private static <T> T inSession(VaadinSession session, Supplier<T> action) {
    session.getLockInstance().lock();
    try {
      return action.get();
    } finally {
      session.getLockInstance().unlock();
    }
  }
}
