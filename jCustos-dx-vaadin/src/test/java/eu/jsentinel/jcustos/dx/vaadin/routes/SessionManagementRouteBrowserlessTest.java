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

import eu.jsentinel.jcustos.audit.AccessDenied;
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
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-068 (CWE-306): the framework's session-management route must not be
 * reachable without the configured requirement, and a refused visitor must
 * leave the store untouched. Real bootstrap, real stores, real listener —
 * only the subject directory is a test fixture.
 */
@DisplayName("SessionManagementRoute behind @ProtectedBy (browserless)")
class SessionManagementRouteBrowserlessTest extends BrowserlessTest {

  private static final PermissionName ADMIN_SESSIONS = new PermissionName("admin:sessions");

  private final InMemorySessionStore store = new InMemorySessionStore();
  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void bootstrapSecurity() {
    JCustosServiceResolver.resetAll();
    SessionManagementContext.reset();
    SubjectStores.reset();
    store.save(new SessionRecord(new SessionId("s-1"), new SubjectId("alice"), TenantId.DEFAULT,
        Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-01T00:00:00Z"),
        JCustosVersion.INITIAL, SessionStatus.ACTIVE));
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
  }

  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
    SessionManagementContext.reset();
    SubjectStores.reset();
  }

  private static void bind(String subject) {
    SubjectStores.subjectStore().setCurrentSubject(subject, String.class);
  }

  @Test
  @DisplayName("anonymous navigation is refused, audited, and leaves the store untouched")
  void anonymousIsRefused() {
    UI.getCurrent().navigate(SessionManagementRoute.ROUTE_NAME);

    assertTrue(getCurrentView() instanceof LoginRouteFixture,
        "an anonymous visitor must be forwarded to the login route, not reach the view; was "
            + getCurrentView().getClass().getSimpleName());
    assertEquals(1, store.findAll().size(), "the store must stay untouched");
    List<AccessDenied> denied = audit.all(AccessDenied.class);
    assertFalse(denied.isEmpty(), "the refusal must be audited as AccessDenied");
  }

  @Test
  @DisplayName("a subject without the permission is refused with the requirement reason")
  void subjectWithoutPermissionIsRefused() {
    bind("bob");
    UI.getCurrent().navigate(SessionManagementRoute.ROUTE_NAME);

    assertFalse(getCurrentView() instanceof SessionManagementRoute,
        "a subject without the permission must not reach the view; was "
            + getCurrentView().getClass().getSimpleName());
    assertTrue(audit.all(AccessDenied.class).stream()
            .anyMatch(d -> d.reason().contains(SessionManagementAccess.REASON_NOT_MET)),
        "AccessDenied must carry the session-management requirement reason");
  }

  @Test
  @DisplayName("an admitted administrator reaches the view and revokes exactly one session")
  void adminReachesViewAndRevokes() {
    bind("admin");
    SessionManagementRoute view = navigate(SessionManagementRoute.class);

    var grid = test(view.grid());
    assertEquals(1, grid.size());
    // The Revoke button lives in a component column; render it the browserless way.
    Button revoke = (Button) grid.renderCellComponent(0, "action");
    assertEquals("Revoke", revoke.getText());
    test(revoke).click();

    assertTrue(store.findAll().isEmpty(), "the default revoke drops the record from the store");
    assertTrue(audit.all(AccessDenied.class).isEmpty(), "an admitted revoke is not a denial");
  }
}
