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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext;
import eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementRoute;
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
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613): the Vaadin bootstrap registers the {@code SessionStore} of
 * {@code .sessions(s -> s.storeBacked(...))} for the per-request revocation check whether
 * or not the session-management view is activated. A record another node or an
 * administration tool revokes then ends the session on its next request.
 */
@DisplayName("JS-SEC-131 — store-backed sessions are revocable without the session-management view")
class SessionStoreRevocationBootstrapBrowserlessTest extends BrowserlessTest {

  private final InMemorySessionStore store = new InMemorySessionStore();
  private final RecordingAuditSink audit = new RecordingAuditSink();
  /** Strong reference: Vaadin's CurrentInstance holds the session weakly. */
  private VaadinSession session;

  @BeforeEach
  void resetBefore() {
    reset();
    session = VaadinSession.getCurrent();
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    SessionManagementContext.reset();
    VaadinSessionRevocation.reset();
    SubjectStores.reset();
  }

  private JCustosRuntime bootstrapWithStoreButWithoutView() {
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .sessions(s -> s.storeBacked(store))
        .install();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    return runtime;
  }

  @Test
  @DisplayName("storeBacked(...) without sessionManagementView(): the store is registered for the revocation check")
  void storeIsRegisteredWithoutTheView() {
    assertTrue(VaadinSessionRevocation.findSessionStore().isEmpty());

    JCustosRuntime runtime = bootstrapWithStoreButWithoutView();

    assertSame(store, VaadinSessionRevocation.findSessionStore().orElseThrow(),
        "SessionLifetimeListener must be able to look the current session's record up");
    assertTrue(runtime.services().stream().anyMatch(service ->
            service.spi() == VaadinSessionRevocation.class
                && "bootstrap-session-revocation".equals(service.source())),
        "the registration is listed in the runtime report: " + runtime.services());
    assertTrue(runtime.services().stream()
            .noneMatch(service -> service.spi() == SessionManagementRoute.class),
        "the view itself stays an opt-in");
    assertTrue(SessionManagementContext.requirement().isEmpty());
  }

  @Test
  @DisplayName("a record marked REVOKED by another node ends the session on its next navigation - no view involved")
  void revocationFromElsewhereIsHonoured() {
    bootstrapWithStoreButWithoutView();
    navigate(WorkView.class);
    SubjectStores.subjectStore().setCurrentSubject("bob", String.class);
    Instant now = Instant.now();
    SessionRecord record = new SessionRecord(SessionId.of(session.getSession().getId()),
        SubjectId.of("bob"), TenantId.DEFAULT, now, now, JCustosVersion.INITIAL,
        SessionStatus.ACTIVE);
    store.save(record);
    navigate(OtherView.class);
    assertEquals(Optional.of("bob"), SubjectStores.subjectStore().currentSubject(String.class),
        "an ACTIVE record does not disturb the session");
    audit.clear();

    // another node, a housekeeping job or an administration tool: only the store changes
    store.save(record.withStatus(SessionStatus.REVOKED));
    navigateIntoTheEndedSession(WorkView.class);

    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals("bob", invalidated.subjectId());
    assertEquals(record.sessionId().value(), invalidated.sessionId());
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty(),
        "the revoked session must not keep its subject");
  }

  /**
   * The lifetime listener ends the session in the middle of this navigation. The browserless
   * UI then belongs to a closed session and cannot finish rendering the target, which the
   * harness reports as an error of its own; what the product did is asserted by the caller.
   * (The request path itself is covered by {@code VaadinSessionRevocationPipelineTest} in
   * {@code jCustos-vaadin}; this test is about the bootstrap wiring.)
   */
  private void navigateIntoTheEndedSession(Class<? extends Div> target) {
    try {
      navigate(target);
    } catch (AssertionError | RuntimeException uiOfAClosedSession) {
      // expected with the browserless UI, see above
    }
  }

  @Test
  @DisplayName("a bootstrap without a store neither registers nor clears a store")
  void bootstrapWithoutStoreLeavesAManualRegistrationAlone() {
    InMemorySessionStore manual = new InMemorySessionStore();
    VaadinSessionRevocation.useSessionStore(manual);

    VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertSame(manual, VaadinSessionRevocation.findSessionStore().orElseThrow());
  }

  /** A view without a restriction; the test is about the session, not about access. */
  @Route("sa31-bootstrap/work")
  public static class WorkView extends Div {
  }

  /** A second view, so that a navigation really happens. */
  @Route("sa31-bootstrap/other")
  public static class OtherView extends Div {
  }
}
