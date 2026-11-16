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
package eu.jsentinel.jcustos.demo.app.browserless;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.security.services.DemoSessionStoreProvider;
import eu.jsentinel.jcustos.demo.app.views.AdminSessionsView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.demo.app.views.PublicView;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.mocks.MockHttpSession;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vaadin.flow.internal.CurrentInstance;
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

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613) and JS-SEC-117 (CWE-522) in the demo's own wiring: the session
 * inventory holds references, never session ids, and Revoke in {@link AdminSessionsView}
 * ends the revoked session at the click; a record revoked elsewhere ends it on its next
 * request.
 *
 * <p>Two real sessions of one Vaadin service: the user's is the browserless session and
 * logs in through the real {@link MyLoginView}; the administrator's is a second
 * {@link VaadinSession} of the same service, in which the real {@link AdminSessionsView}
 * is built and its Revoke button clicked.
 */
@DisplayName("JS-SEC-131 / JS-SEC-117 — the demo's session inventory: references only, Revoke ends the session")
class SessionRevocationBrowserlessTest extends BrowserlessTest {

  private static final MyUser ADMIN = new MyUser(1L, "Admin",
      EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
  private static final MyUser BOB = new MyUser(7L, "Bob", EnumSet.of(AuthorizationRole.USER));

  private final RecordingAuditSink audit = new RecordingAuditSink();

  /** Strong references: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession bobSession;
  private VaadinSession adminSession;

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin-pass-1", ADMIN);
    DemoUserDirectoryProvider.directory().addUser("bob", "bob-pass-12", BOB);
    clearInventory();
  }

  @AfterEach
  void tearDown() {
    clearInventory();
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    System.clearProperty("security.bootstrap.mode");
  }

  @Test
  @DisplayName("the bootstrap registers the demo's inventory for the per-request revocation check")
  void bootstrapRegistersTheInventory() {
    assertSame(DemoSessionStoreProvider.sessionStore(),
        VaadinSessionRevocation.findSessionStore().orElseThrow(),
        "without the registration a revoked record ends nothing (JS-SEC-131)");
  }

  @Test
  @DisplayName("login records the session under its reference - no record and no grid row carries the session id")
  void inventoryHoldsReferencesOnly() {
    String bobSessionId = logInAsBob();

    List<SessionRecord> records = DemoSessionStoreProvider.sessionStore().findAll();
    assertEquals(1, records.size(), "one row for bob's login: " + records);
    assertEquals(SessionRef.of(bobSessionId), records.getFirst().sessionId().value(),
        "the row carries the reference of the live session id");
    assertTrue(records.stream().noneMatch(r -> r.sessionId().value().equals(bobSessionId)),
        "the session cookie must not be stored (JS-SEC-117)");

    AdminSessionsView view = actAsAdmin(AdminSessionsView::new);
    List<SessionRecord> rows = view.grid().getGenericDataView().getItems().toList();
    assertTrue(rows.stream().noneMatch(r -> r.sessionId().value().equals(bobSessionId)),
        "no row carries the cookie; the session-id column renders SessionRef.of(...)");
  }

  @Test
  @DisplayName("Revoke by the administrator ends the user's session at the click; the administrator stays logged in")
  void revokeEndsTheUsersSessionAtTheClick() {
    String bobSessionId = logInAsBob();
    audit.clear();

    actAsAdmin(() -> {
      AdminSessionsView view = new AdminSessionsView();
      SessionRecord bobRow = view.grid().getGenericDataView().getItems()
          .filter(r -> r.subjectId().value().equals("7"))
          .findFirst().orElseThrow();
      revokeButton(view, bobRow).click();
      return view;
    });

    // no request of bob's in between: the session ended at the click
    assertNotEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState),
        "Revoke must end the live session at once, not on its next request");
    assertNull(inSession(bobSession, () -> bobSession.getAttribute(MyUser.class)),
        "bob's subject is dropped");
    assertEquals(List.of(SessionStatus.REVOKED),
        DemoSessionStoreProvider.sessionStore().findAll().stream().map(r -> r.status()).toList(),
        "the record is kept as REVOKED, so every other node refuses the session on its next request");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals("7", invalidated.subjectId(), "the audit names the revoked subject");
    assertEquals(SessionRef.of(bobSessionId), invalidated.sessionId(),
        "the audit carries the reference, never the session cookie (JS-SEC-117)");

    assertEquals(VaadinSessionState.OPEN, inSession(adminSession, adminSession::getState),
        "revoking somebody else must not end the administrator's session");
    assertEquals(Optional.of(ADMIN), inSession(adminSession,
        () -> Optional.ofNullable(adminSession.getAttribute(MyUser.class))));
  }

  @Test
  @DisplayName("a record revoked elsewhere ends the user's session on its next request")
  void revokedRecordEndsTheSessionOnItsNextRequest() {
    String bobSessionId = logInAsBob();
    audit.clear();
    // another node or an operator tool marks the record revoked; the store holds the reference
    SessionRecord bobRecord = DemoSessionStoreProvider.sessionStore().findAll().getFirst();
    DemoSessionStoreProvider.sessionStore().save(bobRecord.withStatus(SessionStatus.REVOKED));

    // bob's next request
    navigateIntoTheEndedSession();

    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals(SessionRef.of(bobSessionId), invalidated.sessionId());
    assertNotEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState),
        "bob's session is closed");
    assertNull(inSession(bobSession, () -> bobSession.getAttribute(MyUser.class)),
        "bob's subject is dropped");
  }

  @Test
  @DisplayName("without a revoke the user's next request goes through")
  void withoutRevokeTheSessionLivesOn() {
    logInAsBob();
    audit.clear();

    navigate(PublicView.class);

    assertEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState));
    assertEquals(Optional.of(BOB), SubjectStores.subjectStore().currentSubject(MyUser.class));
    assertFalse(audit.events().stream().anyMatch(SessionInvalidated.class::isInstance));
  }

  // ── helpers ────────────────────────────────────────────────────

  private String logInAsBob() {
    bobSession = VaadinSession.getCurrent();
    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("bob");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("bob-pass-12");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();
    assertEquals(Optional.of(BOB), SubjectStores.subjectStore().currentSubject(MyUser.class),
        "bob must be logged in");
    return bobSession.getSession().getId();
  }

  /**
   * Runs {@code action} on the administrator's session: a second session of the same
   * service, bound to the test thread under its own lock as its request thread would have
   * it. Bob's request is over meanwhile - the container leaves an idle session unlocked -
   * so his session lock is released for the duration; a command for his session then runs
   * at once, as it would on a live node. Bob's lock and thread state are restored
   * afterwards.
   */
  private <T> T actAsAdmin(Supplier<T> action) {
    Map<Class<?>, CurrentInstance> bobsInstances = CurrentInstance.getInstances();
    if (adminSession == null) {
      adminSession = openSecondSession();
    }
    ReentrantLock bobsLock = (ReentrantLock) VaadinSession.getCurrent().getLockInstance();
    int bobsHolds = bobsLock.getHoldCount();
    for (int i = 0; i < bobsHolds; i++) {
      bobsLock.unlock();
    }
    CurrentInstance.clearAll();
    VaadinSession.setCurrent(adminSession);
    adminSession.getLockInstance().lock();
    try {
      SubjectStores.subjectStore().setCurrentSubject(ADMIN, MyUser.class);
      return action.get();
    } finally {
      adminSession.getLockInstance().unlock();
      for (int i = 0; i < bobsHolds; i++) {
        bobsLock.lock();
      }
      CurrentInstance.clearAll();
      CurrentInstance.restoreInstances(bobsInstances);
    }
  }

  @SuppressWarnings("unchecked")
  private static Button revokeButton(AdminSessionsView view, SessionRecord row) {
    var renderer = (ComponentRenderer<Button, SessionRecord>)
        view.grid().getColumnByKey("action").getRenderer();
    return renderer.createComponent(row);
  }

  /**
   * The lifetime listener ends the session in the middle of this navigation. The
   * browserless UI then belongs to a closed session and cannot finish rendering, which
   * the harness may report as an error of its own; what the product did is asserted by
   * the caller.
   */
  private void navigateIntoTheEndedSession() {
    try {
      navigate(PublicView.class);
    } catch (AssertionError | RuntimeException uiOfAClosedSession) {
      // expected with the browserless UI, see above
    }
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

  /** Reads state of another session under that session's lock. */
  private static <T> T inSession(VaadinSession session, Supplier<T> action) {
    session.getLockInstance().lock();
    try {
      return action.get();
    } finally {
      session.getLockInstance().unlock();
    }
  }

  private static void clearInventory() {
    DemoSessionStoreProvider.sessionStore().findAll()
        .forEach(r -> DemoSessionStoreProvider.sessionStore().delete(r.sessionId()));
  }
}
