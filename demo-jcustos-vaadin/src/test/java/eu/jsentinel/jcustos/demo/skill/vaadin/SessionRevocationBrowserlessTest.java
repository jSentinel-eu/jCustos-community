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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.SessionStoreProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.PublicHomeView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.admin.SessionsView;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static eu.jsentinel.jcustos.demo.skill.vaadin.SkillDemoTestSupport.inSession;
import static eu.jsentinel.jcustos.demo.skill.vaadin.SkillDemoTestSupport.openSecondSession;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613) and JS-SEC-117 (CWE-522) in the demo's own wiring: the session
 * inventory holds references, never session ids, and Revoke in {@link SessionsView} ends
 * the revoked session at the click; a record revoked elsewhere ends it on its next request.
 *
 * <p>Two real sessions of one Vaadin service: the user's is the browserless session and
 * logs in through the real {@link MyLoginView}; the administrator's is a second
 * {@link VaadinSession} of the same service, in which the real {@link SessionsView} is
 * built and its Revoke button clicked. The demo's bootstrap chain runs as shipped.
 */
@DisplayName("JS-SEC-131 / JS-SEC-117 — session inventory: references only, Revoke ends the session")
class SessionRevocationBrowserlessTest extends BrowserlessTest {

  private static final User ADMIN = new User(1L, "Admin",
      EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
  private static final User BOB = new User(7L, "Bob", EnumSet.of(AuthorizationRole.USER));
  private static final String BOB_PASSWORD = "bob-pass-1234";

  private final RecordingAuditSink audit = new RecordingAuditSink();

  /** Strong references: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession bobSession;
  private VaadinSession adminSession;

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() {
    SkillDemoTestSupport.runDemoBootstrap();
    JCustosServiceResolver.setJCustosAuditService(audit);
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    UserDirectoryProvider.directory().addUser("admin", "admin-pass-1234", ADMIN);
    UserDirectoryProvider.directory().addUser("bob", BOB_PASSWORD, BOB);
    TestDirectories.resetBootstrapWiring();
    clearInventory();
  }

  @AfterEach
  void tearDown() {
    clearInventory();
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    TestDirectories.resetBootstrapWiring();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the bootstrap registers the demo's inventory for the per-request revocation check")
  void bootstrapRegistersTheInventory() {
    SessionStore registered = VaadinSessionRevocation.findSessionStore().orElseThrow(
        () -> new AssertionError("no store registered - a revoked record would end nothing"));
    SessionRecord probe = TestDirectories.record("probe-session", "99");
    SessionStoreProvider.sessionStore().save(probe);
    assertTrue(registered.findById(probe.sessionId()).isPresent(),
        "the registered store must be the inventory the view shows");
  }

  @Test
  @DisplayName("login records the session under its reference - no record and no grid row carries the session id")
  void inventoryHoldsReferencesOnly() {
    String bobSessionId = logInAsBob();

    List<SessionRecord> records = SessionStoreProvider.sessionStore().findAll();
    assertEquals(1, records.size(), "one row for bob's login: " + records);
    assertEquals(SessionRef.of(bobSessionId), records.getFirst().sessionId().value(),
        "the row carries the reference of the live session id");
    assertTrue(records.stream().noneMatch(r -> r.sessionId().value().equals(bobSessionId)),
        "the session cookie must not be stored (JS-SEC-117)");

    SessionsView view = actAsAdmin(SessionsView::new);
    List<SessionRecord> rows = view.grid().getGenericDataView().getItems().toList();
    assertEquals(1, rows.size());
    assertTrue(rows.stream().noneMatch(r -> r.sessionId().value().equals(bobSessionId)),
        "no row carries the cookie; the session-id column renders SessionRef.of(...)");
  }

  @Test
  @DisplayName("Revoke by the administrator ends the user's session at the click; the administrator stays logged in")
  void revokeEndsTheUsersSessionAtTheClick() {
    String bobSessionId = logInAsBob();
    audit.clear();

    actAsAdmin(() -> {
      SessionsView view = new SessionsView();
      SessionRecord bobRow = view.grid().getGenericDataView().getItems()
          .filter(r -> r.subjectId().value().equals("7"))
          .findFirst().orElseThrow();
      revokeButton(view, bobRow).click();
      return view;
    });

    // no request of bob's in between: the session ended at the click
    assertNotEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState),
        "Revoke must end the live session at once, not on its next request");
    assertNull(inSession(bobSession, () -> bobSession.getAttribute(User.class)),
        "bob's subject is dropped");
    assertTrue(SessionStoreProvider.sessionStore().findAll().isEmpty(),
        "the record is removed, so every other node refuses the session on its next request");
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals("7", invalidated.subjectId(), "the audit names the revoked subject");
    assertEquals(SessionRef.of(bobSessionId), invalidated.sessionId(),
        "the audit carries the reference, never the session cookie (JS-SEC-117)");

    assertEquals(VaadinSessionState.OPEN, inSession(adminSession, adminSession::getState),
        "revoking somebody else must not end the administrator's session");
    assertEquals(ADMIN, inSession(adminSession, () -> adminSession.getAttribute(User.class)));
  }

  @Test
  @DisplayName("a record revoked elsewhere ends the user's session on its next request")
  void revokedRecordEndsTheSessionOnItsNextRequest() {
    String bobSessionId = logInAsBob();
    audit.clear();
    // another node or an operator tool marks the record revoked; the store holds the reference
    SessionRecord bobRecord = SessionStoreProvider.sessionStore().findAll().getFirst();
    SessionStoreProvider.sessionStore().save(bobRecord.withStatus(SessionStatus.REVOKED));

    // bob's next request
    navigateIntoTheEndedSession();

    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals(SessionRef.of(bobSessionId), invalidated.sessionId());
    assertNotEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState),
        "bob's session is closed");
    assertNull(inSession(bobSession, () -> bobSession.getAttribute(User.class)),
        "bob's subject is dropped");
  }

  @Test
  @DisplayName("without a revoke the user's next request goes through")
  void withoutRevokeTheSessionLivesOn() {
    logInAsBob();
    audit.clear();

    navigate(PublicHomeView.class);

    assertEquals(VaadinSessionState.OPEN, inSession(bobSession, bobSession::getState));
    assertEquals(Optional.of(BOB), SubjectStores.subjectStore().currentSubject(User.class));
    assertFalse(audit.events().stream().anyMatch(SessionInvalidated.class::isInstance));
  }

  // ── helpers ────────────────────────────────────────────────────

  private String logInAsBob() {
    bobSession = VaadinSession.getCurrent();
    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("bob");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(BOB_PASSWORD);
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();
    assertEquals(Optional.of(BOB), SubjectStores.subjectStore().currentSubject(User.class),
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
      SubjectStores.subjectStore().setCurrentSubject(ADMIN, User.class);
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
  private static Button revokeButton(SessionsView view, SessionRecord row) {
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
      navigate(PublicHomeView.class);
    } catch (AssertionError | RuntimeException uiOfAClosedSession) {
      // expected with the browserless UI, see above
    }
  }

  private static void clearInventory() {
    SessionStoreProvider.sessionStore().findAll()
        .forEach(r -> SessionStoreProvider.sessionStore().delete(r.sessionId()));
  }
}
