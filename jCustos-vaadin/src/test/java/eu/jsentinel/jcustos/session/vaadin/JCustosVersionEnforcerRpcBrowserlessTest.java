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

import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.mocks.MockRequest;
import com.vaadin.browserless.mocks.MockResponse;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinServletResponse;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.server.WrappedHttpSession;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-082 (CWE-613): the version enforcer listener is also a {@code RequestHandler}, so
 * revoked roles take effect on the next RPC round-trip and not only on the next navigation.
 */
@DisplayName("JS-SEC-082 — version drift is enforced per UIDL request, not only on navigation")
class JCustosVersionEnforcerRpcBrowserlessTest extends BrowserlessTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY = new JCustosVersionKey(TenantId.DEFAULT, ALICE);

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private InMemoryJCustosVersionStore versionStore;
  private JCustosVersionEnforcerListener listener;

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    versionStore = new InMemoryJCustosVersionStore();
    listener = new JCustosVersionEnforcerListener(
        new JCustosVersionEnforcer(versionStore, audit), Er15LoginView.class);
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("drifted snapshot on an RPC drops the subject, clears the snapshot, audits SessionStale and closes the session")
  void driftOnRpc_isEnforced() throws IOException {
    navigate(Er15WorkView.class);
    VaadinSession session = VaadinSession.getCurrent();
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-15");
    versionStore.increment(ALICE_KEY);

    boolean consumed = listener.handleRequest(session, uidlRequest(session), response());

    assertFalse(consumed, "the handler must never consume the request");
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty(),
        "revocation must take effect on the RPC, not on the next navigation");
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(), "the stale snapshot is cleared");
    assertEquals(1, audit.events().size());
    SessionStale stale = (SessionStale) audit.events().get(0);
    assertEquals("alice", stale.subjectId());
    assertEquals("sid-15", stale.sessionId());
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the session is discarded");
  }

  @Test
  @DisplayName("matching snapshot on an RPC leaves subject, snapshot and session untouched")
  void matchingSnapshotOnRpc_continues() throws IOException {
    navigate(Er15WorkView.class);
    VaadinSession session = VaadinSession.getCurrent();
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-16");

    listener.handleRequest(session, uidlRequest(session), response());

    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isPresent());
    assertTrue(VaadinJCustosVersionContext.current(session).isPresent());
    assertTrue(audit.events().isEmpty());
    assertEquals(VaadinSessionState.OPEN, session.getState());
  }

  // ── helpers ────────────────────────────────────────────────────

  private static VaadinRequest uidlRequest(VaadinSession session) {
    HttpSession http = ((WrappedHttpSession) session.getSession()).getHttpSession();
    MockRequest raw = new MockRequest(http);
    raw.setParameter("v-uiId", String.valueOf(UI.getCurrent().getUIId()));
    raw.setParameter("v-r", "uidl");
    return new VaadinServletRequest(raw, (VaadinServletService) VaadinService.getCurrent());
  }

  private static VaadinResponse response() {
    return new VaadinServletResponse(new MockResponse(), (VaadinServletService) VaadinService.getCurrent());
  }

  @Route("er15-work")
  public static class Er15WorkView extends Div {
  }

  @Route("er15-login")
  public static class Er15LoginView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { }
    @Override public void reactOnFailedLogin() { }
  }
}
