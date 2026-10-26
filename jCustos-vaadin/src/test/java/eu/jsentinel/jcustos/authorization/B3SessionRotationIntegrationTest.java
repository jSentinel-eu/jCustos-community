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
package eu.jsentinel.jcustos.authorization;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration-style B3 test for the
 * <em>Session-Rotation-Honour after Login</em> contract:
 * <ul>
 *   <li>{@link SessionPolicy#onLogin onLogin} returns
 *       {@link SessionDecision.Invalidate Invalidate} — the contract
 *       is that the underlying HTTP session id rotates while the
 *       {@link VaadinSession} (and therefore any subject bound on it
 *       between login and rotation) survives.</li>
 *   <li>A {@link SessionInvalidated} audit event must be emitted with
 *       the <em>old</em> session id (so monitoring can correlate the
 *       rotation with the original session).</li>
 *   <li>{@code Invalidate.loginRoute} is deliberately ignored in the
 *       post-login context — the user proceeds to
 *       {@link LoginView#navigateToApp()} on the rotated session.</li>
 * </ul>
 * <p>
 * Earlier coverage (in {@code demo-vaadin/SessionRotationBrowserlessTest})
 * proved only the audit fired; this test additionally captures the
 * actual {@link WrappedSession#getId() WrappedSession id} before and
 * after the rotation and asserts that it changed. Browserless's
 * {@code MockHttpSession} models {@code VaadinService.reinitializeSession}
 * faithfully enough for that comparison.
 */
@DisplayName("B3 — Session-Rotation-Honour integration test")
class B3SessionRotationIntegrationTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final AtomicReference<SessionContext<Object>> capturedContext = new AtomicReference<>();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setSessionPolicy(new RotatingPolicy(capturedContext, "B3-Test-Rotation"));
    B3FixtureLoginView.lastNavigateToAppCalled = false;
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("Invalidate from onLogin rotates the HTTP session id and emits SessionInvalidated with the old id")
  void rotateAndAudit() {
    navigate(B3FixtureLoginView.class);

    VaadinSession beforeSession = VaadinSession.getCurrent();
    assertNotNull(beforeSession, "Browserless must bind a current VaadinSession before login");
    WrappedSession beforeWrapped = beforeSession.getSession();
    assertNotNull(beforeWrapped, "VaadinSession must expose its wrapped HTTP session");
    String oldSessionId = beforeWrapped.getId();

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("alice");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("alice");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    // ── 1. Policy callback observed: contract honoured. ──
    assertNotNull(capturedContext.get(),
        "SessionPolicy.onLogin must be called after credentials succeed");
    assertEquals(oldSessionId, capturedContext.get().sessionId(),
        "the SessionContext given to onLogin must carry the original wrapped-session id");

    // ── 2. SessionInvalidated audit emitted with the OLD session id. ──
    SessionInvalidated event = audit.events().stream()
        .filter(SessionInvalidated.class::isInstance)
        .map(SessionInvalidated.class::cast)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "expected one SessionInvalidated audit event; got: " + audit.events()));
    assertEquals(oldSessionId, event.sessionId(),
        "SessionInvalidated must carry the OLD wrapped-session id (correlation hook for monitoring)");
    assertEquals("B3-Test-Rotation", event.reason(),
        "SessionInvalidated.reason must come from SessionDecision.Invalidate.reason");

    // ── 3. The actual HTTP session id rotated. ──
    VaadinSession afterSession = VaadinSession.getCurrent();
    assertNotNull(afterSession,
        "the VaadinSession must survive the rotation (only the HTTP-session id changes)");
    WrappedSession afterWrapped = afterSession.getSession();
    assertNotNull(afterWrapped, "post-rotation wrapped session must still be present");
    assertFalse(oldSessionId.equals(afterWrapped.getId()),
        "VaadinService.reinitializeSession must have produced a different wrapped-session id; "
            + "old=" + oldSessionId + " new=" + afterWrapped.getId());

    // ── 4. navigateToApp was called — login flow continues on the rotated session. ──
    assertTrue(B3FixtureLoginView.lastNavigateToAppCalled,
        "the LoginView must proceed to navigateToApp() on the rotated session "
            + "(Invalidate.loginRoute is intentionally ignored in the post-login context)");
  }

  @Test
  @DisplayName("JS-SEC-003: login rotates the session id even when the policy returns Continue (secure-by-default)")
  void rotatesEvenWhenPolicyReturnsContinue() {
    // Override the @BeforeEach RotatingPolicy with one that does NOT ask for
    // invalidation — the behaviour of the pre-00.84.00 resolver default, NoopSessionPolicy.
    // Before JS-SEC-003 this left the pre-auth session id intact: a fixation
    // hole on the canonical login path.
    JCustosServiceResolver.setSessionPolicy(new NonRotatingPolicy(capturedContext));

    navigate(B3FixtureLoginView.class);
    VaadinSession beforeSession = VaadinSession.getCurrent();
    assertNotNull(beforeSession, "Browserless must bind a current VaadinSession before login");
    String oldSessionId = beforeSession.getSession().getId();

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("alice");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("alice");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    // Policy was consulted but returned Continue (no Invalidate requested).
    assertNotNull(capturedContext.get(),
        "SessionPolicy.onLogin must still be called even when it returns Continue");

    // The HTTP session id rotated anyway — secure-by-default.
    WrappedSession afterWrapped = VaadinSession.getCurrent().getSession();
    assertNotNull(afterWrapped, "post-rotation wrapped session must still be present");
    assertFalse(oldSessionId.equals(afterWrapped.getId()),
        "session id must rotate on login even when the policy returns Continue; "
            + "old=" + oldSessionId + " new=" + afterWrapped.getId());

    // A SessionInvalidated audit event is emitted with the OLD id and the
    // default rotation reason (the policy supplied none).
    SessionInvalidated event = audit.events().stream()
        .filter(SessionInvalidated.class::isInstance)
        .map(SessionInvalidated.class::cast)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "expected one SessionInvalidated audit event; got: " + audit.events()));
    assertEquals(oldSessionId, event.sessionId(),
        "SessionInvalidated must carry the OLD wrapped-session id");
    assertEquals("RotationAfterLogin", event.reason(),
        "default rotation reason when the policy does not supply an Invalidate reason");
  }

  // ── Fixtures ──────────────────────────────────────────────────

  /** Test-only LoginView whose checkCredentials always succeeds. */
  @Route("test/b3-fixture-login")
  public static class B3FixtureLoginView extends LoginView {
    static boolean lastNavigateToAppCalled;

    @Override public boolean checkCredentials() { return true; }
    @Override public void navigateToApp() { lastNavigateToAppCalled = true; }
    @Override public void reactOnFailedLogin() { /* not used */ }
  }

  /**
   * SessionPolicy that captures the {@code onLogin} context (so the test
   * can read the old session id from it) and instructs the LoginView to
   * rotate via {@code SessionDecision.Invalidate}.
   */
  static final class RotatingPolicy implements SessionPolicy<Object> {
    private final AtomicReference<SessionContext<Object>> captured;
    private final String reason;

    RotatingPolicy(AtomicReference<SessionContext<Object>> captured, String reason) {
      this.captured = captured;
      this.reason = reason;
    }

    @Override public SessionDecision onLogin(SessionContext<Object> context) {
      captured.set(context);
      return new SessionDecision.Invalidate(reason, "/login");
    }

    @Override public SessionDecision beforeNavigation(SessionContext<Object> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return SessionPolicyDecision.active();
    }
  }

  /**
   * SessionPolicy that captures the {@code onLogin} context but returns
   * {@link SessionDecision.Continue} — models the pre-00.84.00 resolver default
   * ({@code NoopSessionPolicy}), which never asks for invalidation. Used to
   * prove JS-SEC-003 rotates the session id regardless of the decision.
   */
  static final class NonRotatingPolicy implements SessionPolicy<Object> {
    private final AtomicReference<SessionContext<Object>> captured;

    NonRotatingPolicy(AtomicReference<SessionContext<Object>> captured) {
      this.captured = captured;
    }

    @Override public SessionDecision onLogin(SessionContext<Object> context) {
      captured.set(context);
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionDecision beforeNavigation(SessionContext<Object> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return SessionPolicyDecision.active();
    }
  }

}
