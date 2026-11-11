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

import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-124 (CWE-307, CWE-1188): the library {@link LoginView} consults the
 * {@link LoginAttemptPolicy} itself, with the complete protocol of JS-SEC-123 and the
 * "no verdict" path of JS-SEC-126. An application with this view and an
 * {@code AuthenticationService} that knows nothing about throttling is throttled by the
 * resolver's default policy.
 *
 * <p>The views are real routes driven through the browserless UI; the policies are the real
 * {@link InMemoryLoginAttemptPolicy} or a hand-written recorder, never a mock.</p>
 */
@DisplayName("JS-SEC-124 — LoginView runs the login-attempt protocol itself")
class LoginViewThrottlingBrowserlessTest extends BrowserlessTest {

  private static final String PASSWORD = "correct horse battery";

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
  }

  private void submit(String username, String password) {
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue(username);
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(password);
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();
  }

  /**
   * As {@link #submit}, but with the server-side click. The login under test ends the Vaadin
   * session inside the click; the browserless click helper then inspects the UI of that
   * session for focus changes, which a closed session cannot answer.
   */
  private void submitEndingTheSession(String username, String password) {
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue(username);
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(password);
    $view(Button.class).id(LoginView.BTN_LOGIN_ID).click();
  }

  private static Optional<String> boundSubject() {
    return SubjectStores.subjectStore().currentSubject(String.class);
  }

  // ── the regression: a plain service behind the library view is throttled ──

  @Test
  @DisplayName("no policy registered: after five wrong passwords the correct one is refused without being checked")
  void defaultPolicyThrottlesAPlainAuthenticationService() {
    assertTrue(JCustosServiceResolver.findLoginAttemptPolicy().isEmpty(),
        "the test must run against the resolver's default policy");
    PlainLoginView view = navigate(PlainLoginView.class);
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();

    for (int i = 0; i < threshold; i++) {
      submit("alice", "wrong guess " + i);
    }
    assertEquals(threshold, view.checks, "every attempt below the threshold is evaluated");
    assertEquals(threshold, view.failedReactions);

    submit("alice", PASSWORD);

    assertEquals(threshold, view.checks,
        "a locked-out attempt must not reach checkCredentials(): the password is not evaluated");
    assertFalse(view.navigated, "the correct password must not log in while the key is locked");
    assertTrue(boundSubject().isEmpty());
    assertNotNull(view.lastLockout, "the view must be told about the lockout");
    assertTrue(view.lastLockout.failedAttempts() >= threshold);
    assertEquals("", view.password(), "the password does not stay in the field");
  }

  @Test
  @DisplayName("the threshold is the configured one: four failures leave the fifth attempt open - nothing is counted twice")
  void failuresAreCountedOnce() {
    JCustosServiceResolver.setLoginAttemptPolicy(new InMemoryLoginAttemptPolicy(
        LoginAttemptConfiguration.defaults(), Clock.systemUTC(), audit));
    PlainLoginView view = navigate(PlainLoginView.class);
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();

    for (int i = 0; i < threshold - 1; i++) {
      submit("alice", "wrong guess " + i);
    }
    submit("alice", PASSWORD);

    assertTrue(view.navigated, (threshold - 1) + " failures must not lock a threshold of " + threshold);
    assertEquals(Optional.of("alice"), boundSubject());
    assertEquals(threshold - 1, audit.events().stream().filter(LoginFailed.class::isInstance).count(),
        "one LoginFailed per failed attempt");
  }

  // ── the protocol, call by call ──

  @Test
  @DisplayName("success: beforeAttempt, then confirmSuccess - and nothing else")
  void successReportsConfirmSuccess() {
    RecordingPolicy policy = new RecordingPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);

    submit("alice", PASSWORD);

    assertEquals(List.of("beforeAttempt", "confirmSuccess"), policy.calls);
    assertTrue(view.navigated);
    assertEquals(Optional.of("alice"), boundSubject());
  }

  @Test
  @DisplayName("wrong password: beforeAttempt, then recordFailure")
  void failureReportsRecordFailure() {
    RecordingPolicy policy = new RecordingPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);

    submit("alice", "not the password");

    assertEquals(List.of("beforeAttempt", "recordFailure"), policy.calls);
    assertEquals(1, view.failedReactions);
    assertFalse(view.navigated);
  }

  @Test
  @DisplayName("the attempt is keyed on the typed user name and on the address of the registered ClientAddressResolver")
  void attemptCarriesUsernameAndResolvedClientAddress() {
    RecordingPolicy policy = new RecordingPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    JCustosServiceResolver.setClientAddressResolver(request -> Optional.of("203.0.113.77"));
    navigate(PlainLoginView.class);

    submit("Alice", "not the password");

    assertEquals(2, policy.contexts.size());
    for (LoginAttemptContext context : policy.contexts) {
      assertEquals("Alice", context.username(), "the policy canonicalises, the view passes the name as typed");
      assertEquals("203.0.113.77", context.clientAddress());
    }
    assertSame(policy.contexts.get(0), policy.contexts.get(1), "the report names the reserved attempt");
    assertNotEquals("203.0.113.77", VaadinRequest.getCurrent().getRemoteAddr(),
        "the address must come from the resolver, not from the connection peer");
  }

  @Test
  @DisplayName("a lockout from beforeAttempt: no check, no report, reactOnLockedOut with the decision")
  void lockedOutBeforeTheCheck() {
    RecordingPolicy policy = new RecordingPolicy();
    policy.before = LoginAttemptDecision.lockedOut(Duration.ofMinutes(12), 7);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);

    submit("alice", PASSWORD);

    assertEquals(List.of("beforeAttempt"), policy.calls, "a denied attempt reserved nothing");
    assertEquals(0, view.checks);
    assertEquals(0, view.failedReactions, "an overriding view is not told 'wrong credentials'");
    assertEquals(Duration.ofMinutes(12), view.lastLockout.remaining());
    assertEquals(7, view.lastLockout.failedAttempts());
    assertTrue(boundSubject().isEmpty());
  }

  @Test
  @DisplayName("a view that does not override reactOnLockedOut answers a lockout with reactOnFailedLogin")
  void lockoutFallsBackToReactOnFailedLogin() {
    RecordingPolicy policy = new RecordingPolicy();
    policy.before = LoginAttemptDecision.lockedOut(Duration.ofMinutes(1), 5);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    MinimalLoginView view = navigate(MinimalLoginView.class);

    submit("alice", PASSWORD);

    assertEquals(1, view.failedReactions);
    assertEquals(0, view.checks);
  }

  // ── no verdict (JS-SEC-126) ──

  @Test
  @DisplayName("CredentialVerificationUnavailableException: the attempt is abandoned, nothing is counted, the user is told to retry")
  void shedVerificationAbandonsTheAttempt() {
    RecordingPolicy policy = new RecordingPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);
    view.nextFailure = new CredentialVerificationUnavailableException();

    submit("alice", PASSWORD);

    assertEquals(List.of("beforeAttempt", "abandonAttempt"), policy.calls);
    assertEquals(1, view.unavailableReactions);
    assertEquals(0, view.failedReactions);
    assertFalse(view.navigated);
    assertTrue(audit.events().stream().noneMatch(LoginFailed.class::isInstance));
  }

  @Test
  @DisplayName("a shed verification does not use up the real policy: after five of them the correct password still logs in")
  void shedVerificationsDoNotLockTheAccount() {
    PlainLoginView view = navigate(PlainLoginView.class);
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();
    for (int i = 0; i < threshold + 1; i++) {
      view.nextFailure = new CredentialVerificationUnavailableException();
      submit("alice", PASSWORD);
    }
    view.nextFailure = null;

    submit("alice", PASSWORD);

    assertTrue(view.navigated);
    assertEquals(threshold + 1, view.unavailableReactions);
  }

  @Test
  @DisplayName("a view that does not override reactOnVerificationUnavailable falls back to reactOnFailedLogin, still without a counted failure")
  void unavailableFallsBackToReactOnFailedLogin() {
    RecordingPolicy policy = new RecordingPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    MinimalLoginView view = navigate(MinimalLoginView.class);
    view.nextFailure = new CredentialVerificationUnavailableException();

    submit("alice", PASSWORD);

    assertEquals(1, view.failedReactions);
    assertEquals(List.of("beforeAttempt", "abandonAttempt"), policy.calls);
  }

  @Test
  @DisplayName("any other exception of the check: the attempt is abandoned and the exception reaches the caller")
  void otherExceptionAbandonsAndPropagates() {
    RecordingPolicy policy = new RecordingPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);
    view.nextFailure = new IllegalStateException("user directory unreachable");

    IllegalStateException thrown = assertThrows(IllegalStateException.class,
        () -> submit("alice", PASSWORD));

    assertEquals("user directory unreachable", thrown.getMessage());
    assertEquals(List.of("beforeAttempt", "abandonAttempt"), policy.calls);
    assertEquals("", view.password(), "the password does not stay in the field");
  }

  // ── locked while the attempt was in flight (JS-SEC-123) ──

  @Test
  @DisplayName("confirmSuccess answers LockedOut: the bound subject is removed, the session ended, no rotation, LoginFailed audited")
  void lockoutDuringTheCheckUndoesTheLogin() {
    RecordingPolicy policy = new RecordingPolicy();
    policy.confirm = LoginAttemptDecision.lockedOut(Duration.ofMinutes(15), 5);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);

    submitEndingTheSession("alice", PASSWORD);

    assertEquals(List.of("beforeAttempt", "confirmSuccess"), policy.calls);
    assertEquals(1, view.checks, "the credentials were correct and the subject was bound ...");
    assertTrue(boundSubject().isEmpty(), "... and must not stay bound");
    assertFalse(view.navigated);
    assertEquals(5, view.lastLockout.failedAttempts());
    List<String> failedReasons = audit.events().stream()
        .filter(LoginFailed.class::isInstance)
        .map(e -> ((LoginFailed) e).reason()).toList();
    assertEquals(List.of("Locked out while the attempt was in flight"), failedReasons);
    List<String> invalidations = audit.events().stream()
        .filter(SessionInvalidated.class::isInstance)
        .map(e -> ((SessionInvalidated) e).reason()).toList();
    assertEquals(List.of(LoginView.REASON_LOGIN_NOT_CONFIRMED), invalidations,
        "the session is ended, and the post-login rotation must not have run");
  }

  @Test
  @DisplayName("confirmSuccess throws: fail closed - the login is undone and the exception reaches the caller")
  void failingConfirmationUndoesTheLogin() {
    RecordingPolicy policy = new RecordingPolicy();
    policy.confirmFailure = new IllegalStateException("attempt store unreachable");
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    PlainLoginView view = navigate(PlainLoginView.class);

    assertThrows(IllegalStateException.class, () -> submitEndingTheSession("alice", PASSWORD));

    assertTrue(boundSubject().isEmpty(), "a login the policy could not confirm must not stand");
    assertFalse(view.navigated);
    assertEquals(List.of("Login attempt policy failed while confirming the login"),
        audit.events().stream().filter(LoginFailed.class::isInstance)
            .map(e -> ((LoginFailed) e).reason()).toList());
    assertEquals(List.of(LoginView.REASON_LOGIN_NOT_CONFIRMED),
        audit.events().stream().filter(SessionInvalidated.class::isInstance)
            .map(e -> ((SessionInvalidated) e).reason()).toList());
  }

  // ── the opt-out ──

  @Test
  @DisplayName("throttleLoginAttempts() == false: the view never touches the policy")
  void optOutLeavesThePolicyAlone() {
    RecordingPolicy policy = new RecordingPolicy();
    policy.before = LoginAttemptDecision.lockedOut(Duration.ofMinutes(1), 9);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    SelfThrottlingLoginView view = navigate(SelfThrottlingLoginView.class);

    submit("alice", "not the password");
    submit("alice", PASSWORD);

    assertTrue(policy.calls.isEmpty(), "the service behind this view owns the protocol: " + policy.calls);
    assertEquals(2, view.checks);
    assertTrue(view.navigated);
    assertNull(view.lastLockout);
  }

  // ── fixtures ──

  /** A view whose credential check knows nothing about throttling. */
  @Route("test/throttle-plain-login")
  public static class PlainLoginView extends LoginView {
    int checks;
    int failedReactions;
    int unavailableReactions;
    boolean navigated;
    LoginAttemptDecision.LockedOut lastLockout;
    RuntimeException nextFailure;

    @Override public boolean checkCredentials() {
      checks++;
      if (nextFailure != null) {
        throw nextFailure;
      }
      boolean ok = PASSWORD.equals(password());
      if (ok) {
        SubjectStores.subjectStore().setCurrentSubject(username(), String.class);
      }
      return ok;
    }

    @Override public void navigateToApp() {
      navigated = true;
    }

    @Override public void reactOnFailedLogin() {
      failedReactions++;
    }

    @Override protected void reactOnLockedOut(LoginAttemptDecision.LockedOut lockout) {
      lastLockout = lockout;
    }

    @Override protected void reactOnVerificationUnavailable() {
      unavailableReactions++;
    }
  }

  /** A view written before 00.84.00: only the three abstract methods. */
  @Route("test/throttle-minimal-login")
  public static class MinimalLoginView extends LoginView {
    int checks;
    int failedReactions;
    RuntimeException nextFailure;

    @Override public boolean checkCredentials() {
      checks++;
      if (nextFailure != null) {
        throw nextFailure;
      }
      return PASSWORD.equals(password());
    }

    @Override public void navigateToApp() {
      // not reached in these tests
    }

    @Override public void reactOnFailedLogin() {
      failedReactions++;
    }
  }

  /** A view whose authentication service throttles itself. */
  @Route("test/throttle-self-login")
  public static class SelfThrottlingLoginView extends PlainLoginView {
    @Override protected boolean throttleLoginAttempts() {
      return false;
    }
  }

  /** Records the protocol; answers what the test tells it to. */
  private static final class RecordingPolicy implements LoginAttemptPolicy {
    final List<String> calls = new ArrayList<>();
    final List<LoginAttemptContext> contexts = new ArrayList<>();
    LoginAttemptDecision before = LoginAttemptDecision.allowed();
    LoginAttemptDecision confirm = LoginAttemptDecision.allowed();
    RuntimeException confirmFailure;

    private void record(String call, LoginAttemptContext context) {
      calls.add(call);
      contexts.add(context);
    }

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
      record("beforeAttempt", context);
      return before;
    }

    @Override public void recordSuccess(LoginAttemptContext context) {
      record("recordSuccess", context);
    }

    @Override public void recordFailure(LoginAttemptContext context) {
      record("recordFailure", context);
    }

    @Override public LoginAttemptDecision confirmSuccess(LoginAttemptContext context) {
      record("confirmSuccess", context);
      if (confirmFailure != null) {
        throw confirmFailure;
      }
      return confirm;
    }

    @Override public void abandonAttempt(LoginAttemptContext context) {
      record("abandonAttempt", context);
    }
  }
}
