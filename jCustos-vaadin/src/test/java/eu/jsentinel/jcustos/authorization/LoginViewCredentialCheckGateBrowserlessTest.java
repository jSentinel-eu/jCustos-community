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
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;
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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-063 (CWE-770): the library {@link LoginView} enters the credential-check gate of the
 * registered {@link LoginAttemptPolicy} around {@link LoginView#checkCredentials()}. Real routes
 * in the browserless UI, real gates; the policies are the real {@link InMemoryLoginAttemptPolicy}
 * or a hand-written recorder.
 */
@DisplayName("JS-SEC-063 - LoginView bounds concurrent credential checks")
class LoginViewCredentialCheckGateBrowserlessTest extends BrowserlessTest {

  private static final String PASSWORD = "correct horse battery";
  private static final Duration RETRY_AFTER = Duration.ofSeconds(4);

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

  private static CredentialCheckGate singlePermitGate() {
    return CredentialCheckGate.of(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(1)
        .withGateWait(Duration.ZERO)
        .withGateRetryAfter(RETRY_AFTER), Clock.systemUTC(), null);
  }

  @Test
  @DisplayName("every permit busy: no check, beforeAttempt then abandonAttempt, reactOnCredentialCheckDeferred with the retry-after, RateLimitExceeded, no LoginFailed")
  void busyGateDefersTheAttempt() {
    GatedPolicy policy = new GatedPolicy(singlePermitGate());
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    GateLoginView view = navigate(GateLoginView.class);
    CredentialCheckGate.Admission.Entered held = assertInstanceOf(
        CredentialCheckGate.Admission.Entered.class, policy.gate.enter());

    submit("alice", PASSWORD);

    assertEquals(List.of("beforeAttempt", "abandonAttempt"), policy.calls,
        "the reservation is given back, nothing is reported as a failure");
    assertEquals(0, view.checks, "the credentials were not evaluated");
    assertEquals(List.of(RETRY_AFTER), view.deferrals);
    assertEquals(0, view.failedReactions);
    assertFalse(view.navigated);
    assertTrue(audit.all(LoginFailed.class).isEmpty());
    RateLimitExceeded event = audit.single(RateLimitExceeded.class);
    assertEquals(CredentialCheckGate.AUDIT_SCOPE, event.scope());
    assertEquals("", view.password(), "the password does not stay in the field");

    held.close();
    submit("alice", PASSWORD);
    assertTrue(view.navigated, "with the permit free again the login goes through");
    assertEquals(1, view.checks);
  }

  @Test
  @DisplayName("a view written before 00.84.00 answers a deferral through reactOnVerificationUnavailable, then reactOnFailedLogin")
  void deferralFallsBackToTheOlderHooks() {
    GatedPolicy policy = new GatedPolicy(singlePermitGate());
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    MinimalGateLoginView view = navigate(MinimalGateLoginView.class);
    CredentialCheckGate.Admission.Entered held = assertInstanceOf(
        CredentialCheckGate.Admission.Entered.class, policy.gate.enter());

    submit("alice", PASSWORD);

    assertEquals(0, view.checks);
    assertEquals(1, view.failedReactions);
    held.close();
  }

  @Test
  @DisplayName("the permit is held only while checkCredentials() runs - also when it throws")
  void permitIsReleasedAfterTheCheck() {
    GatedPolicy policy = new GatedPolicy(singlePermitGate());
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    GateLoginView view = navigate(GateLoginView.class);

    submit("alice", "wrong");
    assertEquals(1, view.inUseDuringCheck, "the check ran inside the gate");
    assertEquals(0, policy.gate.inUse());

    view.nextFailure = new IllegalStateException("directory down");
    submit("alice", PASSWORD);
    assertEquals(0, policy.gate.inUse());

    submit("alice", PASSWORD);
    assertTrue(view.navigated);
    assertEquals(0, policy.gate.inUse());
  }

  @Test
  @DisplayName("the real policy: deferrals count nothing - more than the threshold, then the correct password logs in")
  void deferralsDoNotLockTheAccount() {
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(1)
        .withGateWait(Duration.ZERO)
        .withGateRetryAfter(RETRY_AFTER), Clock.systemUTC(), audit);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    GateLoginView view = navigate(GateLoginView.class);
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();
    CredentialCheckGate.Admission.Entered held = assertInstanceOf(
        CredentialCheckGate.Admission.Entered.class, policy.credentialCheckGate().enter());

    for (int i = 0; i < threshold + 2; i++) {
      submit("alice", PASSWORD);
    }
    assertEquals(threshold + 2, view.deferrals.size(),
        "every attempt is deferred - none is refused by left-over reservations");
    held.close();

    submit("alice", PASSWORD);
    assertTrue(view.navigated);
    assertEquals(Optional.of("alice"), SubjectStores.subjectStore().currentSubject(String.class));
  }

  @Test
  @DisplayName("throttleLoginAttempts() == false: the view does not enter the gate either")
  void optOutSkipsTheGate() {
    GatedPolicy policy = new GatedPolicy(singlePermitGate());
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    SelfThrottlingGateLoginView view = navigate(SelfThrottlingGateLoginView.class);
    CredentialCheckGate.Admission.Entered held = assertInstanceOf(
        CredentialCheckGate.Admission.Entered.class, policy.gate.enter());

    submit("alice", PASSWORD);

    assertTrue(view.navigated);
    assertTrue(view.deferrals.isEmpty());
    assertTrue(policy.calls.isEmpty());
    held.close();
  }

  // ── fixtures ──

  /** A view that records every hook. */
  @Route("test/gate-login")
  public static class GateLoginView extends LoginView {
    int checks;
    int failedReactions;
    int inUseDuringCheck = -1;
    boolean navigated;
    final List<Duration> deferrals = new ArrayList<>();
    RuntimeException nextFailure;

    @Override public boolean checkCredentials() {
      checks++;
      inUseDuringCheck = JCustosServiceResolver.loginAttemptPolicy().credentialCheckGate().inUse();
      if (nextFailure != null) {
        RuntimeException failure = nextFailure;
        nextFailure = null;
        throw failure;
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

    @Override protected void reactOnCredentialCheckDeferred(Duration retryAfter) {
      deferrals.add(retryAfter);
    }
  }

  /** A view written before 00.84.00: only the three abstract methods. */
  @Route("test/gate-minimal-login")
  public static class MinimalGateLoginView extends LoginView {
    int checks;
    int failedReactions;

    @Override public boolean checkCredentials() {
      checks++;
      return PASSWORD.equals(password());
    }

    @Override public void navigateToApp() {
      // not reached in these tests
    }

    @Override public void reactOnFailedLogin() {
      failedReactions++;
    }
  }

  /** A view whose authentication service runs the protocol itself. */
  @Route("test/gate-self-login")
  public static class SelfThrottlingGateLoginView extends GateLoginView {
    @Override protected boolean throttleLoginAttempts() {
      return false;
    }
  }

  /** Records the protocol and hands out a gate the test controls. */
  private static final class GatedPolicy implements LoginAttemptPolicy {
    final List<String> calls = new ArrayList<>();
    final CredentialCheckGate gate;

    GatedPolicy(CredentialCheckGate gate) {
      this.gate = gate;
    }

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
      calls.add("beforeAttempt");
      return LoginAttemptDecision.allowed();
    }

    @Override public void recordSuccess(LoginAttemptContext context) {
      calls.add("recordSuccess");
    }

    @Override public void recordFailure(LoginAttemptContext context) {
      calls.add("recordFailure");
    }

    @Override public LoginAttemptDecision confirmSuccess(LoginAttemptContext context) {
      calls.add("confirmSuccess");
      return LoginAttemptDecision.allowed();
    }

    @Override public void abandonAttempt(LoginAttemptContext context) {
      calls.add("abandonAttempt");
    }

    @Override public CredentialCheckGate credentialCheckGate() {
      return gate;
    }
  }
}
