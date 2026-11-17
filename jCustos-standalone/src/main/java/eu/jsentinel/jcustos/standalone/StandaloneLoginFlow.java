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
package eu.jsentinel.jcustos.standalone;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Drives the login lifecycle for standalone applications without any
 * UI-toolkit assumption. A typical CLI / desktop main loop calls
 * {@link #login(Object, String)} once with the user-entered credentials
 * and the displayed username (used for brute-force tracking + audit),
 * then carries on with the request-handling loop.
 * <p>
 * Behaviour mirrors the Vaadin / REST flow:
 * <ol>
 *   <li>Ask {@link LoginAttemptPolicy} whether the username is currently
 *       throttled — return {@link LoginResult#lockedOut} on a hit so the
 *       caller can render a wait time. An allowed attempt is reserved by
 *       the policy (JS-SEC-123) and is reported back exactly once, by one
 *       of the next three steps.</li>
 *   <li>Enter the policy's {@link CredentialCheckGate} (JS-SEC-063, CWE-770).
 *       When it defers the attempt - every permit busy for the whole wait -
 *       the attempt is given back to the policy, nothing is counted, and
 *       {@link CredentialCheckDeferredException} reaches the caller with the
 *       retry-after. The gate is unbounded unless the policy's
 *       {@code LoginAttemptLimits} set {@code maxConcurrentCredentialChecks}.</li>
 *   <li>Delegate to the registered {@link AuthenticationService}; the permit is
 *       given back as soon as {@code checkCredentials} has returned.</li>
 *   <li>On success — load the subject, confirm the success with the
 *       policy, bind the subject into the active
 *       {@link eu.jsentinel.jcustos.authorization.api.SubjectStore} and
 *       emit a {@link LoginSucceeded} audit event. If the policy answers
 *       that the key was locked in the meantime, the login is denied with
 *       {@link LoginResult#lockedOut} and no subject is bound.</li>
 *   <li>On failure — record the failure on the policy, with the reason.
 *       The policy publishes the one {@link LoginFailed} audit event of the
 *       rejected login (see {@link LoginAttemptPolicy#recordFailure}); until
 *       00.84.00 this flow published a second one.</li>
 *   <li>No verdict — the {@link AuthenticationService} threw
 *       {@link CredentialVerificationUnavailableException} because the
 *       credential check was shed under load (JS-SEC-126). The attempt is
 *       given back to the policy, nothing is counted, no
 *       {@link LoginFailed} is written, and the exception reaches the
 *       caller, who answers "try again later".</li>
 *   <li>The check failed — the {@link AuthenticationService} threw any other
 *       {@link RuntimeException} (exit review XR09-6, CWE-755). Until then this
 *       counted as "no verdict" as well, so input that made the check throw
 *       could be tried without limit. Now it is recorded as a failed attempt
 *       with the reason {@link #REASON_CHECK_FAILED} and answered with
 *       {@link LoginResult#rejected}, exactly like wrong credentials; the
 *       exception is logged with its class only.</li>
 * </ol>
 *
 * <p>The flow has no client address; the address counter of the policy
 * (JS-SEC-062) therefore does not apply to it.
 *
 * @param <T> the credentials type
 * @param <U> the subject type
 */
public final class StandaloneLoginFlow<T, U> {

  /**
   * Reason of the {@link LoginFailed} event when the {@link AuthenticationService} accepted
   * the credentials but returned no subject.
   *
   * @since 00.84.00
   */
  public static final String REASON_NO_SUBJECT = "Subject lookup returned null";

  /**
   * Reason of the {@link LoginFailed} event this flow publishes itself: the key was locked
   * while the credentials were being checked (JS-SEC-123). The policy reports nothing in that
   * case, so the flow does.
   *
   * @since 00.84.00
   */
  public static final String REASON_LOCKED_IN_FLIGHT = "Locked out while the attempt was in flight";

  /**
   * Reason of the failed attempt the policy records when the {@link AuthenticationService}
   * threw anything but {@link CredentialVerificationUnavailableException} (exit review
   * XR09-6, CWE-755). The caller sees {@link LoginResult.Rejected}, as for wrong credentials.
   *
   * @since 00.84.00
   */
  public static final String REASON_CHECK_FAILED = "Credential check failed";

  private final AuthenticationService<T, U> authenticationService;
  private final Clock clock;

  /**
   * Uses the SPI-resolved {@link AuthenticationService} and the system
   * UTC clock. The most common entry point.
   */
  public StandaloneLoginFlow() {
    this(JCustosServiceResolver.authenticationService(), Clock.systemUTC());
  }

  /**
   * Test seam. Pass an explicit {@link AuthenticationService} and clock
   * so tests can avoid SPI registration churn.
   */
  public StandaloneLoginFlow(AuthenticationService<T, U> authenticationService, Clock clock) {
    this.authenticationService = Objects.requireNonNull(authenticationService, "authenticationService");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Runs one login attempt.
   *
   * @param credentials credentials accepted by the configured
   *                    {@link AuthenticationService}
   * @param username    displayed username, used for brute-force tracking
   *                    and audit; may be {@code null} or empty for
   *                    anonymous flows (all of which share one throttle key)
   * @return the outcome
   * @throws CredentialVerificationUnavailableException when the
   *         {@link AuthenticationService} could not verify the credentials
   *         at all (JS-SEC-126). This is neither {@link LoginResult.Rejected}
   *         nor a failed attempt: nothing was counted and no
   *         {@link LoginFailed} was written. Map it to "temporarily
   *         unavailable, try again" (HTTP 503 or 429). Any other
   *         {@link RuntimeException} of the service is a failed attempt and
   *         returns {@link LoginResult.Rejected} (exit review XR09-6).
   *         The subclass {@link CredentialCheckDeferredException} means the
   *         credential-check gate deferred the attempt (JS-SEC-063); it
   *         carries the retry-after.
   */
  public LoginResult<U> login(T credentials, String username) {
    LoginAttemptPolicy policy = JCustosServiceResolver.loginAttemptPolicy();
    LoginAttemptContext attempt = LoginAttemptContext.now(username, null, null);
    // obtained before the reservation: a policy that cannot hand out its gate reserves nothing
    CredentialCheckGate gate = policy.credentialCheckGate();

    LoginAttemptDecision decision = policy.beforeAttempt(attempt);
    if (decision instanceof LoginAttemptDecision.LockedOut lockout) {
      return LoginResult.lockedOut(lockout);
    }

    // JS-SEC-063 (CWE-770): at most maxConcurrentCredentialChecks checks run at once
    CredentialCheckGate.Admission.Entered permit;
    switch (gate.enter()) {
      case CredentialCheckGate.Admission.Deferred deferred -> {
        // no verdict: the reservation is released, nothing is counted, no LoginFailed
        policy.abandonAttempt(attempt);
        throw new CredentialCheckDeferredException(deferred.retryAfter());
      }
      case CredentialCheckGate.Admission.Entered entered -> permit = entered;
    }

    boolean ok;
    U subject = null;
    try {
      try {
        ok = authenticationService.checkCredentials(credentials);
      } finally {
        permit.close();
      }
      if (ok) {
        subject = authenticationService.loadSubject(credentials);
      }
    } catch (CredentialVerificationUnavailableException noVerdict) {
      // JS-SEC-126 (CWE-703): "could not verify" is not "wrong". The reservation taken in
      // beforeAttempt is released (JS-SEC-123), no failure is recorded, no LoginFailed is
      // audited; the caller sees the exception as the third outcome.
      policy.abandonAttempt(attempt);
      throw noVerdict;
    } catch (RuntimeException checkFailure) {
      // XR09-6 (CWE-755): only the exception above means "no verdict". Anything else counts as
      // a failed attempt - otherwise input that makes the check throw would buy unlimited
      // guesses - and looks like wrong credentials. The class only: the message may carry
      // what was entered.
      HasLogger.staticLogger().warn("Login check failed with {}; counted as a failed attempt",
          checkFailure.getClass().getName());
      policy.recordFailure(attempt, REASON_CHECK_FAILED);
      return LoginResult.rejected();
    }

    // JS-SEC-123 follow-up: the policy's recordFailure is the audit point of a rejected login and
    // publishes LoginFailed itself; a second event here audited every rejected login twice.
    if (!ok) {
      policy.recordFailure(attempt, LoginAttemptPolicy.REASON_CREDENTIALS_REJECTED);
      return LoginResult.rejected();
    }
    if (subject == null) {
      policy.recordFailure(attempt, REASON_NO_SUBJECT);
      return LoginResult.rejected();
    }

    // JS-SEC-123 (CWE-367, CWE-307): the key can have been locked while the credentials were
    // being checked. A correct password neither lifts that lockout nor passes it.
    if (policy.confirmSuccess(attempt) instanceof LoginAttemptDecision.LockedOut lockout) {
      audit(new LoginFailed(now(), username, null, REASON_LOCKED_IN_FLIGHT));
      return LoginResult.lockedOut(lockout);
    }
    SubjectStores.subjectStore().setCurrentSubject(subject, authenticationService.subjectType());
    audit(new LoginSucceeded(now(), username, null, null));
    return LoginResult.success(subject);
  }

  /**
   * Removes the current subject from the {@link eu.jsentinel.jcustos.authorization.api.SubjectStore}.
   * Does not emit an audit event — that is the {@code LogoutService}'s
   * responsibility, which standalone applications wire up explicitly
   * when they need it.
   */
  public void logout() {
    SubjectStores.subjectStore().deleteCurrentSubject(authenticationService.subjectType());
    // V00.74: clear the propagation slot so a subsequent thread (or a
    // re-login in the same thread) starts without a stale credential.
    // Best-effort: the SPI store may not be registered in setups that
    // do not opt into V00.74 propagation.
    JCustosServiceResolver.findTokenCredentialStore()
        .ifPresent(eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore::clear);
  }

  /**
   * V00.74 — bind a {@link TokenCredential} for the current thread so
   * {@code @PropagateToken}-annotated wrappers can forward it to
   * downstream HTTP calls. Convenience for the standalone / CLI demo
   * pattern (after a successful login, the caller has the token at
   * hand and binds it here).
   *
   * <p>Looks up the SPI-resolved
   * {@code TokenCredentialStore} (see Konzept §6.3).
   *
   * @param credential the credential to bind; non-null
   */
  public void bindToken(TokenCredential credential) {
    JCustosServiceResolver.tokenCredentialStore().bind(credential);
  }

  private Instant now() {
    return Instant.now(clock);
  }

  private static void audit(eu.jsentinel.jcustos.audit.AuditEvent event) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // never block login because the audit sink failed
    }
  }

  /**
   * Outcome of a single {@link #login} call.
   *
   * @param <U> subject type
   */
  public sealed interface LoginResult<U>
      permits LoginResult.Success, LoginResult.Rejected, LoginResult.LockedOut {

    /** Credentials were valid and a subject was bound into the store. */
    record Success<U>(U subject) implements LoginResult<U> { }

    /** Credentials were invalid (wrong password, unknown user, etc.). */
    record Rejected<U>() implements LoginResult<U> { }

    /**
     * The username is currently locked out. The caller should not retry yet. Also the outcome
     * when the lockout set in while the credentials were being checked (JS-SEC-123), or when
     * the throttle is full of live lockouts and refuses further keys (JS-SEC-122).
     */
    record LockedOut<U>(LoginAttemptDecision.LockedOut decision) implements LoginResult<U> { }

    static <U> LoginResult<U> success(U subject) {
      return new Success<>(subject);
    }

    static <U> LoginResult<U> rejected() {
      return new Rejected<>();
    }

    static <U> LoginResult<U> lockedOut(LoginAttemptDecision.LockedOut decision) {
      return new LockedOut<>(decision);
    }
  }
}
