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

import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
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
 *   <li>Delegate to the registered {@link AuthenticationService}.</li>
 *   <li>On success — load the subject, confirm the success with the
 *       policy, bind the subject into the active
 *       {@link eu.jsentinel.jcustos.authorization.api.SubjectStore} and
 *       emit a {@link LoginSucceeded} audit event. If the policy answers
 *       that the key was locked in the meantime, the login is denied with
 *       {@link LoginResult#lockedOut} and no subject is bound.</li>
 *   <li>On failure — record the failure on the policy and emit a
 *       {@link LoginFailed} audit event.</li>
 *   <li>No verdict — the {@link AuthenticationService} threw, typically
 *       {@link CredentialVerificationUnavailableException} because the
 *       credential check was shed under load (JS-SEC-126). The attempt is
 *       given back to the policy, nothing is counted, no
 *       {@link LoginFailed} is written, and the exception reaches the
 *       caller, who answers "try again later".</li>
 * </ol>
 *
 * @param <T> the credentials type
 * @param <U> the subject type
 */
public final class StandaloneLoginFlow<T, U> {

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
   *         {@link RuntimeException} of the service passes through the same
   *         way.
   */
  public LoginResult<U> login(T credentials, String username) {
    LoginAttemptPolicy policy = JCustosServiceResolver.loginAttemptPolicy();
    LoginAttemptContext attempt = LoginAttemptContext.now(username, null, null);

    LoginAttemptDecision gate = policy.beforeAttempt(attempt);
    if (gate instanceof LoginAttemptDecision.LockedOut lockout) {
      return LoginResult.lockedOut(lockout);
    }

    boolean ok;
    U subject = null;
    try {
      ok = authenticationService.checkCredentials(credentials);
      if (ok) {
        subject = authenticationService.loadSubject(credentials);
      }
    } catch (RuntimeException noVerdict) {
      // JS-SEC-126 (CWE-703): "could not verify" is not "wrong". The reservation taken in
      // beforeAttempt is released (JS-SEC-123), no failure is recorded, no LoginFailed is
      // audited; the caller sees the exception as the third outcome.
      policy.abandonAttempt(attempt);
      throw noVerdict;
    }

    if (!ok) {
      policy.recordFailure(attempt);
      audit(new LoginFailed(now(), username, null, "Credentials rejected"));
      return LoginResult.rejected();
    }
    if (subject == null) {
      policy.recordFailure(attempt);
      audit(new LoginFailed(now(), username, null, "Subject lookup returned null"));
      return LoginResult.rejected();
    }

    // JS-SEC-123 (CWE-367, CWE-307): the key can have been locked while the credentials were
    // being checked. A correct password neither lifts that lockout nor passes it.
    if (policy.confirmSuccess(attempt) instanceof LoginAttemptDecision.LockedOut lockout) {
      audit(new LoginFailed(now(), username, null, "Locked out while the attempt was in flight"));
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
