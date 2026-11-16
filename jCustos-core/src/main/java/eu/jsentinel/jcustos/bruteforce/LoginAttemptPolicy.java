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
package eu.jsentinel.jcustos.bruteforce;

/**
 * Policy that throttles repeated failed login attempts.
 * <p>
 * The expected call sequence inside an authentication flow is:
 * <ol>
 *   <li>{@link #beforeAttempt(LoginAttemptContext)} — before the
 *       password check. If the decision is not
 *       {@link LoginAttemptDecision#allowed() allowed}, skip the
 *       check and return the user a generic "try again later" error.</li>
 *   <li>Exactly one report for every allowed attempt:
 *       <ul>
 *         <li>{@link #confirmSuccess(LoginAttemptContext)} (or the older
 *             {@link #recordSuccess(LoginAttemptContext)}) — the check
 *             succeeded;</li>
 *         <li>{@link #recordFailure(LoginAttemptContext)} — the check
 *             rejected the credentials;</li>
 *         <li>{@link #abandonAttempt(LoginAttemptContext)} — the check
 *             could not be carried out (load shedding, an outage, an
 *             exception) and says nothing about the credentials.</li>
 *       </ul></li>
 * </ol>
 *
 * <p><strong>An allowed attempt is a reservation</strong> (JS-SEC-123,
 * CWE-367). The shipped policies count the attempt as "in flight" when
 * they allow it and release it with the report, so that requests arriving
 * in parallel see each other: with a threshold of five, the sixth
 * concurrent request is denied although none of the first five has failed
 * yet. A reservation that is never reported lapses after a short time, so
 * a caller that forgets the report degrades the throttle for a moment
 * instead of locking the key for good.
 *
 * <p>Implementations decide which key to track by — typically a
 * combination of {@code username} and {@code clientAddress}. The default
 * {@link InMemoryLoginAttemptPolicy} tracks the combined key plus the
 * user name alone so an attacker cannot cycle clients to escape the
 * counter.
 */
public interface LoginAttemptPolicy {

  /**
   * Decides whether the attempt described by {@code context} may proceed.
   * The failure counter is not touched here — that happens in
   * {@link #recordFailure(LoginAttemptContext)} after the actual check —
   * but an implementation may reserve the attempt, see the type
   * description.
   *
   * @param context attempt context
   * @return decision; never {@code null}
   */
  LoginAttemptDecision beforeAttempt(LoginAttemptContext context);

  /**
   * Reports whether {@code context} is locked out right now, without
   * starting an attempt.
   * <p>
   * For a user interface that wants to show "locked for another 12
   * minutes" outside a login. Since 00.84.00 {@link #beforeAttempt} reserves
   * the attempt it allows, so calling it merely to look leaves a
   * reservation behind until that lapses. The default asks
   * {@code beforeAttempt} and gives an allowed attempt straight back; the
   * shipped policies answer from their state without reserving anything.
   *
   * @param context attempt context
   * @return the lockout in force, or {@link LoginAttemptDecision#allowed()};
   *         never {@code null}
   * @since 00.84.00
   */
  default LoginAttemptDecision peek(LoginAttemptContext context) {
    LoginAttemptDecision decision = beforeAttempt(context);
    if (decision instanceof LoginAttemptDecision.Allowed) {
      abandonAttempt(context);
    }
    return decision;
  }

  /**
   * Records a successful attempt. Implementations typically reset the
   * per-key failure counter. A lockout that is in force is
   * <strong>not</strong> lifted (JS-SEC-123): callers that must know
   * whether the login may complete use
   * {@link #confirmSuccess(LoginAttemptContext)} instead.
   *
   * @param context attempt context
   */
  void recordSuccess(LoginAttemptContext context);

  /**
   * The reason {@link #recordFailure(LoginAttemptContext)} records in the
   * {@code LoginFailed} event.
   *
   * @since 00.84.00
   */
  String REASON_CREDENTIALS_REJECTED = "Credentials rejected";

  /**
   * Records a failed attempt. Implementations typically increment a
   * per-key counter and may escalate the throttling decision.
   * <p>
   * <strong>The audit point of a rejected login.</strong> The shipped
   * policies - {@link InMemoryLoginAttemptPolicy},
   * {@link StoreBackedLoginAttemptPolicy} and {@link NoopLoginAttemptPolicy} -
   * publish exactly one {@code LoginFailed} event per call, with the user
   * name and client address of {@code context}. Code that reports a rejected
   * login here therefore publishes no {@code LoginFailed} of its own; until
   * 00.84.00 {@code StandaloneLoginFlow} did, and a rejected standalone login
   * was audited twice. A policy written by an application publishes the event
   * as well, or rejected logins behind it go unaudited.
   *
   * @param context attempt context
   */
  void recordFailure(LoginAttemptContext context);

  /**
   * Records a failed attempt with the reason the {@code LoginFailed} event
   * carries, for a caller that knows more than "the credentials were
   * rejected" - for example that the credentials were accepted but no
   * subject could be loaded. The default ignores the reason and delegates to
   * {@link #recordFailure(LoginAttemptContext)}; the shipped policies record
   * it.
   *
   * @param context attempt context
   * @param reason  reason for the audit event; {@code null} or blank means
   *                {@link #REASON_CREDENTIALS_REJECTED}
   * @since 00.84.00
   */
  default void recordFailure(LoginAttemptContext context, String reason) {
    recordFailure(context);
  }

  /**
   * Records a successful attempt and says whether the login may complete.
   * <p>
   * JS-SEC-123 (CWE-367, CWE-307): the key can have been locked while this
   * attempt was being checked — by failures reported in the meantime, or
   * because the report arrives after its reservation lapsed. A correct
   * password must not buy its way past that lockout, and it must not
   * remove it either. In that case the policy keeps the lockout and
   * returns {@link LoginAttemptDecision.LockedOut}; the caller treats the
   * attempt as denied and does <strong>not</strong> establish a session.
   * <p>
   * The default delegates to {@link #recordSuccess(LoginAttemptContext)}
   * and allows, which is the behaviour of every policy written before this
   * method existed.
   *
   * @param context attempt context
   * @return {@link LoginAttemptDecision#allowed()} when the login may
   *         complete, {@link LoginAttemptDecision.LockedOut} when it must
   *         be denied; never {@code null}
   * @since 00.84.00
   */
  default LoginAttemptDecision confirmSuccess(LoginAttemptContext context) {
    recordSuccess(context);
    return LoginAttemptDecision.allowed();
  }

  /**
   * Gives back an allowed attempt whose check produced neither a success
   * nor a failure.
   * <p>
   * JS-SEC-126 (CWE-703): "could not verify" is not "wrong". When the
   * credential check was shed under load or failed with an exception, the
   * caller reports that here: the reservation is released and the failure
   * counter stays where it was. The default does nothing, which is correct
   * for a policy that reserves nothing.
   *
   * @param context attempt context
   * @since 00.84.00
   */
  default void abandonAttempt(LoginAttemptContext context) {
    // nothing reserved, nothing to release
  }
}
