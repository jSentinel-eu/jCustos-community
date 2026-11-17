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
package eu.jsentinel.jcustos.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Duration;
import java.util.Objects;

/**
 * Writes the answer to a throttled request: {@code 429 Too Many Requests} with a
 * {@code Retry-After} header (RFC 9110 §10.2.3, RFC 6585 §4).
 *
 * <p>The REST adapter has no login endpoint of its own; the application's login handler drives
 * the {@code LoginAttemptPolicy}. Whenever that handler refuses an attempt without evaluating it
 * - a lockout, an address lockout (JS-SEC-062), a credential check the policy's gate deferred
 * (JS-SEC-063) - it answers through this class, so every refusal looks the same on the wire and
 * the retry-after is never rounded down to a moment at which the client is refused again:
 *
 * <pre>{@code
 * CredentialCheckGate gate = policy.credentialCheckGate();
 * if (policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.LockedOut lockout) {
 *   RestThrottleResponses.tooManyRequests(response, lockout.remaining());
 *   return;
 * }
 * CredentialCheckGate.Admission.Entered permit;
 * switch (gate.enter()) {
 *   case CredentialCheckGate.Admission.Deferred deferred -> {
 *     policy.abandonAttempt(attempt);              // no verdict, nothing counted
 *     RestThrottleResponses.tooManyRequests(response, deferred.retryAfter());
 *     return;
 *   }
 *   case CredentialCheckGate.Admission.Entered entered -> permit = entered;
 * }
 * boolean valid;
 * try {
 *   valid = checkCredentials(credentials);         // the password check runs inside the gate
 * } catch (CredentialVerificationUnavailableException shed) {
 *   policy.abandonAttempt(attempt);                // no verdict: answer "try again later"
 *   ...
 *   return;
 * } catch (RuntimeException checkFailed) {
 *   policy.recordFailure(attempt, "Credential check failed");  // counted like a wrong password
 *   ...
 *   return;
 * } finally {
 *   permit.close();                                // every admitted check gives its permit back
 * }
 * // valid: confirmSuccess(attempt) - a LockedOut answer is a 429 as well; otherwise recordFailure
 * }</pre>
 *
 * <p>The permit of an {@code Entered} admission must be closed whatever the check does: a login
 * handler that only tests {@code gate.enter() instanceof Deferred} keeps every permit it is
 * granted, and after {@code maxConcurrentCredentialChecks} logins every further one is deferred
 * until the process restarts.
 *
 * <p>The body is the generic {@link #DEFAULT_BODY}; it says nothing about which limit was hit or
 * whether the account exists.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestThrottleResponses {

  /** Name of the {@code Retry-After} response header. */
  public static final String RETRY_AFTER = "Retry-After";

  /** Body of {@link #tooManyRequests(RestResponse, Duration)}: {@value}. */
  public static final String DEFAULT_BODY = "Too Many Requests";

  /** Smallest {@code Retry-After} written, in seconds: {@value}. */
  public static final long MIN_RETRY_AFTER_SECONDS = 1L;

  private RestThrottleResponses() {
  }

  /**
   * Answers {@code 429} with a {@code Retry-After} header and the generic {@link #DEFAULT_BODY}.
   *
   * @param response   the response to write; non-null
   * @param retryAfter when the client may try again; non-null
   */
  public static void tooManyRequests(RestResponse response, Duration retryAfter) {
    tooManyRequests(response, retryAfter, DEFAULT_BODY);
  }

  /**
   * Answers {@code 429} with a {@code Retry-After} header and {@code body}, for an application
   * whose error bodies have a format of their own.
   *
   * @param response   the response to write; non-null
   * @param retryAfter when the client may try again; non-null
   * @param body       the body; non-null, and it must not tell which limit was hit
   */
  public static void tooManyRequests(RestResponse response, Duration retryAfter, String body) {
    Objects.requireNonNull(response, "response");
    Objects.requireNonNull(body, "body");
    String header = retryAfterValue(retryAfter);
    response.status(HttpStatus.TOO_MANY_REQUESTS.code());
    response.header(RETRY_AFTER, header);
    response.body(body);
  }

  /**
   * The value of a {@code Retry-After} header for {@code retryAfter}: whole seconds, rounded up,
   * at least {@link #MIN_RETRY_AFTER_SECONDS}. Rounding down would send the client back before
   * the limit has lifted - {@code 1.9 s} becomes {@code 2}, not {@code 1}. For a front end that
   * writes its headers itself.
   *
   * @param retryAfter when the client may try again; non-null; zero or negative yields the
   *                   minimum
   * @return the header value, a decimal number of seconds
   */
  public static String retryAfterValue(Duration retryAfter) {
    Objects.requireNonNull(retryAfter, "retryAfter");
    if (retryAfter.isNegative() || retryAfter.isZero()) {
      return Long.toString(MIN_RETRY_AFTER_SECONDS);
    }
    long seconds = retryAfter.getSeconds();
    if (retryAfter.getNano() > 0 && seconds < Long.MAX_VALUE) {
      seconds++;
    }
    return Long.toString(Math.max(MIN_RETRY_AFTER_SECONDS, seconds));
  }
}
