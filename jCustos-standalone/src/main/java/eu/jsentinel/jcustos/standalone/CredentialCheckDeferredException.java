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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;

import java.time.Duration;
import java.util.Objects;

/**
 * Thrown by {@link StandaloneLoginFlow#login} when the credential-check gate of the
 * {@link eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy} deferred the attempt (JS-SEC-063,
 * CWE-770): every permit stayed busy for the whole wait, so the credentials were not checked.
 *
 * <p>Like its superclass it is no verdict: the attempt was given back to the policy, nothing was
 * counted against the account, no {@code LoginFailed} was written. A caller that already
 * catches {@link CredentialVerificationUnavailableException} handles the deferral without a
 * change; one that wants to tell the user when to try again reads {@link #retryAfter()} - an
 * HTTP front end answers 429 with a {@code Retry-After} header.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class CredentialCheckDeferredException extends CredentialVerificationUnavailableException {

  private static final long serialVersionUID = 1L;

  private final Duration retryAfter;

  /**
   * @param retryAfter when the caller may try again; positive
   */
  public CredentialCheckDeferredException(Duration retryAfter) {
    Objects.requireNonNull(retryAfter, "retryAfter");
    if (retryAfter.isNegative() || retryAfter.isZero()) {
      throw new IllegalArgumentException("retryAfter must be positive");
    }
    this.retryAfter = retryAfter;
  }

  /**
   * @return when the caller may try again; positive
   */
  public Duration retryAfter() {
    return retryAfter;
  }
}
