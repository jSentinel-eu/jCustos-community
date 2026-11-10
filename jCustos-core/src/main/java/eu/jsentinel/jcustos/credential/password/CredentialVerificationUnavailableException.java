/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.PublicFailureType;

/**
 * Signals that a credential could not be verified - not that it is wrong.
 *
 * <p>JS-SEC-126 (CWE-703, CWE-645): the hashing pipeline reports load
 * shedding as {@link PublicFailureType#TEMPORARILY_UNAVAILABLE}. A
 * component with a richer result type passes that on as it is. A component
 * behind a boolean contract - above all
 * {@code AuthenticationService.checkCredentials(...)} - has only "valid" and
 * "invalid" to choose from, and "invalid" would count a correct password as
 * a failed attempt. Such a component throws this exception instead:</p>
 *
 * <pre>{@code
 * CredentialVerificationResult result = hashing.verify(password, storedHash);
 * CredentialVerificationUnavailableException.throwIfUnavailable(result);
 * return result instanceof CredentialVerificationResult.Verified;
 * }</pre>
 *
 * <p>Whoever drives the login - {@code StandaloneLoginFlow}, a REST handler,
 * a login view - treats the exception as a third outcome: it releases the
 * attempt with {@code LoginAttemptPolicy.abandonAttempt(...)}, records no
 * failure, writes no "login failed" audit event and answers "try again
 * later" (HTTP 503 or 429).</p>
 *
 * <p>The message never says which account was involved or why the
 * verification was shed.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class CredentialVerificationUnavailableException extends RuntimeException {

  /** Creates the exception with its fixed, non-revealing message. */
  public CredentialVerificationUnavailableException() {
    super("credential verification is temporarily unavailable");
  }

  /**
   * Throws when {@code result} reports that the verification could not be
   * carried out; returns normally for every other result.
   *
   * @param result a verification result; must not be {@code null}
   * @throws CredentialVerificationUnavailableException when
   *         {@link CredentialVerificationResult#temporarilyUnavailable()}
   */
  public static void throwIfUnavailable(CredentialVerificationResult result) {
    if (result.temporarilyUnavailable()) {
      throw new CredentialVerificationUnavailableException();
    }
  }
}
