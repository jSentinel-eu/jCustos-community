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
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;

import java.util.Objects;
import java.util.Optional;

/**
 * A password check whose cost does not depend on whether the account exists (JS-SEC-064,
 * CWE-208, CWE-203) - the helper behind the timing contract of
 * {@link eu.jsentinel.jcustos.authentication.AuthenticationService#checkCredentials}.
 *
 * <p>An application with its own user directory typically writes
 * {@code user == null ? false : hashing.verify(password, user.hash())}. The unknown account
 * returns at once, the known one after a full KDF run of a few hundred milliseconds - the
 * difference is measurable over the network and tells an attacker which user names exist.
 * {@link #verify} takes the stored hash as an {@link Optional} and runs a comparable KDF in
 * both cases: {@link PasswordHashingService#verify(char[], String)} for a stored hash,
 * {@link PasswordHashingService#verifyAgainstNothing(char[])} - the pipeline's dummy
 * verification under the active policy, through the same KDF limiter - for none:
 *
 * <pre>{@code
 * public boolean checkCredentials(Credentials credentials) {
 *   Optional<String> storedHash = directory.find(credentials.username()).map(User::passwordHash);
 *   CredentialVerificationResult result = ConstantCostCredentialCheck.verify(
 *       storedHash, credentials.password(), hashing);
 *   CredentialVerificationUnavailableException.throwIfUnavailable(result);
 *   return result instanceof CredentialVerificationResult.Verified;
 * }
 * }</pre>
 *
 * <p><strong>Approximated, not guaranteed.</strong> The helper removes the large, systematic
 * difference - one KDF run or none. It does not make the check constant-time: the directory
 * lookup, the parameters of an old stored hash compared with the dummy hash of the active
 * policy, caches, the garbage collector and the KDF limiter still vary. Keep the throttle of the
 * {@code LoginAttemptPolicy} and the bound of its credential-check gate in place.
 *
 * <p>A blank stored hash is treated like a missing one, so an account without a password costs
 * the same as an unknown one. The result for a missing hash is never
 * {@link CredentialVerificationResult.Verified}: should a pipeline answer the dummy path with
 * {@code Verified}, the helper answers {@link PublicFailureType#INVALID_CREDENTIALS} - fail
 * closed. A dummy verification the KDF limiter shed is passed on as
 * {@link PublicFailureType#TEMPORARILY_UNAVAILABLE}, exactly as a shed real verification is, so
 * the outcome under load does not reveal the account either.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class ConstantCostCredentialCheck {

  private ConstantCostCredentialCheck() {
  }

  /**
   * Verifies {@code password} against {@code storedHash}, or runs the pipeline's dummy
   * verification when there is no stored hash.
   *
   * @param storedHash the encoded hash of the account; empty (or blank) when the account does not
   *                   exist or has no password; non-null
   * @param password   the candidate; caller-owned, neither modified nor zeroed; non-null
   * @param pipeline   the hashing pipeline; non-null
   * @return the pipeline's result for a stored hash; for none, a {@link
   *         CredentialVerificationResult.Failed} - never {@code Verified}
   */
  public static CredentialVerificationResult verify(Optional<String> storedHash, char[] password,
                                                    PasswordHashingService pipeline) {
    Objects.requireNonNull(storedHash, "storedHash");
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(pipeline, "pipeline");
    Optional<String> usable = storedHash.filter(hash -> !hash.isBlank());
    if (usable.isPresent()) {
      return pipeline.verify(password, usable.get());
    }
    CredentialVerificationResult dummy = pipeline.verifyAgainstNothing(password);
    if (dummy instanceof CredentialVerificationResult.Failed failed) {
      return failed;
    }
    // fail closed: there is no account whose password could have matched
    return new CredentialVerificationResult.Failed(
        PublicFailureType.INVALID_CREDENTIALS, InternalAuditEventType.VERIFICATION_DUMMY_PATH);
  }
}
