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
package eu.jsentinel.jcustos.authentication;

/**
 * SPI contract for credential validation and subject loading.
 * <p>
 * Implementations must be registered in
 * {@code META-INF/services/eu.jsentinel.jcustos.authentication.AuthenticationService}.
 *
 * @param <T> the credentials type (e.g. a username/password record)
 * @param <U> the subject (user) type
 */
public interface AuthenticationService<T, U> {

  /**
   * Validates the given credentials.
   *
   * <p><strong>Timing contract (JS-SEC-064, CWE-208, CWE-203).</strong> An unknown account
   * must cost about as much as a known account with a wrong password, and must be answered the
   * same way - {@code false}, never an exception or an early return that a known account does
   * not take. Otherwise the response time tells an attacker which user names exist, and a list
   * of valid accounts is the first step of every spraying or stuffing attack. An implementation
   * that looks up a stored password hash therefore verifies the password against a dummy hash of
   * comparable cost when no account is found;
   * {@link eu.jsentinel.jcustos.credential.password.ConstantCostCredentialCheck} does exactly
   * that on top of the jCustos hashing pipeline. A disabled or locked account is checked in full
   * as well before it is refused.
   *
   * <p>This <em>reduces</em> the timing difference; it does not make the check constant-time.
   * Database lookups, caches, the garbage collector and the KDF limiter still vary, and an
   * attacker who can take many measurements may still see a difference. Treat the contract as
   * one layer next to the throttle of the {@code LoginAttemptPolicy}, not as a guarantee.
   *
   * <p>An implementation that cannot check the credentials at all - the KDF was shed under
   * load, the directory is unreachable - throws
   * {@link eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException}
   * instead of returning {@code false} (JS-SEC-126).
   *
   * @param credentials the credentials to check
   * @return {@code true} if the credentials are valid
   */
  boolean checkCredentials(T credentials);

  /**
   * Loads the subject for the given (already validated) credentials.
   *
   * @param credentials the validated credentials
   * @return the authenticated subject
   */
  U loadSubject(T credentials);

  /**
   * Returns the class token for the subject type.
   * Used by {@link eu.jsentinel.jcustos.authorization.api.SubjectStore}
   * implementations to store and retrieve the subject.
   *
   * @return the subject class
   */
  Class<U> subjectType();

}
