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

import java.time.Clock;
import java.time.Instant;

/**
 * {@link LoginAttemptPolicy} that never throttles and counts nothing.
 * <p>
 * It still publishes the {@code LoginFailed} event of a rejected login: the
 * policy's {@link #recordFailure(LoginAttemptContext)} is the single audit point
 * of a rejected login (see {@link LoginAttemptPolicy#recordFailure}), and
 * switching throttling off must not switch the audit trail off with it. Until
 * 00.84.00 a rejected login behind this policy was audited by the standalone
 * login flow only.
 * <p>
 * JS-SEC-124 (CWE-1188): until 00.83.00 this was what the resolver handed
 * out when no policy was registered. The resolver default is now a
 * throttling {@link InMemoryLoginAttemptPolicy}; this class remains as the
 * <strong>explicit opt-out</strong> for applications that throttle
 * elsewhere. Registering it — through {@code META-INF/services}, the
 * resolver or the bootstrap — is announced once as
 * {@code bruteforce/noop-policy} and reported by the DX bootstrap.
 */
public final class NoopLoginAttemptPolicy implements LoginAttemptPolicy {

  /** Singleton instance. */
  public static final NoopLoginAttemptPolicy INSTANCE = new NoopLoginAttemptPolicy();

  /** Public for {@link java.util.ServiceLoader} discovery. Prefer {@link #INSTANCE}. */
  public NoopLoginAttemptPolicy() {
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    return LoginAttemptDecision.allowed();
  }

  @Override
  public void recordSuccess(LoginAttemptContext context) {
    // intentionally empty
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    recordFailure(context, REASON_CREDENTIALS_REJECTED);
  }

  @Override
  public void recordFailure(LoginAttemptContext context, String reason) {
    // Nothing is counted; the rejected login is audited.
    LoginFailureAudit.publish(null, Instant.now(Clock.systemUTC()), context, reason);
  }
}
