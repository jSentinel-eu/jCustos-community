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

import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;

import java.time.Instant;

/**
 * Publishes the one {@link LoginFailed} event of a rejected login on behalf of the shipped
 * {@link LoginAttemptPolicy} implementations - the single audit point the SPI describes for
 * {@link LoginAttemptPolicy#recordFailure(LoginAttemptContext)}.
 */
final class LoginFailureAudit {

  private LoginFailureAudit() {
  }

  /**
   * @param auditService the policy's audit service, or {@code null} for the registered one
   * @param at           event time
   * @param context      the attempt; user name and client address go into the event
   * @param reason       the caller's reason; {@code null} or blank means
   *                     {@link LoginAttemptPolicy#REASON_CREDENTIALS_REJECTED}
   */
  static void publish(JCustosAuditService auditService, Instant at,
                      LoginAttemptContext context, String reason) {
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new LoginFailed(
          at,
          context.username() == null ? "" : context.username(),
          context.clientAddress(),
          reason == null || reason.isBlank()
              ? LoginAttemptPolicy.REASON_CREDENTIALS_REJECTED
              : reason));
    } catch (RuntimeException auditFailure) {
      // never block a security decision because the audit sink failed
    }
  }
}
