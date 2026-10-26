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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.credential.InternalAuditEventType;

import java.time.Instant;
import java.util.Objects;

/**
 * Failed credential verification, carrying the internal differentiated
 * classification so audit sinks can distinguish unknown user from
 * wrong password, broken envelope, missing provider or rejected pepper
 * key. Since 00.84.00 the same event records a replayed refresh token
 * ({@link InternalAuditEventType#REFRESH_TOKEN_REPLAY}, JS-SEC-071); the
 * {@code username} then carries the subject id of the token family.
 *
 * <p>The {@code internalAuditEventType} stays strictly inside audit
 * sinks; the perimeter still sees the generic
 * {@code INVALID_CREDENTIALS} response (CWE-203 / CWE-209).</p>
 *
 * @param timestamp              UTC creation time
 * @param username               username supplied by the attempt
 *                               (may be a sentinel for unknown-user
 *                               paths so log search still works)
 * @param clientAddress          remote client address, or {@code null}
 * @param internalAuditEventType the differentiated failure classification
 */
public record CredentialVerificationFailed(
    Instant timestamp,
    String username,
    String clientAddress,
    InternalAuditEventType internalAuditEventType
) implements AuditEvent {

  public CredentialVerificationFailed {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(internalAuditEventType, "internalAuditEventType");
  }
}
