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
package eu.jsentinel.jcustos.audit;

import java.time.Instant;
import java.util.Objects;

/**
 * A session was forcibly invalidated by application or framework code
 * (rotation after login, role change, password reset, admin action).
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param subjectId subject identifier, never {@code null}
 * @param sessionId session identifier, or {@code null} if not tracked.
 *                  JS-SEC-117 (CWE-532): producers record the
 *                  {@link SessionRef} of the identifier, never the identifier
 *                  itself
 * @param reason    short reason key (e.g. {@code "RotationAfterLogin"},
 *                  {@code "RoleChange"}), never {@code null}
 */
public record SessionInvalidated(
    Instant timestamp,
    String subjectId,
    String sessionId,
    String reason
) implements AuditEvent {

  public SessionInvalidated {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(reason, "reason");
  }
}
