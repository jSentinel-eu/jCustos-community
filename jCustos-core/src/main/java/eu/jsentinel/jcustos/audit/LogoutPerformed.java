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

import eu.jsentinel.jcustos.logout.LogoutScope;

import java.time.Instant;
import java.util.Objects;

/**
 * A subject's session was terminated by an explicit logout.
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param subjectId subject identifier, never {@code null}
 * @param sessionId session that was terminated, or {@code null} if not
 *                  tracked (e.g. {@link LogoutScope#CurrentSession} without
 *                  a known session id). JS-SEC-117 (CWE-532): producers
 *                  record the {@link SessionRef} of the identifier, never the
 *                  identifier itself
 * @param scope     scope of the logout, never {@code null}
 */
public record LogoutPerformed(
    Instant timestamp,
    String subjectId,
    String sessionId,
    LogoutScope scope
) implements AuditEvent {

  public LogoutPerformed {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(scope, "scope");
  }
}
