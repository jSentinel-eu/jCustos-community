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
 * Emitted when a request was refused because the session's
 * security-version snapshot no longer matches the subject's
 * current version. Carries both values so a SIEM can pivot on
 * the delta (admin revoked a role, password changed, …) without
 * parsing free-form reason strings.
 *
 * <p>Fired by the security-vaadin / security-rest interceptors
 * before the authorization step (Phase 4c of the V00.70 roadmap)
 * and by callers of
 * {@code eu.jsentinel.jcustos.session.JCustosVersionEnforcer}.
 *
 * @param timestamp       UTC creation time, never {@code null}
 * @param subjectId       subject identifier, never blank
 * @param sessionId       session identifier, or {@code null} if
 *                        the adapter does not track session ids.
 *                        JS-SEC-117 (CWE-532): producers pass a non-secret
 *                        reference; the REST filter records a truncated
 *                        SHA-256 of the token-derived identifier, never
 *                        the token
 * @param route           navigation route / REST path that triggered
 *                        the check, or {@code null}
 * @param snapshotVersion value captured when the session was opened
 * @param currentVersion  subject's current security version at check
 *                        time; must differ from {@code snapshotVersion}
 */
public record SessionStale(
    Instant timestamp,
    String subjectId,
    String sessionId,
    String route,
    long snapshotVersion,
    long currentVersion
) implements AuditEvent {

  /** Validates the record components. */
  public SessionStale {
    Objects.requireNonNull(timestamp, "timestamp must not be null");
    if (subjectId == null || subjectId.isBlank()) {
      throw new IllegalArgumentException("subjectId must not be blank");
    }
    if (snapshotVersion < 0L) {
      throw new IllegalArgumentException("snapshotVersion must not be negative");
    }
    if (currentVersion < 0L) {
      throw new IllegalArgumentException("currentVersion must not be negative");
    }
    if (snapshotVersion == currentVersion) {
      throw new IllegalArgumentException(
          "SessionStale requires snapshotVersion != currentVersion");
    }
  }
}
