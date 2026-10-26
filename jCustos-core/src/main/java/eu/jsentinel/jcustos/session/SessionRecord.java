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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Persistent representation of a single authenticated session.
 * <p>
 * Stored by {@link SessionStore} keyed on {@link #sessionId()};
 * queried by
 * {@code (tenant, subjectId)} when an admin or a security service
 * needs to enumerate every session of a given subject (e.g.
 * "revoke all sessions of alice after a password change").
 *
 * <p>The {@code securityVersionAtLogin} component is the
 * {@link JCustosVersion} of the subject at the moment this session
 * was opened. A planned {@code JCustosVersionCheck} interceptor
 * (Phase 4 of the V00.70 roadmap) compares this value to the
 * subject's <em>current</em> security version on every request: a
 * mismatch means the subject's authority has changed since login,
 * and the session must be re-validated.
 *
 * <p>Mutation: records are immutable. Callers update fields by
 * building a new {@code SessionRecord} via the {@code with…}
 * convenience methods and calling {@code SessionStore.save(...)}
 * again.
 *
 * @param sessionId               unique session identifier
 * @param subjectId               authenticated subject; non-null
 * @param tenant                  tenant scope; {@code null} becomes
 *                                {@link TenantId#DEFAULT}
 * @param createdAt               when the session was opened; non-null
 * @param lastActivityAt          last activity on the session; non-null,
 *                                must not predate {@code createdAt}
 * @param securityVersionAtLogin  subject security version at login; non-null
 * @param status                  current lifecycle state; non-null
 */
@ExperimentalJCustosApi
public record SessionRecord(
    SessionId sessionId,
    SubjectId subjectId,
    TenantId tenant,
    Instant createdAt,
    Instant lastActivityAt,
    JCustosVersion securityVersionAtLogin,
    SessionStatus status
) {

  /**
   * Validates the record components and normalises a {@code null}
   * tenant to {@link TenantId#DEFAULT}.
   *
   * @param sessionId              unique session identifier; non-null
   * @param subjectId              authenticated subject; non-null
   * @param tenant                 tenant scope; {@code null} becomes DEFAULT
   * @param createdAt              creation instant; non-null
   * @param lastActivityAt         last activity instant; non-null and
   *                               not before {@code createdAt}
   * @param securityVersionAtLogin subject security version; non-null
   * @param status                 lifecycle state; non-null
   */
  public SessionRecord {
    requireNonNull(sessionId, "sessionId must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(createdAt, "createdAt must not be null");
    requireNonNull(lastActivityAt, "lastActivityAt must not be null");
    if (lastActivityAt.isBefore(createdAt)) {
      throw new IllegalArgumentException(
          "lastActivityAt must not be before createdAt");
    }
    requireNonNull(securityVersionAtLogin,
        "securityVersionAtLogin must not be null");
    requireNonNull(status, "status must not be null");
  }

  /**
   * Returns a copy with {@link #lastActivityAt()} updated to
   * {@code newLastActivity}.
   *
   * @param newLastActivity new last-activity instant; non-null
   * @return new {@code SessionRecord}; receiver unchanged
   */
  public SessionRecord withLastActivityAt(Instant newLastActivity) {
    return new SessionRecord(
        sessionId, subjectId, tenant,
        createdAt, newLastActivity,
        securityVersionAtLogin, status);
  }

  /**
   * Returns a copy with {@link #status()} updated to {@code newStatus}.
   * Use this to transition an {@link SessionStatus#ACTIVE} session to
   * {@link SessionStatus#EXPIRED} or {@link SessionStatus#REVOKED}.
   *
   * @param newStatus new lifecycle state; non-null
   * @return new {@code SessionRecord}; receiver unchanged
   */
  public SessionRecord withStatus(SessionStatus newStatus) {
    return new SessionRecord(
        sessionId, subjectId, tenant,
        createdAt, lastActivityAt,
        securityVersionAtLogin, newStatus);
  }

  /**
   * Returns a copy keyed by {@code newSessionId}. Used to re-key a record
   * created during login once the HTTP session id has rotated
   * (JS-SEC-060, CWE-384), so revocation by id still reaches the live session.
   *
   * @param newSessionId the surviving session id; non-null
   * @return new {@code SessionRecord}; receiver unchanged
   * @since 00.84.00
   */
  public SessionRecord withSessionId(SessionId newSessionId) {
    return new SessionRecord(
        newSessionId, subjectId, tenant,
        createdAt, lastActivityAt,
        securityVersionAtLogin, status);
  }
}
