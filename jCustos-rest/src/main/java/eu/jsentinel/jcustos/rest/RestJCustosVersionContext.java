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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;

import static java.util.Objects.requireNonNull;

/**
 * Per-request session security context surfaced by a
 * {@link RestSubjectResolver} so {@link RestJCustosVersionFilter}
 * can run a drift check before authorization.
 * <p>
 * Implementations of {@code RestSubjectResolver} that want their
 * deployment to participate in Phase 4c drift detection override
 * {@link RestSubjectResolver#resolveJCustosVersionContext(RestRequest)}
 * and return a populated record. Implementations that don't (e.g.
 * stateless API-key flows where every request rehydrates the
 * subject) keep the default {@code Optional.empty()} and the
 * filter is a no-op for them.
 *
 * <p>JS-SEC-117 (CWE-532, CWE-522): {@code sessionId} exists for audit
 * correlation only. Pass a non-secret identifier of the session — a session
 * row id, a token id ({@code jti}), a hash — <strong>never the token
 * itself</strong>. As a safeguard {@link RestJCustosVersionFilter} does not
 * forward the value as it is: the audit event carries
 * {@link RestJCustosVersionFilter#sessionReference(String)}, a marked,
 * truncated SHA-256. The safeguard does not make it right to keep a bearer token in
 * this record longer than the request.
 *
 * @param subjectId authenticated subject; non-null
 * @param tenant    tenant scope; {@code null} becomes
 *                  {@link TenantId#DEFAULT}
 * @param snapshot  security version captured when the session /
 *                  token was issued; non-null
 * @param sessionId non-secret session identifier for audit correlation
 *                  (session row id, token id) — never the token itself;
 *                  may be {@code null}
 */
@ExperimentalJCustosApi
public record RestJCustosVersionContext(
    SubjectId subjectId,
    TenantId tenant,
    JCustosVersion snapshot,
    String sessionId
) {

  /** Validates the components and normalises {@code null} tenant. */
  public RestJCustosVersionContext {
    requireNonNull(subjectId, "subjectId must not be null");
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(snapshot, "snapshot must not be null");
  }

  /**
   * Prints the session reference instead of {@code sessionId} (JS-SEC-117, CWE-532): in
   * REST the value is all too often the bearer token itself, and the generated
   * {@code toString()} printed it into any log line or exception message that
   * stringified the context.
   *
   * @return a description that carries {@link SessionRef#ofNullable(String)} of the session id
   * @since 00.84.00
   */
  @Override
  public String toString() {
    return "RestJCustosVersionContext[subjectId=" + subjectId + ", tenant=" + tenant
        + ", snapshot=" + snapshot + ", sessionRef=" + SessionRef.ofNullable(sessionId) + "]";
  }
}
