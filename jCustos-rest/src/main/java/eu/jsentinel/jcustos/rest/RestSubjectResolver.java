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

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionMetadata;

import java.util.Optional;

/**
 * Resolves the current security subject from a REST request.
 */
@FunctionalInterface
public interface RestSubjectResolver {

  /**
   * Resolves the current subject.
   *
   * @param request request
   * @return subject, or empty if no subject is authenticated
   */
  Optional<JCustosSubject> resolveSubject(RestRequest request);

  /**
   * Resolves session metadata for the current request.
   * <p>
   * The default returns {@link Optional#empty()} so existing
   * implementations keep working. Implementations that want the
   * REST filters to enforce idle / absolute lifetime via
   * {@code SessionPolicy.evaluate(SessionMetadata)} should override
   * this and return a populated record built from their token
   * store's metadata (creation timestamp, last-activity timestamp).
   *
   * @param request request
   * @return metadata for the current request, or empty when the
   *         resolver doesn't track session lifetime
   */
  default Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
    return Optional.empty();
  }

  /**
   * Resolves the session's security-version snapshot for
   * {@link RestJCustosVersionFilter}.
   * <p>
   * The default returns {@link Optional#empty()} so existing
   * implementations keep working — the filter becomes a no-op for
   * them. Override this when your token / session store records
   * the {@link eu.jsentinel.jcustos.session.JCustosVersion}
   * captured at login time and you want drifted sessions refused
   * with {@code 401 + WWW-Authenticate: SessionStale}.
   *
   * @param request request
   * @return security-version context, or empty when the resolver
   *         doesn't track per-session versions
   */
  default Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
    return Optional.empty();
  }

  /**
   * Resolves the key under which the session of this request is recorded in the
   * {@link eu.jsentinel.jcustos.session.SessionStore} (JS-SEC-131, CWE-613).
   * <p>
   * The default returns {@link Optional#empty()} so existing implementations keep
   * working - the revocation check of {@link RestSessionRevocation} then passes every
   * request. Override this when the application saves a
   * {@link eu.jsentinel.jcustos.session.SessionRecord} per login and a revoked record is
   * to end the session: return the {@link SessionId} the record was saved under.
   * <p>
   * JS-SEC-117 (CWE-522): the id is a key, and it ends up in a store that administrators
   * list. Record a session under a non-secret identifier - a session row id, a token id
   * ({@code jti}), or {@code SessionRef.of(token)} - <strong>never under the bearer token
   * itself</strong>.
   * <p>
   * The method is only called while a store is registered with
   * {@link RestSessionRevocation#useSessionStore}.
   *
   * @param request request
   * @return the session id of the request, or empty when the request has no recorded
   *         session
   * @since 00.84.00
   */
  default Optional<SessionId> resolveSessionId(RestRequest request) {
    return Optional.empty();
  }
}
