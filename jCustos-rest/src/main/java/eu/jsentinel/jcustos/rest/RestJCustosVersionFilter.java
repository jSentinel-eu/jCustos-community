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

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer.EnforcementOutcome;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * REST adapter for {@link JCustosVersionEnforcer}.
 * <p>
 * Wire this filter <strong>before</strong>
 * {@link RestAuthorizationFilter} in the application's request
 * pipeline. {@link #allow(RestRequest, RestResponse, String)} returns
 * {@code true} when the request passes the drift check — the
 * caller proceeds with authorization. It returns {@code false} when
 * the session has drifted; in that case the filter has already
 * written the 401 response with a {@code WWW-Authenticate:
 * SessionStale} header (RFC 7235) and the
 * {@code SessionStale} audit event has been published. Callers
 * must <em>not</em> invoke the handler in that case.
 *
 * <p>JS-SEC-086: status and body of that 401 are rendered by the mapper a
 * bootstrap published to {@link RestDecisionContext} (falling back to
 * {@link HttpStatusDecisionMapper}), so a configured error-body strategy
 * applies here as well. The mapper only renders: a drifted session is
 * refused whatever the mapper returns.
 *
 * <p>If the {@link RestSubjectResolver} does not surface a
 * {@link RestJCustosVersionContext} (the default), the filter
 * returns {@code true} unconditionally — applications that don't
 * yet track per-session versions opt in by overriding
 * {@link RestSubjectResolver#resolveJCustosVersionContext(RestRequest) resolveJCustosVersionContext}.
 */
@ExperimentalJCustosApi
public final class RestJCustosVersionFilter {

  /** Header value advertised when the session has drifted (RFC 7235 style). */
  public static final String SESSION_STALE_CHALLENGE = "SessionStale";

  private final RestSubjectResolver resolver;
  private final JCustosVersionEnforcer enforcer;

  /**
   * @param resolver subject / version-context resolver; non-null
   * @param enforcer adapter-neutral enforcer; non-null
   */
  public RestJCustosVersionFilter(RestSubjectResolver resolver,
                                   JCustosVersionEnforcer enforcer) {
    this.resolver = requireNonNull(resolver, "resolver must not be null");
    this.enforcer = requireNonNull(enforcer, "enforcer must not be null");
  }

  /**
   * Runs the drift check.
   *
   * @param request  current request; non-null
   * @param response response to populate on drift; non-null
   * @param route    route / path used in the audit event; may be
   *                 {@code null} — the filter passes through to
   *                 {@link JCustosVersionEnforcer#enforce enforce}
   * @return {@code true} when the request passes (caller proceeds);
   *         {@code false} when the session has drifted (caller
   *         must skip the handler — the response is already
   *         written)
   */
  public boolean allow(RestRequest request, RestResponse response, String route) {
    requireNonNull(request, "request must not be null");
    requireNonNull(response, "response must not be null");
    Optional<RestJCustosVersionContext> ctx =
        resolver.resolveJCustosVersionContext(request);
    if (ctx.isEmpty()) {
      return true;
    }
    RestJCustosVersionContext context = ctx.get();
    EnforcementOutcome outcome = enforcer.enforce(
        context.subjectId(),
        context.tenant(),
        context.snapshot(),
        context.sessionId(),
        route);
    if (outcome instanceof EnforcementOutcome.SessionStale) {
      // JS-SEC-086: status and body come from the published mapper (body strategy included);
      // the more specific challenge replaces the mapper's generic Bearer challenge.
      RestDecisionContext.mapperOrDefault()
          .apply(AuthorizationDecision.unauthenticated("session-stale"), response);
      response.header(RestHeaders.WWW_AUTHENTICATE, SESSION_STALE_CHALLENGE);
      return false;
    }
    return true;
  }

  /**
   * Convenience overload that derives {@code route} from
   * {@link RestRequest#path() request.path()}.
   *
   * @param request  current request; non-null
   * @param response response to populate on drift; non-null
   * @return same semantics as {@link #allow(RestRequest, RestResponse, String)}
   */
  public boolean allow(RestRequest request, RestResponse response) {
    return allow(request, response, request == null ? null : request.path());
  }
}
