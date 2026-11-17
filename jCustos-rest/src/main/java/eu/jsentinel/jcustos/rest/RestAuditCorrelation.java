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

import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.CorrelationIdResolver;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Correlation scope of a REST request (R5, JS-SEC-066, CWE-778): audit events
 * recorded while the request is handled carry its correlation id, in the audit
 * store and as {@code corr=} in the audit line.
 * <p>
 * {@link RestAuthenticationFilter} and {@link RestAuthorizationFilter} run
 * through {@link #run(RestRequest, Runnable)}, so a request that passes them
 * is covered from the filter to the end of the handler;
 * {@link RestJCustosVersionFilter} and {@link RestOriginGuard} decide inside
 * {@link #call(RestRequest, java.util.function.Supplier)}. An application that
 * audits before or outside these filters — its own login handler on a route
 * without a jCustos filter, say — wraps the request handling itself, ideally
 * as the outermost step, so that every filter of the request uses one id:
 * <pre>{@code
 * RestAuditCorrelation.run(request, () -> router.dispatch(request, response));
 * }</pre>
 * Scopes do not stack per filter: when a scope is already open on the thread,
 * {@code run} uses it, so every audit event of one request carries the same id.
 * The id is decided by the registered {@link CorrelationIdResolver}, from
 * {@link RestClientAddress#view(RestRequest)}: a proxy's {@code X-Request-ID}
 * only from a trusted proxy, otherwise a server-side UUID.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestAuditCorrelation {

  private RestAuditCorrelation() {
  }

  /**
   * Runs {@code action} inside the correlation scope of {@code request}: opens
   * one when none is open on this thread and closes it in a {@code finally}
   * block, whatever the action throws; inside an open scope the action runs
   * unchanged. A {@code null} request runs the action without a scope.
   *
   * @param request the request whose correlation id applies, may be {@code null}
   * @param action  what to run, typically the filter and the handler
   */
  public static void run(RestRequest request, Runnable action) {
    Objects.requireNonNull(action, "action");
    if (request == null || AuditCorrelation.current().isPresent()) {
      action.run();
      return;
    }
    try (AuditCorrelation.Scope ignored =
             AuditCorrelation.openFor(RestClientAddress.view(request))) {
      action.run();
    }
  }

  /**
   * {@link #run(RestRequest, Runnable)} for an action with a result: a filter decision such as
   * {@link RestJCustosVersionFilter#allow(RestRequest, RestResponse)}, or a router that returns
   * whether it still has a response to write. The scope rules are the same: one is opened when
   * none is open on this thread and closed in a {@code finally} block, whatever the action
   * throws; inside an open scope the action runs unchanged; a {@code null} request runs the
   * action without a scope.
   *
   * @param request the request whose correlation id applies, may be {@code null}
   * @param action  what to run; non-null
   * @param <T>     the result type
   * @return what {@code action} returned
   * @since 00.84.00
   */
  public static <T> T call(RestRequest request, Supplier<T> action) {
    Objects.requireNonNull(action, "action");
    if (request == null || AuditCorrelation.current().isPresent()) {
      return action.get();
    }
    try (AuditCorrelation.Scope ignored =
             AuditCorrelation.openFor(RestClientAddress.view(request))) {
      return action.get();
    }
  }
}
