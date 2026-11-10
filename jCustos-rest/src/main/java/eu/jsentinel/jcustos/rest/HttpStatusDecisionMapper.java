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

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;

/**
 * Maps semantic authorization decisions to generic HTTP response behavior.
 * <p>
 * This is the REST row of the canonical cross-adapter mapping — see
 * {@link AuthorizationDecision} for the full table (R024). The switch is
 * exhaustive over the sealed type; {@code StepUpRequired} returns a
 * {@code 401} with an RFC&nbsp;7235 {@code WWW-Authenticate: StepUp} challenge
 * rather than a Vaadin reroute or a thrown exception, because HTTP has a
 * first-class challenge mechanism the other adapters lack.
 */
public final class HttpStatusDecisionMapper implements RestDecisionMapping {

  /**
   * Auth scheme used in the {@code WWW-Authenticate} header when an
   * adapter challenges for a step-up. The full header value follows
   * RFC 7235 syntax: {@code StepUp method="<method>"}. The
   * {@code method} parameter carries the mechanism token (e.g.
   * {@code MFA}, {@code REAUTH}) lifted from
   * {@link AuthorizationDecision.StepUpRequired#method()}.
   */
  public static final String STEP_UP_SCHEME = "StepUp";

  /** JS-SEC-086: challenge sent with every {@code Unauthenticated} 401. */
  public static final String BEARER_CHALLENGE = "Bearer";

  private final RestErrorBodies errorBodies;

  /** Uses the generic default bodies. */
  public HttpStatusDecisionMapper() {
    this(RestErrorBodies.generic());
  }

  /**
   * Uses application-supplied bodies while keeping the status codes and
   * the RFC 7235 challenge header this class already gets right.
   *
   * @param errorBodies body strategy for denied decisions (non-null)
   * @since 00.83.00
   */
  public HttpStatusDecisionMapper(RestErrorBodies errorBodies) {
    this.errorBodies = java.util.Objects.requireNonNull(errorBodies, "errorBodies");
  }

  /**
   * Applies a decision to the response.
   *
   * @param decision decision
   * @param response response
   * @return true if the protected handler may continue
   */
  @Override
  public boolean apply(AuthorizationDecision decision, RestResponse response) {
    return switch (decision) {
      case AuthorizationDecision.Granted() -> true;
      case AuthorizationDecision.Unauthenticated(String ignored) -> {
        // JS-SEC-086 (RFC 7235 §3.1): a 401 carries a challenge. Bearer is the REST adapter's
        // credential scheme; filters that know a more specific challenge (SessionStale) set it
        // after the mapper has run.
        response.status(HttpStatus.UNAUTHORIZED.code());
        response.header(RestHeaders.WWW_AUTHENTICATE, BEARER_CHALLENGE);
        response.body(errorBodies.bodyFor(decision));
        yield false;
      }
      case AuthorizationDecision.Forbidden(String ignored) -> {
        response.status(HttpStatus.FORBIDDEN.code());
        response.body(errorBodies.bodyFor(decision));
        yield false;
      }
      case AuthorizationDecision.StepUpRequired stepUp -> {
        // RFC 7235 — return 401 with a syntactically-conformant
        // challenge so strict HTTP clients (curl --location, Postman,
        // OWASP tools) accept the response without ad-hoc parsing.
        response.status(HttpStatus.UNAUTHORIZED.code());
        response.header(
            RestHeaders.WWW_AUTHENTICATE,
            STEP_UP_SCHEME + " method=\"" + stepUp.method() + "\"");
        response.body(errorBodies.bodyFor(decision));
        yield false;
      }
    };
  }
}
