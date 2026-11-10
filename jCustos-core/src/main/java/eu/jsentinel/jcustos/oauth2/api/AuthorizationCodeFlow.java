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
package eu.jsentinel.jcustos.oauth2.api;

import com.svenruppert.functional.result.Result;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The OAuth2 Authorization-Code flow (RFC 6749 §4.1 + PKCE RFC 7636, V00.77):
 * {@link #startRequest} produces the browser-redirect URI (and stores the PKCE
 * verifier + state in the {@link StateStore}); {@link #handleCallback} validates
 * the returned {@code state}, consumes it single-use, and exchanges the code for
 * tokens. JOSE-free; the HTTP implementation lives in {@code jCustos-oauth2}.
 *
 * @since 00.77.00
 */
public interface AuthorizationCodeFlow {

  /** Builds the authorization request (redirect URI + the state key bound in the store). */
  AuthorizationRequest startRequest(StartRequestParams params);

  /**
   * Validates + consumes the callback state and exchanges the code for tokens.
   *
   * <p>JS-SEC-059: returns a {@link CallbackResult} rather than a bare {@link TokenResponse} so the
   * stored OIDC {@code nonce} and {@code resumeTarget} survive the single-use state consumption and
   * the caller can bind the {@code id_token} to the nonce.
   *
   * <p>JS-SEC-150 (CWE-346, RFC 9207): an implementation that is configured with an expected
   * issuer rejects a response whose {@code iss} differs — and, when the issuer announces the
   * parameter, a response without one — <em>before</em> it consumes the {@code state} and before
   * it contacts the token endpoint. This is the defence against authorisation-server mix-up.
   */
  Result<CallbackResult, OAuth2Error> handleCallback(CallbackParams params);

  /** Inputs for {@link #startRequest}. */
  record StartRequestParams(
      Set<String> additionalScopes,
      Map<String, String> additionalParams,
      Optional<String> nonce,
      Optional<URI> resumeTarget) {
    public StartRequestParams {
      additionalScopes = Set.copyOf(Objects.requireNonNull(additionalScopes, "additionalScopes"));
      additionalParams = Map.copyOf(Objects.requireNonNull(additionalParams, "additionalParams"));
      Objects.requireNonNull(nonce, "nonce");
      Objects.requireNonNull(resumeTarget, "resumeTarget");
    }
    /** An empty request (configured scopes only). */
    public static StartRequestParams empty() {
      return new StartRequestParams(Set.of(), Map.of(), Optional.empty(), Optional.empty());
    }
  }

  /** The result of {@link #startRequest}: where the browser must go. */
  record AuthorizationRequest(URI redirectTo, String stateKey) {
    public AuthorizationRequest {
      Objects.requireNonNull(redirectTo, "redirectTo");
      Objects.requireNonNull(stateKey, "stateKey");
    }
  }

  /**
   * The query parameters delivered to the redirect URI.
   *
   * <p><strong>JS-SEC-150 (CWE-346):</strong> since 00.84.00 the record carries the {@code iss}
   * parameter of the authorisation response (RFC 9207). An adapter passes the raw query value
   * through; {@link #handleCallback} compares it with the issuer the flow is configured for
   * ({@link OAuth2ClientConfig#expectedIssuer()}) before the {@code state} is consumed and before
   * any code is sent to a token endpoint. The four-argument constructor is kept for callers that
   * have no {@code iss} to pass — a flow whose configuration requires the parameter then rejects
   * the callback.
   *
   * @param code             the authorisation code, if the response carried one
   * @param state            the {@code state} value
   * @param error            the {@code error} code, if the response is an error response
   * @param errorDescription the {@code error_description}, if any
   * @param iss              the {@code iss} parameter of the response (RFC 9207), if present
   */
  record CallbackParams(
      Optional<String> code,
      String state,
      Optional<String> error,
      Optional<String> errorDescription,
      Optional<String> iss) {
    public CallbackParams {
      Objects.requireNonNull(code, "code");
      Objects.requireNonNull(state, "state");
      Objects.requireNonNull(error, "error");
      Objects.requireNonNull(errorDescription, "errorDescription");
      Objects.requireNonNull(iss, "iss");
    }

    /**
     * The pre-00.84.00 shape: a callback without an {@code iss} parameter.
     *
     * @param code             the authorisation code, if the response carried one
     * @param state            the {@code state} value
     * @param error            the {@code error} code, if the response is an error response
     * @param errorDescription the {@code error_description}, if any
     */
    public CallbackParams(
        Optional<String> code,
        String state,
        Optional<String> error,
        Optional<String> errorDescription) {
      this(code, state, error, errorDescription, Optional.empty());
    }
  }
}
