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
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.net.URI;
import java.util.List;
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

    /**
     * Builds the parameters from the query of the redirect, as the transport delivers it: every
     * value of every parameter, in wire order. This is the one way the jCustos adapters (REST
     * and Vaadin) read a callback (JS-SEC-098, CWE-1041).
     *
     * <p>RFC 6749 §3.1: response parameters must not be included more than once. A query that
     * repeats {@code code}, {@code state}, {@code error}, {@code error_description},
     * {@code error_uri} or {@code iss} is refused as a whole — keeping the first
     * value would let a second {@code state}, {@code code} or {@code iss} reach a component
     * that reads the last one (parameter pollution). Up to 00.83.00 the REST adapter read a
     * single-valued map and never saw a repetition; the Vaadin adapter refused a repeated
     * {@code iss} only. A query without a non-blank {@code state} is refused as well. A blank
     * {@code code}, {@code error}, {@code error_description} or {@code iss} counts as absent.
     * Other parameters are ignored.
     *
     * @param query the query parameters, each with all its values; may be {@code null}
     * @return the parameters, or {@link OAuth2Error.StateInvalid} when the query repeats a
     *     response parameter or carries no {@code state}; the detail names the parameter, never
     *     a value
     * @since 00.84.00
     */
    @ExperimentalJCustosApi
    public static Result<CallbackParams, OAuth2Error> fromMultiValued(Map<String, List<String>> query) {
      Map<String, List<String>> params = query == null ? Map.of() : query;
      // The parameters of an authorisation response (RFC 6749 §4.1.2 and §4.1.2.1, RFC 9207).
      for (String name : List.of("code", "state", "error", "error_description", "error_uri", "iss")) {
        if (values(params, name).size() > 1) {
          return Result.failure(new OAuth2Error.StateInvalid("callback-parameter-repeated:" + name));
        }
      }
      Optional<String> state = single(params, "state");
      if (state.isEmpty()) {
        return Result.failure(new OAuth2Error.StateInvalid("callback-without-state"));
      }
      return Result.success(new CallbackParams(single(params, "code"), state.get(),
          single(params, "error"), single(params, "error_description"), single(params, "iss")));
    }

    private static List<String> values(Map<String, List<String>> query, String name) {
      List<String> values = query.get(name);
      if (values == null) {
        return List.of();
      }
      return values.stream().filter(Objects::nonNull).toList();
    }

    private static Optional<String> single(Map<String, List<String>> query, String name) {
      List<String> values = values(query, name);
      return values.isEmpty() || values.get(0).isBlank() ? Optional.empty() : Optional.of(values.get(0));
    }

    /**
     * Masks the authorisation code (JS-SEC-127, CWE-532): until it is redeemed it buys
     * tokens, and the generated {@code toString()} printed it into any log line or exception
     * message that stringified the parameters.
     *
     * <p>Since 00.84.00 the {@code state} is masked as well - it is the key of the
     * pending login, and a log reader must not be able to complete it - and the values
     * the sender of the callback chooses freely ({@code error}, {@code error_description},
     * {@code iss}) are scrubbed with {@link LogFieldScrubber}, so they can forge no log
     * line (CWE-117).
     *
     * @return a description without code and state
     */
    @Override
    public String toString() {
      return "CallbackParams[code=" + (code.isPresent() ? "***" : "<none>")
          + ", state=" + (state.isEmpty() ? "<empty>" : "***")
          + ", error=" + error.map(LogFieldScrubber::scrub).orElse("<none>")
          + ", errorDescription="
          + errorDescription.map(LogFieldScrubber::scrubMessage).orElse("<none>")
          + ", iss=" + iss.map(LogFieldScrubber::scrub).orElse("<none>") + "]";
    }
  }
}
