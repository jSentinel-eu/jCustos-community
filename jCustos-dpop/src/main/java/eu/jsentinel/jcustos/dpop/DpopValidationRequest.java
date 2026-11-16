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
package eu.jsentinel.jcustos.dpop;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/**
 * The inbound request context a {@link DpopProofValidator} validates a proof against
 * (V00.79): the raw {@code DPoP} header value, the actual HTTP method + request URI
 * the proof must bind to ({@code htm} / {@code htu}, RFC 9449 §4.3), and — when the
 * proof accompanies a DPoP-bound access token at a resource server — that access
 * token so the {@code ath} claim can be checked (§4.3 step 12) together with the key
 * thumbprint the token is bound to ({@code cnf.jkt}, §6.1).
 *
 * <p><strong>JS-SEC-148 (CWE-345):</strong> since 00.84.00 the request carries the expected key
 * thumbprint. {@code ath} only ties the proof to the token; whether the proof was signed with the
 * key the token is bound to is a separate check, and up to 00.83.x it was left to a voluntary
 * follow-up call ({@link ValidatedDpopProof#confirms}). A thief of a DPoP-bound token could
 * therefore sign a proof with a key of his own and receive a successful validation. A request that
 * carries an access token but no expected thumbprint is now rejected — the validator fails
 * closed.
 *
 * @param proofCompact the raw {@code DPoP} header value
 * @param httpMethod   the HTTP method of the request
 * @param httpUri      the request URI
 * @param accessToken  the presented access token, at a resource server
 * @param expectedJkt  the {@code cnf.jkt} of the presented access token — the thumbprint of the
 *                     key the proof must be signed with (since 00.84.00)
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public record DpopValidationRequest(
    String proofCompact,
    String httpMethod,
    URI httpUri,
    Optional<String> accessToken,
    Optional<JwkThumbprint> expectedJkt) {

  public DpopValidationRequest {
    Objects.requireNonNull(proofCompact, "proofCompact");
    Objects.requireNonNull(httpMethod, "httpMethod");
    Objects.requireNonNull(httpUri, "httpUri");
    Objects.requireNonNull(accessToken, "accessToken");
    Objects.requireNonNull(expectedJkt, "expectedJkt");
  }

  /**
   * The pre-00.84.00 shape, without an expected key thumbprint. A request built this way with an
   * access token is rejected by the validator ({@link DpopValidationError.KeyBindingMismatch}),
   * because the key binding cannot be checked (JS-SEC-148).
   */
  public DpopValidationRequest(
      String proofCompact, String httpMethod, URI httpUri, Optional<String> accessToken) {
    this(proofCompact, httpMethod, httpUri, accessToken, Optional.empty());
  }

  /**
   * A request that validates the proof on its own — no access token, hence no {@code ath} and no
   * key-binding check. This is the profile of the <em>token endpoint</em> (RFC 9449 §5), where the
   * proof introduces the key a token is about to be bound to. It must not be used at a protected
   * resource; use {@link #boundTo(String, String, URI, String, JwkThumbprint)} there.
   */
  public static DpopValidationRequest of(String proofCompact, String httpMethod, URI httpUri) {
    return new DpopValidationRequest(proofCompact, httpMethod, httpUri, Optional.empty(), Optional.empty());
  }

  /**
   * The complete binding for a protected resource (RFC 9449 §7): the proof's {@code ath} must
   * match {@code accessToken}, <em>and</em> the proof must be signed with the key whose thumbprint
   * is {@code expectedJkt} — the {@code cnf.jkt} claim of that access token (or of its
   * introspection response).
   *
   * @param proofCompact the raw {@code DPoP} header value
   * @param httpMethod   the HTTP method of the request
   * @param httpUri      the request URI
   * @param accessToken  the presented access token
   * @param expectedJkt  the {@code cnf.jkt} of the access token
   * @return the request
   * @since 00.84.00
   */
  public static DpopValidationRequest boundTo(
      String proofCompact, String httpMethod, URI httpUri, String accessToken, JwkThumbprint expectedJkt) {
    Objects.requireNonNull(accessToken, "accessToken");
    Objects.requireNonNull(expectedJkt, "expectedJkt");
    return new DpopValidationRequest(
        proofCompact, httpMethod, httpUri, Optional.of(accessToken), Optional.of(expectedJkt));
  }

  /**
   * A request that checks {@code ath} only.
   *
   * @deprecated since 00.84.00 (JS-SEC-148, CWE-345): without the expected key thumbprint the
   *     binding is incomplete — a proof signed with <em>any</em> key would pass. The validator
   *     therefore <strong>rejects</strong> every request built by this method with
   *     {@link DpopValidationError.KeyBindingMismatch}; it fails closed instead of validating half
   *     a binding. Use {@link #boundTo(String, String, URI, String, JwkThumbprint)} and pass the
   *     {@code cnf.jkt} of the access token.
   */
  @Deprecated(since = "00.84.00", forRemoval = true)
  public static DpopValidationRequest boundTo(
      String proofCompact, String httpMethod, URI httpUri, String accessToken) {
    return new DpopValidationRequest(
        proofCompact, httpMethod, httpUri, Optional.of(accessToken), Optional.empty());
  }

  /**
   * Masks the proof and the access token (JS-SEC-127, CWE-532): the generated
   * {@code toString()} printed the bearer token and a proof that is valid for this method and
   * URI into any log line or exception message that stringified the request.
   *
   * @return a description without proof and token
   */
  @Override
  public String toString() {
    return "DpopValidationRequest[proofCompact=***, httpMethod=" + httpMethod
        + ", httpUri=" + httpUri
        + ", accessToken=" + (accessToken.isPresent() ? "***" : "<none>")
        + ", expectedJkt=" + expectedJkt.map(JwkThumbprint::value).orElse("<none>") + "]";
  }
}
