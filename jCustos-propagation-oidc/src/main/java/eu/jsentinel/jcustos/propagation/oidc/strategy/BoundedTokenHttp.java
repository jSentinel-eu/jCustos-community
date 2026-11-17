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
package eu.jsentinel.jcustos.propagation.oidc.strategy;

import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;
import eu.jsentinel.jcustos.util.json.BoundedJson;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;
import java.util.Optional;

/**
 * The token-endpoint exchange of the two propagation strategies.
 *
 * <p>JS-SEC-036 (CWE-770) bounded the response body here, in a copy of what the OAuth2 clients
 * did. Since 00.84.00 (JS-SEC-098, CWE-1041) the exchange is {@link OAuth2FormPost} of
 * {@code jCustos-core} — the client authentication, the time bound and the 1 MiB response cap of
 * every other OAuth2 client of jCustos — and the body is read with {@link BoundedJson}. What is
 * left here is the strategies' contract: every failure is a {@link JCustosPropagationException},
 * and the body of a refused request never reaches its message.
 */
final class BoundedTokenHttp {

  /** Lifetime assumed for a minted token whose response names none. */
  static final long DEFAULT_EXPIRES_IN_SECONDS = 60L;

  private BoundedTokenHttp() {
  }

  /**
   * The client authentication the strategies' constructor arguments describe:
   * {@code client_secret_post} with id and secret, a public client with an id only, none
   * without an id.
   *
   * @param clientId     the client id, may be {@code null}
   * @param clientSecret the client secret, may be {@code null}
   * @return the authentication, empty without a client id
   */
  static Optional<ClientAuthentication> clientAuthentication(String clientId, String clientSecret) {
    if (clientId == null) {
      return Optional.empty();
    }
    return Optional.of(clientSecret == null
        ? new ClientAuthentication.NoneAuthentication(clientId)
        : new ClientAuthentication.ClientSecretPost(clientId, SecretValue.ofString(clientSecret)));
  }

  /**
   * POSTs {@code form} to the token endpoint.
   *
   * @return the completed exchange, whatever its status
   * @throws JCustosPropagationException with status {@code 0} when the endpoint could not be
   *                                     reached or the response exceeded the size cap
   */
  static OAuth2FormPost.Outcome post(HttpClient http, URI endpoint, Map<String, String> form,
      Optional<ClientAuthentication> auth) {
    Result<OAuth2FormPost.Outcome, OAuth2Error> result = auth
        .map(a -> OAuth2FormPost.post(http, endpoint, form, a))
        .orElseGet(() -> OAuth2FormPost.postWithoutClientAuthentication(http, endpoint, form));
    if (result.isFailure()) {
      OAuth2Error error = result.fold(ok -> null, e -> e);
      throw new JCustosPropagationException(0, "Token endpoint call failed: " + error.message());
    }
    return result.getOrThrow();
  }

  /**
   * Whether {@code outcome} carries a 2xx status.
   *
   * @param outcome the exchange
   * @return {@code true} for a success status
   */
  static boolean isSuccess(OAuth2FormPost.Outcome outcome) {
    return outcome.status() >= HttpStatus.OK.code()
        && outcome.status() < HttpStatus.MULTIPLE_CHOICES.code();
  }

  /**
   * The minted token of a successful response.
   *
   * @param outcome a 2xx exchange
   * @return the token and its lifetime in seconds
   * @throws JCustosPropagationException when the body is no JSON object with a top-level string
   *                                     {@code access_token}
   */
  static MintedToken mintedToken(OAuth2FormPost.Outcome outcome) {
    Map<String, Object> json = BoundedJson.parseObject(outcome.body()).getOrElse(Map.of());
    String accessToken = BoundedJson.string(json, "access_token")
        .orElseThrow(() -> new JCustosPropagationException(outcome.status(),
            "Token endpoint response missing access_token"));
    long expiresIn = BoundedJson.integer(json, "expires_in").orElse(DEFAULT_EXPIRES_IN_SECONDS);
    return new MintedToken(accessToken, expiresIn);
  }

  /**
   * A token the endpoint minted.
   *
   * @param accessToken      the token
   * @param expiresInSeconds its lifetime
   */
  record MintedToken(String accessToken, long expiresInSeconds) {

    /**
     * Masks the token (JS-SEC-127, CWE-532).
     *
     * @return a description without the token
     */
    @Override
    public String toString() {
      return "MintedToken[accessToken=***, expiresInSeconds=" + expiresInSeconds + "]";
    }
  }
}
