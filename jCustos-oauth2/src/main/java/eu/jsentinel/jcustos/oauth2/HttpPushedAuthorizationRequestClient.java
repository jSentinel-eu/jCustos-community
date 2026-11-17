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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.PushedAuthorizationRequestClient;
import eu.jsentinel.jcustos.oauth2.api.PushedAuthorizationResponse;
import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;
import eu.jsentinel.jcustos.oauth2.internal.OAuth2Json;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * HTTP {@link PushedAuthorizationRequestClient} (V00.79, RFC 9126). POSTs the
 * authorization-request parameters + client authentication to the (https-enforced)
 * {@code pushed_authorization_request_endpoint}, and parses the {@code 201} response
 * carrying {@code request_uri} + {@code expires_in}. A non-2xx body with an
 * {@code error} member maps to {@link OAuth2Error.ProtocolError}.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public final class HttpPushedAuthorizationRequestClient implements PushedAuthorizationRequestClient {

  private final HttpClient http;
  private final URI parEndpoint;
  private final ClientAuthentication clientAuth;

  public HttpPushedAuthorizationRequestClient(URI parEndpoint, ClientAuthentication clientAuth, HttpClient http) {
    this.parEndpoint = EndpointSecurity.requireHttps(
        Objects.requireNonNull(parEndpoint, "parEndpoint"), "oauth2/par-endpoint-not-https");
    this.clientAuth = Objects.requireNonNull(clientAuth, "clientAuth");
    this.http = Objects.requireNonNull(http, "http");
  }

  @Override
  public Result<PushedAuthorizationResponse, OAuth2Error> push(Map<String, String> authorizationRequestParams) {
    Objects.requireNonNull(authorizationRequestParams, "authorizationRequestParams");
    return OAuth2FormPost.post(http, parEndpoint, authorizationRequestParams, clientAuth).flatMap(outcome -> {
      // JS-SEC-098: read the body once; a body that is no well-formed JSON object lacks every field.
      Map<String, Object> json = OAuth2Json.object(outcome.body()).orElse(Map.of());
      if (outcome.status() == HttpStatus.OK.code()
          || outcome.status() == HttpStatus.CREATED.code()) {
        Optional<String> requestUri = OAuth2Json.string(json, "request_uri");
        if (requestUri.isEmpty()) {
          return Result.failure(new OAuth2Error.MalformedResponse("PAR response without request_uri"));
        }
        long expiresIn = OAuth2Json.longValue(json, "expires_in").orElse(60L);
        return Result.success(new PushedAuthorizationResponse(requestUri.get(), Duration.ofSeconds(expiresIn)));
      }
      return Result.failure(OAuth2Json.string(json, "error")
          .map(e -> (OAuth2Error) new OAuth2Error.ProtocolError(e))
          .orElse(new OAuth2Error.EndpointError(outcome.status())));
    });
  }

  /**
   * Builds the browser-facing authorization-endpoint redirect for a {@code request_uri}
   * (RFC 9126 §4): only {@code client_id} + {@code request_uri} travel in the URL.
   */
  public static URI authorizationRedirect(URI authorizationEndpoint, String clientId, String requestUri) {
    Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint");
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(requestUri, "requestUri");
    String query = "client_id=" + enc(clientId) + "&request_uri=" + enc(requestUri);
    String sep = authorizationEndpoint.getRawQuery() == null ? "?" : "&";
    return URI.create(authorizationEndpoint + sep + query);
  }

  private static String enc(String v) {
    return URLEncoder.encode(v, StandardCharsets.UTF_8);
  }
}
