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

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.PkceVerifier;
import eu.jsentinel.jcustos.oauth2.api.TokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;
import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;
import eu.jsentinel.jcustos.oauth2.internal.OAuth2Json;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * JDK-HttpClient {@link TokenEndpointClient} (V00.77). POSTs the form-encoded
 * grant to the token endpoint, applies the configured client authentication
 * (Basic header / body fields / public client) and maps the response to a
 * {@link TokenResponse} or a non-secret {@link OAuth2Error}.
 *
 * <p>Discipline: HTTPS is enforced (loopback {@code http} only with
 * {@code -Djcustos.dev=true}, see {@link EndpointSecurity}); the response body is
 * capped at 1 MiB and read with {@link OAuth2Json}; a missing {@code access_token}
 * on a 2xx is a {@code malformed-response}; a 4xx with an {@code error} field is
 * a {@code protocol-error}; any other non-2xx is an {@code endpoint-error}.
 *
 * <p>Since 00.84.00 (JS-SEC-098, CWE-1041) the exchange itself — client
 * authentication, time bound, size cap, transport errors — is
 * {@link OAuth2FormPost}, which the other OAuth2 clients and the propagation
 * strategies share; this class kept a copy of its own up to 00.83.00.
 *
 * <p>Signed client assertions ({@code private_key_jwt} / {@code client_secret_jwt})
 * are wired in V00.77 phase 6.
 *
 * @since 00.77.00
 */
public final class HttpTokenEndpointClient implements TokenEndpointClient {

  private static final String CODE = "oauth2/token-endpoint-not-https";
  private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

  private final URI tokenEndpoint;
  private final ClientAuthentication clientAuth;
  private final HttpClient http;
  private final Supplier<Instant> clock;

  public HttpTokenEndpointClient(URI tokenEndpoint, ClientAuthentication clientAuth, HttpClient http) {
    this(tokenEndpoint, clientAuth, http, Instant::now);
  }

  public HttpTokenEndpointClient(URI tokenEndpoint, ClientAuthentication clientAuth,
      HttpClient http, Supplier<Instant> clock) {
    this.tokenEndpoint = EndpointSecurity.requireHttps(
        Objects.requireNonNull(tokenEndpoint, "tokenEndpoint"), CODE);
    this.clientAuth = Objects.requireNonNull(clientAuth, "clientAuth");
    this.http = Objects.requireNonNull(http, "http");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Result<TokenResponse, OAuth2Error> exchangeCode(String code, URI redirectUri, PkceVerifier pkce) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "authorization_code");
    form.put("code", Objects.requireNonNull(code, "code"));
    form.put("redirect_uri", Objects.requireNonNull(redirectUri, "redirectUri").toString());
    form.put("code_verifier", Objects.requireNonNull(pkce, "pkce").value());
    return post(form);
  }

  @Override
  public Result<TokenResponse, OAuth2Error> refresh(SecretValue refreshToken) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "refresh_token");
    byte[] rt = refreshToken.asUtf8Bytes();
    form.put("refresh_token", new String(rt, StandardCharsets.UTF_8));
    Arrays.fill(rt, (byte) 0);
    return post(form);
  }

  @Override
  public Result<TokenResponse, OAuth2Error> clientCredentials(Set<String> scopes) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    if (scopes != null && !scopes.isEmpty()) {
      form.put("scope", String.join(" ", scopes));
    }
    return post(form);
  }

  @Override
  public Result<TokenResponse, OAuth2Error> deviceToken(String deviceCode) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", DEVICE_CODE_GRANT);
    form.put("device_code", Objects.requireNonNull(deviceCode, "deviceCode"));
    return post(form);
  }

  private Result<TokenResponse, OAuth2Error> post(Map<String, String> form) {
    return OAuth2FormPost.post(http, tokenEndpoint, form, clientAuth, clock).flatMap(outcome -> {
      // JS-SEC-098: read the body once; a body that is no well-formed JSON object lacks every field.
      Map<String, Object> json = OAuth2Json.object(outcome.body()).orElse(Map.of());
      int status = outcome.status();
      if (status / 100 == 2) {
        return parseTokenResponse(json);
      }
      // RFC 6749 §5.2: a 4xx error body carries an "error" field
      Optional<String> oauthError = OAuth2Json.string(json, "error");
      return oauthError.<Result<TokenResponse, OAuth2Error>>map(
              e -> Result.failure(new OAuth2Error.ProtocolError(e)))
          .orElseGet(() -> Result.failure(new OAuth2Error.EndpointError(status)));
    });
  }

  private Result<TokenResponse, OAuth2Error> parseTokenResponse(Map<String, Object> json) {
    Optional<String> accessToken = OAuth2Json.string(json, "access_token");
    if (accessToken.isEmpty()) {
      return Result.failure(new OAuth2Error.MalformedResponse("no access_token"));
    }
    String tokenType = OAuth2Json.string(json, "token_type").orElse("Bearer");
    Optional<Instant> expiresAt = OAuth2Json.longValue(json, "expires_in")
        .map(seconds -> clock.get().plusSeconds(seconds));
    Optional<String> refreshToken = OAuth2Json.string(json, "refresh_token");
    Optional<String> idToken = OAuth2Json.string(json, "id_token");
    Set<String> scopes = OAuth2Json.string(json, "scope")
        .map(OAuth2Json::parseScopes)
        .orElse(Set.of());
    return Result.success(new TokenResponse(
        accessToken.get(), refreshToken, idToken, tokenType, expiresAt, scopes));
  }
}
