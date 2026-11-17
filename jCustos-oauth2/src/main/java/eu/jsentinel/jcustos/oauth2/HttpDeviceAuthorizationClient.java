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
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.DeviceAuthorizationClient;
import eu.jsentinel.jcustos.oauth2.api.DeviceAuthorizationResponse;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;
import eu.jsentinel.jcustos.oauth2.internal.OAuth2Json;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * RFC 8628 §3.1/§3.2 device-authorization endpoint over JDK {@link HttpClient}
 * (V00.77): exchanges scopes for a {@code device_code} + {@code user_code}. The
 * absolute {@code expiresAt} is derived from {@code expires_in} against the
 * injected clock; a missing {@code interval} defaults per RFC 8628.
 */
public final class HttpDeviceAuthorizationClient implements DeviceAuthorizationClient {

  private static final String CODE = "oauth2/device-authorization-endpoint";

  private final HttpClient http;
  private final URI endpoint;
  private final ClientAuthentication clientAuthentication;
  private final Supplier<Instant> clock;

  public HttpDeviceAuthorizationClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication) {
    this(http, endpoint, clientAuthentication, Instant::now);
  }

  public HttpDeviceAuthorizationClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication, Supplier<Instant> clock) {
    this.http = Objects.requireNonNull(http, "http");
    this.endpoint = EndpointSecurity.requireHttps(Objects.requireNonNull(endpoint, "endpoint"), CODE);
    this.clientAuthentication = Objects.requireNonNull(clientAuthentication, "clientAuthentication");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Result<DeviceAuthorizationResponse, OAuth2Error> requestDeviceCode(Set<String> scopes) {
    Map<String, String> form = new LinkedHashMap<>();
    if (scopes != null && !scopes.isEmpty()) {
      form.put("scope", String.join(" ", scopes));
    }
    return OAuth2FormPost.post(http, endpoint, form, clientAuthentication).flatMap(outcome -> {
      if (outcome.status() / 100 != 2) {
        return OAuth2Json.string(outcome.body(), "error")
            .<Result<DeviceAuthorizationResponse, OAuth2Error>>map(
                e -> Result.failure(new OAuth2Error.ProtocolError(e)))
            .orElseGet(() -> Result.failure(new OAuth2Error.EndpointError(outcome.status())));
      }
      return parse(outcome.body());
    });
  }

  private Result<DeviceAuthorizationResponse, OAuth2Error> parse(String body) {
    // JS-SEC-098: read the body once; a body that is no well-formed JSON object lacks every field.
    Map<String, Object> json = OAuth2Json.object(body).orElse(Map.of());
    String deviceCode = OAuth2Json.string(json, "device_code").orElse(null);
    String userCode = OAuth2Json.string(json, "user_code").orElse(null);
    String verificationUri = OAuth2Json.string(json, "verification_uri").orElse(null);
    if (deviceCode == null || userCode == null || verificationUri == null) {
      return Result.failure(new OAuth2Error.MalformedResponse(
          "device-authorization response missing device_code/user_code/verification_uri"));
    }
    long interval = OAuth2Json.longValue(json, "interval")
        .orElse(DeviceAuthorizationResponse.DEFAULT_INTERVAL_SECONDS);
    Instant expiresAt = clock.get().plusSeconds(
        OAuth2Json.longValue(json, "expires_in").orElse(600L));
    return Result.success(new DeviceAuthorizationResponse(
        deviceCode, userCode, URI.create(verificationUri),
        OAuth2Json.string(json, "verification_uri_complete").map(URI::create),
        expiresAt, interval));
  }
}
