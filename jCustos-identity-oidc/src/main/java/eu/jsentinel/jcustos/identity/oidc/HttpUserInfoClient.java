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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
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

import eu.jsentinel.jcustos.util.BoundedHttpBody;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oidc.api.UserInfoClient;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.util.json.BoundedJson;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Pulls claims from the OIDC UserInfo endpoint (OIDC Core §5.3, V00.78). Sends a
 * Bearer-authenticated GET over JDK {@link HttpClient}, enforces https (V00.77
 * dev-loopback carve-out, see {@link EndpointSecurity}), caps the body at 1 MiB and
 * parses the JSON response with {@link BoundedJson}. The {@code sub} claim is mandatory; the caller MUST
 * verify it matches the ID token's {@code sub} (OIDC §5.3.2). The access token is
 * sent only in the {@code Authorization} header and never logged.
 *
 * <p>This V00.78 client handles the JSON UserInfo response; a signed/encrypted
 * (application/jwt) UserInfo response is a documented V00.78.x extension.
 */
public final class HttpUserInfoClient implements UserInfoClient {

  private static final int MAX_BYTES = 1024 * 1024;
  private static final String CODE = "oauth2/userinfo-endpoint";
  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private final HttpClient http;
  private final URI endpoint;

  public HttpUserInfoClient(HttpClient http, URI endpoint) {
    this.http = Objects.requireNonNull(http, "http");
    this.endpoint = EndpointSecurity.requireHttps(Objects.requireNonNull(endpoint, "endpoint"), CODE);
  }

  @Override
  public Result<UserInfoResponse, OAuth2Error> fetch(String accessToken) {
    Objects.requireNonNull(accessToken, "accessToken");
    HttpResponse<byte[]> response;
    try {
      response = http.send(HttpRequest.newBuilder(endpoint).timeout(TIMEOUT)
          .header("Accept", "application/json")
          .header("Authorization", "Bearer " + accessToken)
          .GET().build(), BoundedHttpBody.ofByteArray(MAX_BYTES + 1));
    } catch (java.net.http.HttpTimeoutException e) {
      return Result.failure(new OAuth2Error.NetworkError("timeout"));
    } catch (IOException e) {
      return Result.failure(new OAuth2Error.NetworkError(e.getClass().getSimpleName()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Result.failure(new OAuth2Error.NetworkError("interrupted"));
    }
    if (response.statusCode() / 100 != 2) {
      return Result.failure(new OAuth2Error.EndpointError(response.statusCode()));
    }

    String body;
    byte[] bytes = response.body();
    if (bytes.length > MAX_BYTES) {
      return Result.failure(new OAuth2Error.MalformedResponse("userinfo body exceeds the size cap"));
    }
    body = new String(bytes, StandardCharsets.UTF_8);

    Result<Map<String, Object>, String> parsed = BoundedJson.parseObject(body);
    if (parsed.isFailure()) {
      return Result.failure(new OAuth2Error.MalformedResponse("invalid userinfo document"));
    }
    Map<String, Object> json = parsed.getOrThrow();
    if (!(json.get("sub") instanceof String sub) || sub.isBlank()) {
      return Result.failure(new OAuth2Error.MalformedResponse("userinfo response without sub"));
    }
    return Result.success(new UserInfoResponse(sub, json));
  }
}
