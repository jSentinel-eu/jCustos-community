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
package eu.jsentinel.jcustos.oauth2.internal;

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

import eu.jsentinel.jcustos.util.BoundedHttpBody;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * Shared form-{@code POST} plumbing for the OAuth2 introspection / revocation
 * endpoints (V00.77): HTTPS enforcement, client authentication (Basic header /
 * body fields / public client), a 1 MiB body cap and transport-error mapping.
 * The token-endpoint client keeps its own copy; the V00.77.x consolidation (B6)
 * unifies them.
 */
public final class OAuth2FormPost {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);
  private static final int MAX_BYTES = 1024 * 1024;

  /** A completed HTTP exchange. */
  public record Outcome(int status, String body) {

    /**
     * Shows the length of the body, not the body (JS-SEC-127, CWE-532): an introspection
     * response names the token's subject and scopes, a token response carries tokens.
     *
     * @return a description without the body
     */
    @Override
    public String toString() {
      return "Outcome[status=" + status + ", body=<"
          + (body == null ? 0 : body.length()) + " chars>]";
    }
  }

  private OAuth2FormPost() {
    throw new AssertionError("no instances");
  }

  /** Enforces https (loopback http only with {@code -Djcustos.dev=true}). */
  public static URI requireHttps(URI endpoint, String code) {
    String scheme = endpoint.getScheme();
    if ("https".equalsIgnoreCase(scheme)) {
      return endpoint;
    }
    boolean devLoopback = Boolean.getBoolean("jcustos.dev")
        && "http".equalsIgnoreCase(scheme)
        && ("localhost".equalsIgnoreCase(endpoint.getHost()) || "127.0.0.1".equals(endpoint.getHost()));
    if (devLoopback) {
      return endpoint;
    }
    throw new IllegalArgumentException(code + ": endpoint must use https:// (got: " + endpoint + ")");
  }

  /** POSTs {@code form} (plus client auth) to {@code endpoint}, returning the capped response. */
  public static Result<Outcome, OAuth2Error> post(HttpClient http, URI endpoint,
      Map<String, String> form, ClientAuthentication auth) {
    HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
        .timeout(TIMEOUT)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");
    applyClientAuth(auth, endpoint, form, request);

    HttpResponse<byte[]> response;
    try {
      response = http.send(request.POST(HttpRequest.BodyPublishers.ofString(encode(form))).build(),
          BoundedHttpBody.ofByteArray(MAX_BYTES + 1));
    } catch (java.net.http.HttpTimeoutException e) {
      return Result.failure(new OAuth2Error.NetworkError("timeout"));
    } catch (IOException e) {
      return Result.failure(new OAuth2Error.NetworkError(e.getClass().getSimpleName()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Result.failure(new OAuth2Error.NetworkError("interrupted"));
    }

    byte[] bytes = response.body();
    if (bytes.length > MAX_BYTES) {
      return Result.failure(new OAuth2Error.MalformedResponse("body exceeds the size cap"));
    }
    return Result.success(new Outcome(response.statusCode(), new String(bytes, StandardCharsets.UTF_8)));
  }

  private static void applyClientAuth(ClientAuthentication auth, URI endpoint,
      Map<String, String> form, HttpRequest.Builder request) {
    switch (auth) {
      case ClientAuthentication.ClientSecretBasic basic ->
          request.header("Authorization", basicHeader(basic.clientId(), basic.secret()));
      case ClientAuthentication.ClientSecretPost post -> {
        form.put("client_id", post.clientId());
        byte[] secret = post.secret().asUtf8Bytes();
        form.put("client_secret", new String(secret, StandardCharsets.UTF_8));
        Arrays.fill(secret, (byte) 0);
      }
      case ClientAuthentication.NoneAuthentication none -> form.put("client_id", none.clientId());
      case ClientAuthentication.PrivateKeyJwt pk ->
          ClientAssertions.applyPrivateKeyJwt(pk, endpoint, Instant::now, JwtSigners.require(), form);
      case ClientAuthentication.ClientSecretJwt cs ->
          ClientAssertions.applyClientSecretJwt(cs, endpoint, Instant::now, form);
    }
  }

  private static String basicHeader(String clientId, SecretValue secret) {
    byte[] secretBytes = secret.asUtf8Bytes();
    byte[] idBytes = clientId.getBytes(StandardCharsets.UTF_8);
    byte[] userInfo = new byte[idBytes.length + 1 + secretBytes.length];
    System.arraycopy(idBytes, 0, userInfo, 0, idBytes.length);
    userInfo[idBytes.length] = ':';
    System.arraycopy(secretBytes, 0, userInfo, idBytes.length + 1, secretBytes.length);
    String header = "Basic " + Base64.getEncoder().encodeToString(userInfo);
    Arrays.fill(userInfo, (byte) 0);
    Arrays.fill(secretBytes, (byte) 0);
    return header;
  }

  private static String encode(Map<String, String> form) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> e : form.entrySet()) {
      if (sb.length() > 0) {
        sb.append('&');
      }
      sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
          .append('=')
          .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
    }
    return sb.toString();
  }
}
