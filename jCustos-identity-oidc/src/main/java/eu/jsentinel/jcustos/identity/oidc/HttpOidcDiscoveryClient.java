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
import eu.jsentinel.jcustos.identity.oidc.internal.OidcJson;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.internal.OAuth2FormPost;
import eu.jsentinel.jcustos.oidc.api.OidcDiscoveryClient;
import eu.jsentinel.jcustos.oidc.api.OidcProviderMetadata;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Fetches OIDC provider metadata from {@code <issuer>/.well-known/openid-configuration}
 * over JDK {@link HttpClient} (OIDC Discovery 1.0 / RFC 8414, V00.78). HTTPS is
 * enforced (the V00.77 dev-loopback carve-out), the response body is capped at
 * 1 MiB and parsed by the in-tree {@link OidcJson}. The returned {@code issuer}
 * MUST exactly equal the requested issuer (Discovery §4.3 — defeats a rogue
 * metadata document claiming someone else's issuer). Results are TTL-cached.
 */
public final class HttpOidcDiscoveryClient implements OidcDiscoveryClient {

  /** Default discovery-document cache TTL. */
  public static final long DEFAULT_TTL_MILLIS = Duration.ofHours(1).toMillis();
  private static final int MAX_BYTES = 1024 * 1024;
  private static final String CODE = "oauth2/discovery-endpoint";
  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private final HttpClient http;
  private final long ttlMillis;
  private final Map<URI, Cached> cache = new LinkedHashMap<>();

  private record Cached(OidcProviderMetadata metadata, long expiresAtMillis) {
  }

  public HttpOidcDiscoveryClient(HttpClient http) {
    this(http, DEFAULT_TTL_MILLIS);
  }

  public HttpOidcDiscoveryClient(HttpClient http, long ttlMillis) {
    this.http = Objects.requireNonNull(http, "http");
    if (ttlMillis < 0) {
      throw new IllegalArgumentException("ttlMillis must be >= 0");
    }
    this.ttlMillis = ttlMillis;
  }

  @Override
  public Result<OidcProviderMetadata, OAuth2Error> discover(URI issuer) {
    Objects.requireNonNull(issuer, "issuer");
    OAuth2FormPost.requireHttps(issuer, CODE);
    long now = System.currentTimeMillis();
    synchronized (cache) {
      Cached hit = cache.get(issuer);
      if (hit != null && hit.expiresAtMillis() > now) {
        return Result.success(hit.metadata());
      }
    }

    URI wellKnown = URI.create(
        issuer.toString().replaceAll("/+$", "") + "/.well-known/openid-configuration");
    HttpResponse<byte[]> response;
    try {
      response = http.send(HttpRequest.newBuilder(wellKnown).timeout(TIMEOUT)
          .header("Accept", "application/json").GET().build(),
          BoundedHttpBody.ofByteArray(MAX_BYTES + 1));
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
      return Result.failure(new OAuth2Error.MalformedResponse("discovery body exceeds the size cap"));
    }
    body = new String(bytes, StandardCharsets.UTF_8);

    Map<String, Object> json;
    try {
      json = OidcJson.parseObject(body);
    } catch (OidcJson.JsonException e) {
      return Result.failure(new OAuth2Error.MalformedResponse("invalid discovery document"));
    }

    String metaIssuer = str(json, "issuer");
    if (metaIssuer == null || !metaIssuer.equals(issuer.toString())) {
      // OIDC Discovery §4.3 / RFC 8414 §3.3: issuer mismatch is a substitution attack.
      return Result.failure(new OAuth2Error.MalformedResponse("issuer mismatch in discovery document"));
    }
    URI authorization = uri(json, "authorization_endpoint");
    URI token = uri(json, "token_endpoint");
    URI jwks = uri(json, "jwks_uri");
    if (authorization == null || token == null || jwks == null) {
      return Result.failure(new OAuth2Error.MalformedResponse(
          "discovery document missing a mandatory endpoint"));
    }

    OidcProviderMetadata metadata = new OidcProviderMetadata(
        metaIssuer, authorization, token, jwks,
        optUri(json, "userinfo_endpoint"),
        optUri(json, "end_session_endpoint"),
        optUri(json, "introspection_endpoint"),
        optUri(json, "revocation_endpoint"),
        optUri(json, "device_authorization_endpoint"),
        strSet(json, "scopes_supported"),
        strSet(json, "response_types_supported"),
        strSet(json, "id_token_signing_alg_values_supported"),
        // JS-SEC-150 (CWE-346, RFC 9207 §3): whether the issuer puts `iss` on every
        // authorisation response; absent means false.
        Boolean.TRUE.equals(json.get("authorization_response_iss_parameter_supported")));

    synchronized (cache) {
      cache.put(issuer, new Cached(metadata, now + ttlMillis));
    }
    return Result.success(metadata);
  }

  private static String str(Map<String, Object> json, String key) {
    return json.get(key) instanceof String s ? s : null;
  }

  private static URI uri(Map<String, Object> json, String key) {
    String value = str(json, key);
    return value == null ? null : URI.create(value);
  }

  private static Optional<URI> optUri(Map<String, Object> json, String key) {
    return Optional.ofNullable(uri(json, key));
  }

  private static Set<String> strSet(Map<String, Object> json, String key) {
    if (json.get(key) instanceof List<?> list) {
      java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
      for (Object o : list) {
        if (o instanceof String s) {
          out.add(s);
        }
      }
      return out;
    }
    return Set.of();
  }
}
