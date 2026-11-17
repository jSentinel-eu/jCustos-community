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
package eu.jsentinel.jcustos.test.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * A real, dependency-light OIDC provider stub for V00.79 integration tests — a JDK
 * {@link HttpServer} on loopback that serves discovery, JWKS, token and UserInfo,
 * and signs <em>real</em> RS256 ID tokens with a freshly generated RSA key. No
 * mocks: a Relying-Party under test runs its actual discovery / token-exchange /
 * id-token-validation / userinfo pipeline against this server. Tests set the
 * desired ID-token / UserInfo claims (e.g. a Keycloak {@code realm_access} block)
 * to exercise vendor profiles end-to-end.
 *
 * <p>The issuer is {@code http://127.0.0.1:<port>}, so tests run with
 * {@code -Djcustos.dev=true} (the framework's loopback-http carve-out).
 *
 * <p><strong>Since 00.84.00 the flag is needed for the JWKS as well</strong>
 * (JS-SEC-098). Every endpoint jCustos calls follows one rule,
 * {@link eu.jsentinel.jcustos.net.EndpointSecurity}: {@code https}, or plain
 * {@code http} to a loopback host ({@code localhost}, {@code 127.0.0.0/8},
 * {@code [::1]}) only while {@code jcustos.dev=true}. Up to 00.83.00
 * {@code HttpJwksClient} accepted {@link #jwksUri()} without the flag; a test
 * that builds a validator from it now fails at construction with
 * {@code jwks/uri-not-https} unless the flag is set. Set it per test class —
 * {@code System.setProperty("jcustos.dev", "true")} before the first client is
 * built and {@code System.clearProperty("jcustos.dev")} afterwards — or for a
 * whole module in the Surefire configuration
 * ({@code <systemPropertyVariables><jcustos.dev>true</jcustos.dev></systemPropertyVariables>}).
 * Never set it in production: it is what admits cleartext {@code http}.
 */
public final class StubIdentityProvider implements AutoCloseable {

  private final HttpServer server;
  private final RSAKey signingKey;
  private final String issuer;
  private final String clientId;
  private final Supplier<Instant> clock;

  private volatile Map<String, Object> idTokenClaims = new LinkedHashMap<>();
  private volatile Map<String, Object> userInfoClaims =
      new LinkedHashMap<>(Map.of("sub", "stub-subject"));

  private StubIdentityProvider(String clientId, Supplier<Instant> clock) {
    this.clientId = Objects.requireNonNull(clientId, "clientId");
    this.clock = Objects.requireNonNull(clock, "clock");
    try {
      this.signingKey = new RSAKeyGenerator(2048).keyID("stub-key-1").generate();
      this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    } catch (Exception e) {
      throw new IllegalStateException("failed to start stub IdP", e);
    }
    this.issuer = "http://127.0.0.1:" + server.getAddress().getPort();
    server.createContext("/.well-known/openid-configuration", this::discovery);
    server.createContext("/jwks", this::jwks);
    server.createContext("/token", this::token);
    server.createContext("/userinfo", this::userinfo);
    server.start();
  }

  /** Starts a stub IdP for {@code clientId} using {@code clock} for token timestamps. */
  public static StubIdentityProvider start(String clientId, Supplier<Instant> clock) {
    return new StubIdentityProvider(clientId, clock);
  }

  public String issuer() {
    return issuer;
  }

  public URI issuerUri() {
    return URI.create(issuer);
  }

  public URI jwksUri() {
    return URI.create(issuer + "/jwks");
  }

  public URI tokenEndpoint() {
    return URI.create(issuer + "/token");
  }

  public URI userInfoEndpoint() {
    return URI.create(issuer + "/userinfo");
  }

  public String clientId() {
    return clientId;
  }

  /** @return the public signing key (for building a JwtValidator directly, if a test prefers). */
  public RSAKey publicSigningKey() {
    return signingKey.toPublicJWK();
  }

  /** Sets the extra claims merged into every issued ID token (e.g. vendor role blocks). */
  public StubIdentityProvider withIdTokenClaims(Map<String, Object> claims) {
    this.idTokenClaims = new LinkedHashMap<>(Objects.requireNonNull(claims, "claims"));
    return this;
  }

  /** Sets the UserInfo response claims (must include {@code sub}). */
  public StubIdentityProvider withUserInfoClaims(Map<String, Object> claims) {
    this.userInfoClaims = new LinkedHashMap<>(Objects.requireNonNull(claims, "claims"));
    return this;
  }

  /** Signs a real RS256 ID token with the given claims (used by {@code /token} + directly). */
  public String signIdToken(Map<String, Object> claims) {
    JWTClaimsSet.Builder b = new JWTClaimsSet.Builder();
    for (Map.Entry<String, Object> e : claims.entrySet()) {
      Object v = e.getValue();
      switch (e.getKey()) {
        case "iss" -> b.issuer((String) v);
        case "sub" -> b.subject((String) v);
        case "aud" -> {
          if (v instanceof List<?> list) {
            b.audience(list.stream().map(String::valueOf).toList());
          } else {
            b.audience((String) v);
          }
        }
        case "exp" -> b.expirationTime(Date.from(Instant.ofEpochSecond(((Number) v).longValue())));
        case "iat" -> b.issueTime(Date.from(Instant.ofEpochSecond(((Number) v).longValue())));
        default -> b.claim(e.getKey(), v);
      }
    }
    try {
      SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), b.build());
      jwt.sign(new RSASSASigner(signingKey));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException("failed to sign id token", e);
    }
  }

  private Map<String, Object> defaultIdTokenClaims() {
    Instant now = clock.get();
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", issuer);
    claims.put("sub", "stub-subject");
    claims.put("aud", clientId);
    claims.put("iat", now.getEpochSecond());
    claims.put("exp", now.plusSeconds(300).getEpochSecond());
    claims.putAll(idTokenClaims);
    return claims;
  }

  private void discovery(HttpExchange exchange) throws IOException {
    drain(exchange);
    respond(exchange, 200, "{"
        + "\"issuer\":\"" + issuer + "\","
        + "\"authorization_endpoint\":\"" + issuer + "/authorize\","
        + "\"token_endpoint\":\"" + tokenEndpoint() + "\","
        + "\"jwks_uri\":\"" + jwksUri() + "\","
        + "\"userinfo_endpoint\":\"" + userInfoEndpoint() + "\","
        + "\"end_session_endpoint\":\"" + issuer + "/logout\","
        + "\"scopes_supported\":[\"openid\",\"profile\",\"email\"],"
        + "\"response_types_supported\":[\"code\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}");
  }

  private void jwks(HttpExchange exchange) throws IOException {
    drain(exchange);
    respond(exchange, 200, "{\"keys\":[" + signingKey.toPublicJWK().toJSONString() + "]}");
  }

  private void token(HttpExchange exchange) throws IOException {
    drain(exchange);
    String idToken = signIdToken(defaultIdTokenClaims());
    respond(exchange, 200, "{"
        + "\"access_token\":\"stub-access-token\","
        + "\"token_type\":\"Bearer\","
        + "\"expires_in\":3600,"
        + "\"id_token\":\"" + idToken + "\"}");
  }

  private void userinfo(HttpExchange exchange) throws IOException {
    drain(exchange);
    respond(exchange, 200, toJson(userInfoClaims));
  }

  private static String toJson(Map<String, Object> map) {
    StringBuilder sb = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String, Object> e : map.entrySet()) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append('"').append(e.getKey()).append("\":").append(jsonValue(e.getValue()));
    }
    return sb.append('}').toString();
  }

  private static String jsonValue(Object v) {
    if (v == null) {
      return "null";
    }
    if (v instanceof Number || v instanceof Boolean) {
      return v.toString();
    }
    if (v instanceof List<?> list) {
      StringBuilder sb = new StringBuilder("[");
      for (int i = 0; i < list.size(); i++) {
        if (i > 0) {
          sb.append(',');
        }
        sb.append(jsonValue(list.get(i)));
      }
      return sb.append(']').toString();
    }
    if (v instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked")
      Map<String, Object> m = (Map<String, Object>) map;
      return toJson(m);
    }
    return '"' + v.toString().replace("\\", "\\\\").replace("\"", "\\\"") + '"';
  }

  private static void drain(HttpExchange exchange) throws IOException {
    exchange.getRequestBody().readAllBytes();
  }

  private static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] out = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, out.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(out);
    }
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
