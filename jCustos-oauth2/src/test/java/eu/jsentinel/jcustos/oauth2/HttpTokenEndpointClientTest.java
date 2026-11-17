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
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("HttpTokenEndpointClient — against a real JDK HttpServer token endpoint (no mocks)")
class HttpTokenEndpointClientTest {

  private static final Instant NOW = Instant.parse("2026-06-26T12:00:00Z");

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicReference<String> capturedAuth = new AtomicReference<>();
  private final AtomicReference<String> capturedBody = new AtomicReference<>();
  private volatile int status = 200;
  private volatile String responseBody = "{}";

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      capturedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
      capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      byte[] out = responseBody.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    tokenEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
    System.setProperty("jcustos.dev", "true"); // allow http://localhost in tests
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private HttpTokenEndpointClient client(ClientAuthentication auth) {
    return new HttpTokenEndpointClient(tokenEndpoint, auth, HttpClient.newHttpClient(), () -> NOW);
  }

  @Test
  @DisplayName("client_credentials with Basic auth: sends the Basic header and parses the token")
  void clientCredentialsBasic() {
    responseBody = "{\"access_token\":\"AT-1\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"a b\"}";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.ClientSecretBasic("svc", SecretValue.ofString("s3cr3t")))
        .clientCredentials(Set.of("a", "b"));

    TokenResponse tr = r.toOptional().orElseThrow(() -> new AssertionError("expected success, got " + r));
    assertEquals("AT-1", tr.accessToken());
    assertEquals("Bearer", tr.tokenType());
    assertEquals(Set.of("a", "b"), tr.scopes());
    assertEquals(NOW.plusSeconds(3600), tr.expiresAt().orElseThrow());
    assertTrue(capturedAuth.get().startsWith("Basic "), "Basic header must be sent");
    assertTrue(capturedBody.get().contains("grant_type=client_credentials"));
  }

  @Test
  @DisplayName("JS-SEC-034: a duplicate / multi-space scope response yields Result.success (never a thrown IAE)")
  void duplicateScopesDoNotThrow() {
    // "read read   write" — a duplicate scope value AND empty tokens from consecutive
    // spaces both made Set.of throw IllegalArgumentException, escaping the Result contract.
    responseBody = "{\"access_token\":\"AT-9\",\"token_type\":\"Bearer\",\"scope\":\"read read   write\"}";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.NoneAuthentication("svc"))
        .clientCredentials(Set.of());

    TokenResponse tr = r.toOptional().orElseThrow(() -> new AssertionError("expected success, got " + r));
    assertEquals(Set.of("read", "write"), tr.scopes());
  }

  @Test
  @DisplayName("client_secret_post: client_id + client_secret go into the form body, not a header")
  void clientSecretPost() {
    responseBody = "{\"access_token\":\"AT-2\",\"token_type\":\"Bearer\"}";
    client(new ClientAuthentication.ClientSecretPost("svc", SecretValue.ofString("s3cr3t")))
        .clientCredentials(Set.of()).toOptional().orElseThrow();
    assertEquals(null, capturedAuth.get(), "no Authorization header for client_secret_post");
    assertTrue(capturedBody.get().contains("client_id=svc"));
    assertTrue(capturedBody.get().contains("client_secret=s3cr3t"));
  }

  @Test
  @DisplayName("a 4xx error body maps to ProtocolError(error), never echoing error_description")
  void errorBodyMapsToProtocolError() {
    status = 400;
    responseBody = "{\"error\":\"invalid_grant\",\"error_description\":\"internal node 10.0.0.5 said no\"}";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.NoneAuthentication("svc")).refresh(SecretValue.ofString("rt"));
    OAuth2Error err = r.map(t -> (OAuth2Error) null).getOrElse(e -> e);
    OAuth2Error.ProtocolError pe = assertInstanceOf(OAuth2Error.ProtocolError.class, err);
    assertEquals("invalid_grant", pe.oauthError());
    assertEquals("oauth2/protocol-error:invalid_grant", pe.code());
    assertTrue(!pe.message().contains("10.0.0.5"), "error_description detail must not leak");
  }

  @Test
  @DisplayName("a non-2xx without an error field maps to EndpointError(status)")
  void non2xxMapsToEndpointError() {
    status = 503;
    responseBody = "service unavailable";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.NoneAuthentication("svc")).clientCredentials(Set.of());
    OAuth2Error err = r.map(t -> (OAuth2Error) null).getOrElse(e -> e);
    OAuth2Error.EndpointError ee = assertInstanceOf(OAuth2Error.EndpointError.class, err);
    assertEquals(503, ee.statusCode());
  }

  @Test
  @DisplayName("a 2xx without access_token maps to MalformedResponse")
  void missingAccessTokenMalformed() {
    responseBody = "{\"token_type\":\"Bearer\"}";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.NoneAuthentication("svc")).clientCredentials(Set.of());
    assertInstanceOf(OAuth2Error.MalformedResponse.class, r.map(t -> (OAuth2Error) null).getOrElse(e -> e));
  }

  @Test
  @DisplayName("a non-https, non-loopback token endpoint is refused at construction")
  void httpsEnforced() {
    System.clearProperty("jcustos.dev");
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        new HttpTokenEndpointClient(URI.create("http://idp.example/token"),
            new ClientAuthentication.NoneAuthentication("svc"), HttpClient.newHttpClient()));
    assertTrue(ex.getMessage().contains("token-endpoint-not-https"));
  }

  // ── JS-SEC-098 (CWE-1041): the response is read with the one bounded JSON reader ──

  @Test
  @DisplayName("JS-SEC-098: a unicode escape in the token response is decoded (the old scanner kept it raw)")
  void unicodeEscapeDecoded() {
    responseBody = "{\"access_token\":\"AT\\u002D3\",\"token_type\":\"Bearer\"}";
    TokenResponse tr = client(new ClientAuthentication.NoneAuthentication("svc"))
        .clientCredentials(Set.of()).toOptional().orElseThrow();
    assertEquals("AT-3", tr.accessToken());
  }

  @Test
  @DisplayName("JS-SEC-098: a token response naming access_token twice is malformed, neither value is used")
  void duplicateAccessTokenMalformed() {
    responseBody = "{\"access_token\":\"AT-first\",\"token_type\":\"Bearer\",\"access_token\":\"AT-second\"}";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.NoneAuthentication("svc")).clientCredentials(Set.of());
    assertInstanceOf(OAuth2Error.MalformedResponse.class, r.map(t -> (OAuth2Error) null).getOrElse(e -> e));
  }

  @Test
  @DisplayName("JS-SEC-098: trailing content after the token response makes it malformed")
  void trailingContentMalformed() {
    responseBody = "{\"access_token\":\"AT-4\",\"token_type\":\"Bearer\"} trailing";
    Result<TokenResponse, OAuth2Error> r = client(
        new ClientAuthentication.NoneAuthentication("svc")).clientCredentials(Set.of());
    assertInstanceOf(OAuth2Error.MalformedResponse.class, r.map(t -> (OAuth2Error) null).getOrElse(e -> e));
  }

  @Test
  @DisplayName("JS-SEC-098: the token endpoint follows the one https rule — [::1] and 127.0.0.2 with the flag only")
  void loopbackRule() {
    for (String uri : java.util.List.of("http://[::1]:8080/token", "http://127.0.0.2:8080/token")) {
      new HttpTokenEndpointClient(URI.create(uri), new ClientAuthentication.NoneAuthentication("svc"),
          HttpClient.newHttpClient());
    }
    System.clearProperty("jcustos.dev");
    for (String uri : java.util.List.of("http://[::1]:8080/token", "http://127.0.0.2:8080/token",
        "http://localhost:8080/token")) {
      assertThrows(IllegalArgumentException.class, () -> new HttpTokenEndpointClient(URI.create(uri),
          new ClientAuthentication.NoneAuthentication("svc"), HttpClient.newHttpClient()), uri);
    }
  }
}
