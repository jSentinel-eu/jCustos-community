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
package eu.jsentinel.jcustos.oauth2.http;

import com.sun.net.httpserver.HttpServer;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-098 (CWE-1041, CWE-770): the one form-POST of jCustos, against a real JDK
 * {@link HttpServer} on loopback (no mocks).
 */
@DisplayName("JS-SEC-098 — OAuth2FormPost: client authentication, size cap, transport errors")
class OAuth2FormPostTest {

  private static final Instant NOW = Instant.parse("2026-11-17T10:00:00Z");

  private HttpServer server;
  private URI endpoint;
  private final AtomicReference<Map<String, String>> receivedForm = new AtomicReference<>();
  private final AtomicReference<String> receivedAuthorization = new AtomicReference<>();
  private final AtomicReference<String> receivedContentType = new AtomicReference<>();
  private final AtomicReference<String> receivedAccept = new AtomicReference<>();
  private volatile byte[] answer = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
  private volatile int answerStatus = 200;

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      receivedForm.set(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
      receivedAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
      receivedContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
      receivedAccept.set(exchange.getRequestHeaders().getFirst("Accept"));
      byte[] body = answer;
      exchange.sendResponseHeaders(answerStatus, body.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private static Map<String, String> parseForm(String raw) {
    Map<String, String> form = new HashMap<>();
    if (raw.isEmpty()) {
      return form;
    }
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
          URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return form;
  }

  private static OAuth2FormPost.Outcome success(Result<OAuth2FormPost.Outcome, OAuth2Error> result) {
    assertTrue(result.isSuccess(), () -> "expected a completed exchange: " + result);
    return result.getOrThrow();
  }

  private static OAuth2Error failure(Result<OAuth2FormPost.Outcome, OAuth2Error> result) {
    assertTrue(result.isFailure(), () -> "expected a failure: " + result);
    return result.fold(ok -> null, e -> e);
  }

  @Test
  @DisplayName("client_secret_basic: credentials in the Basic header, none in the body; JSON and form headers")
  void clientSecretBasic() {
    OAuth2FormPost.Outcome outcome = success(OAuth2FormPost.post(HttpClient.newHttpClient(), endpoint,
        Map.of("grant_type", "client_credentials"),
        new ClientAuthentication.ClientSecretBasic("rp", SecretValue.ofString("s3cret"))));

    assertEquals(200, outcome.status());
    assertEquals("{\"ok\":true}", outcome.body());
    assertEquals("Basic " + Base64.getEncoder().encodeToString("rp:s3cret".getBytes(StandardCharsets.UTF_8)),
        receivedAuthorization.get());
    assertEquals(Map.of("grant_type", "client_credentials"), receivedForm.get());
    assertEquals("application/x-www-form-urlencoded", receivedContentType.get());
    assertEquals("application/json", receivedAccept.get());
  }

  @Test
  @DisplayName("client_secret_post: client_id and client_secret in the body, the caller's map untouched")
  void clientSecretPost() {
    Map<String, String> form = Map.of("grant_type", "client_credentials", "scope", "a b");
    success(OAuth2FormPost.post(HttpClient.newHttpClient(), endpoint, form,
        new ClientAuthentication.ClientSecretPost("rp", SecretValue.ofString("s3cret"))));

    assertEquals(Map.of("grant_type", "client_credentials", "scope", "a b",
        "client_id", "rp", "client_secret", "s3cret"), receivedForm.get());
    assertNull(receivedAuthorization.get());
    assertEquals(2, form.size(), "an unmodifiable form is accepted and not changed");
  }

  @Test
  @DisplayName("public client: client_id only; without client authentication: neither")
  void publicAndUnauthenticated() {
    success(OAuth2FormPost.post(HttpClient.newHttpClient(), endpoint, Map.of("grant_type", "x"),
        new ClientAuthentication.NoneAuthentication("rp")));
    assertEquals(Map.of("grant_type", "x", "client_id", "rp"), receivedForm.get());

    success(OAuth2FormPost.postWithoutClientAuthentication(HttpClient.newHttpClient(), endpoint,
        Map.of("grant_type", "x")));
    assertEquals(Map.of("grant_type", "x"), receivedForm.get());
    assertNull(receivedAuthorization.get());
  }

  @Test
  @DisplayName("client_secret_jwt: the assertion is addressed to the endpoint and dated with the given clock")
  void clientSecretJwt() {
    success(OAuth2FormPost.post(HttpClient.newHttpClient(), endpoint, Map.of("grant_type", "x"),
        new ClientAuthentication.ClientSecretJwt("rp", SecretValue.ofString("a-shared-secret-of-32-bytes!!!!!"),
            Duration.ofMinutes(1)), () -> NOW));

    Map<String, String> form = receivedForm.get();
    assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form.get("client_assertion_type"));
    assertFalse(form.containsKey("client_secret"), "the shared secret never travels itself");
    String[] segments = form.get("client_assertion").split("\\.");
    assertEquals(3, segments.length);
    String claims = new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
    assertTrue(claims.contains("\"aud\":\"" + endpoint + "\""), claims);
    assertTrue(claims.contains("\"iat\":" + NOW.getEpochSecond()), claims);
  }

  @Test
  @DisplayName("private_key_jwt without a JwtSigner on the class path is an explicit, non-secret failure")
  void privateKeyJwtWithoutSigner() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    JwtSigningKey key = JwtSigningKey.of(generator.generateKeyPair().getPrivate(), JwsAlgorithm.ES256, "kid-1");
    IllegalStateException missing = assertThrows(IllegalStateException.class,
        () -> OAuth2FormPost.post(HttpClient.newHttpClient(), endpoint, Map.of("grant_type", "x"),
            new ClientAuthentication.PrivateKeyJwt("rp", key, Duration.ofMinutes(1))));
    assertTrue(missing.getMessage().startsWith("oauth2/no-jwt-signer"), missing.getMessage());
  }

  @Test
  @DisplayName("JS-SEC-036: a body of exactly the cap is read, one byte more is refused")
  void responseSizeCap() {
    answer = new byte[OAuth2FormPost.MAX_RESPONSE_BYTES];
    assertEquals(OAuth2FormPost.MAX_RESPONSE_BYTES,
        success(OAuth2FormPost.postWithoutClientAuthentication(HttpClient.newHttpClient(), endpoint,
            Map.of())).body().length());

    answer = new byte[OAuth2FormPost.MAX_RESPONSE_BYTES + 1];
    OAuth2Error error = failure(OAuth2FormPost.postWithoutClientAuthentication(HttpClient.newHttpClient(),
        endpoint, Map.of()));
    assertTrue(error instanceof OAuth2Error.NetworkError || error instanceof OAuth2Error.MalformedResponse,
        error.toString());
  }

  @Test
  @DisplayName("a non-2xx status is a completed exchange; the caller decides")
  void errorStatusIsAnOutcome() {
    answerStatus = 400;
    answer = "{\"error\":\"invalid_client\"}".getBytes(StandardCharsets.UTF_8);
    OAuth2FormPost.Outcome outcome = success(OAuth2FormPost.postWithoutClientAuthentication(
        HttpClient.newHttpClient(), endpoint, Map.of()));
    assertEquals(400, outcome.status());
    assertFalse(outcome.toString().contains("invalid_client"), "Outcome.toString masks the body");
  }

  @Test
  @DisplayName("an unreachable endpoint is a network-error, not an exception")
  void unreachable() throws IOException {
    int closedPort;
    try (ServerSocket socket = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      closedPort = socket.getLocalPort();
    }
    OAuth2Error error = failure(OAuth2FormPost.postWithoutClientAuthentication(HttpClient.newHttpClient(),
        URI.create("http://127.0.0.1:" + closedPort + "/token"), Map.of()));
    assertInstanceOf(OAuth2Error.NetworkError.class, error);
  }
}
