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
package eu.jsentinel.jcustos.propagation.oidc;

import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OutboundCall;
import eu.jsentinel.jcustos.propagation.oidc.cache.InMemoryTokenExchangeCache;
import eu.jsentinel.jcustos.propagation.oidc.strategy.ClientCredentialsStrategy;
import eu.jsentinel.jcustos.propagation.oidc.strategy.JCustosPropagationException;
import eu.jsentinel.jcustos.propagation.oidc.strategy.TokenExchangeStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-098 (CWE-1041, CWE-319): the two strategies use the one https rule, the one form-POST
 * and the one JSON reader of {@code jCustos-core} instead of copies of their own. A real JDK
 * {@link HttpServer} on loopback stands in for the token endpoint (no mocks).
 */
@DisplayName("JS-SEC-098 — propagation strategies on the shared https rule, form-POST and JSON reader")
class StrategyConsolidationTest {

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicReference<Map<String, String>> receivedForm = new AtomicReference<>();
  private final AtomicReference<String> receivedAuthorization = new AtomicReference<>();
  private volatile String answer = "{\"access_token\":\"minted\",\"expires_in\":3600}";

  @BeforeEach
  void start() throws IOException {
    System.setProperty("jcustos.dev", "true");
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      receivedForm.set(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
      receivedAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
      byte[] out = answer.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    tokenEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private static Map<String, String> parseForm(String raw) {
    Map<String, String> form = new HashMap<>();
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      if (eq > 0) {
        form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
      }
    }
    return form;
  }

  private ClientCredentialsStrategy clientCredentials(String clientId, String clientSecret) {
    return new ClientCredentialsStrategy(tokenEndpoint, clientId, clientSecret, HttpClient.newHttpClient(),
        new InMemoryTokenExchangeCache(), ClientCredentialsStrategy.NAME);
  }

  private TokenExchangeStrategy exchange(String clientId, String clientSecret) {
    return new TokenExchangeStrategy(tokenEndpoint, clientId, clientSecret, HttpClient.newHttpClient(),
        new InMemoryTokenExchangeCache());
  }

  private static OutboundCall call() {
    return new OutboundCall("svc", "m", "api", Map.of());
  }

  @Test
  @DisplayName("the token endpoint follows the one https rule: [::1] and 127.0.0.2 with the flag, nothing without")
  void httpsRule() {
    for (String uri : List.of("http://[::1]:8080/token", "http://127.0.0.2:8080/token", "http://localhost:8080/token")) {
      new TokenExchangeStrategy(URI.create(uri), "cid", "secret");
      ClientCredentialsStrategy.forClient(URI.create(uri), "cid", "secret");
    }
    for (String uri : List.of("http://localhost.evil.example/token", "http://127.0.0.1.nip.io/token")) {
      assertThrows(IllegalArgumentException.class, () -> new TokenExchangeStrategy(URI.create(uri), "c", "s"), uri);
      assertThrows(IllegalArgumentException.class,
          () -> ClientCredentialsStrategy.forClient(URI.create(uri), "c", "s"), uri);
    }
    System.clearProperty("jcustos.dev");
    for (String uri : List.of("http://[::1]:8080/token", "http://127.0.0.1:8080/token", "http://localhost:8080/token")) {
      IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
          () -> new TokenExchangeStrategy(URI.create(uri), "cid", "secret"), uri);
      assertTrue(refused.getMessage().startsWith("propagation/endpoint-not-https: "), refused.getMessage());
      assertThrows(IllegalArgumentException.class,
          () -> ClientCredentialsStrategy.forClient(URI.create(uri), "cid", "secret"), uri);
    }
  }

  @Test
  @DisplayName("client id and secret travel as client_secret_post; an id alone as a public client; none without id")
  void clientAuthentication() {
    exchange("cid", "csecret").resolve(call(), Optional.of(new BearerToken("subject-1")));
    assertEquals("cid", receivedForm.get().get("client_id"));
    assertEquals("csecret", receivedForm.get().get("client_secret"));
    assertEquals("subject-1", receivedForm.get().get("subject_token"));
    assertEquals(null, receivedAuthorization.get(), "client_secret_post, no Basic header");

    clientCredentials("cid", null).resolve(call(), Optional.empty());
    assertEquals("cid", receivedForm.get().get("client_id"));
    assertFalse(receivedForm.get().containsKey("client_secret"));
    assertEquals("client_credentials", receivedForm.get().get("grant_type"));

    clientCredentials(null, null).resolve(new OutboundCall("svc", "m", "other-api", Map.of()), Optional.empty());
    assertFalse(receivedForm.get().containsKey("client_id"));
    assertFalse(receivedForm.get().containsKey("client_secret"));
  }

  @Test
  @DisplayName("a unicode escape in the minted token is decoded (the old JsonResponse kept it raw)")
  void unicodeEscapeDecoded() {
    answer = "{\"access_token\":\"minted\\u002Dtoken\",\"expires_in\":3600}";
    HeaderValue header = exchange("cid", "csecret")
        .resolve(call(), Optional.of(new BearerToken("subject-2"))).orElseThrow();
    assertEquals("Bearer minted-token", header.value());
  }

  @Test
  @DisplayName("a response that names access_token twice is refused, neither token is forwarded")
  void duplicateAccessTokenRefused() {
    answer = "{\"access_token\":\"first\",\"access_token\":\"second\"}";
    JCustosPropagationException refused = assertThrows(JCustosPropagationException.class,
        () -> clientCredentials("cid", "csecret").resolve(call(), Optional.empty()));
    assertEquals("Token endpoint response missing access_token", refused.getMessage());
    assertFalse(refused.getMessage().contains("first"));
  }

  @Test
  @DisplayName("an unreachable endpoint is a JCustosPropagationException with status 0")
  void unreachable() throws IOException {
    int closedPort;
    try (java.net.ServerSocket socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      closedPort = socket.getLocalPort();
    }
    ClientCredentialsStrategy strategy = new ClientCredentialsStrategy(
        URI.create("http://127.0.0.1:" + closedPort + "/token"), "cid", "csecret", HttpClient.newHttpClient(),
        new InMemoryTokenExchangeCache(), ClientCredentialsStrategy.NAME);
    JCustosPropagationException refused = assertThrows(JCustosPropagationException.class,
        () -> strategy.resolve(call(), Optional.empty()));
    assertEquals(0, refused.httpStatus());
    assertTrue(refused.getMessage().startsWith("Token endpoint call failed: "), refused.getMessage());
  }
}
