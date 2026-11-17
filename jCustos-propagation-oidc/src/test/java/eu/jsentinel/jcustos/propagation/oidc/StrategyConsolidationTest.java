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
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
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
  private final AtomicInteger hits = new AtomicInteger();
  private volatile String answer = "{\"access_token\":\"minted\",\"expires_in\":3600}";

  @BeforeEach
  void start() throws IOException {
    System.setProperty("jcustos.dev", "true");
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      hits.incrementAndGet();
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
  @DisplayName("RF25: a token with an escaped CR/LF is a JCustosPropagationException and is not cached - the next call asks again")
  void tokenWithCrLfIsRefusedAndNotCached() {
    answer = "{\"access_token\":\"abc\\r\\nX-Injected: 1\",\"expires_in\":3600}";
    ClientCredentialsStrategy credentials = clientCredentials("cid", "csecret");
    TokenExchangeStrategy exchange = exchange("cid", "csecret");

    for (int call = 1; call <= 2; call++) {
      JCustosPropagationException refused = assertThrows(JCustosPropagationException.class,
          () -> credentials.resolve(call(), Optional.empty()),
          "until the exit review the token was cached and HeaderValue threw IllegalArgumentException");
      assertEquals(200, refused.httpStatus());
      assertFalse(refused.getMessage().contains("X-Injected"), refused.getMessage());
      assertEquals(call, hits.get(), "a refused token is not cached: call " + call + " reaches the endpoint");
    }
    hits.set(0);
    for (int call = 1; call <= 2; call++) {
      assertThrows(JCustosPropagationException.class,
          () -> exchange.resolve(call(), Optional.of(new BearerToken("subject-3"))));
      assertEquals(call, hits.get(), "token exchange: call " + call + " reaches the endpoint");
    }
  }

  @Test
  @DisplayName("RF25: a token is sent only if it is printable ASCII without space; providers' other printable characters pass")
  void bearerCredentialCharacters() {
    for (String refusedToken : List.of("", "two words", "tab\\tbefore", "caf\\u00e9", "nul\\u0000", "del\\u007f")) {
      answer = "{\"access_token\":\"" + refusedToken + "\",\"expires_in\":3600}";
      assertThrows(JCustosPropagationException.class,
          () -> clientCredentials("cid", "csecret").resolve(call(), Optional.empty()), refusedToken);
    }
    for (String token : List.of("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", "a-._~+/b==", "00Dx!AQ4AQ:x|y")) {
      answer = "{\"access_token\":\"" + token + "\",\"expires_in\":3600}";
      HeaderValue header = clientCredentials("cid", "csecret").resolve(call(), Optional.empty()).orElseThrow();
      assertEquals("Bearer " + token, header.value());
    }
  }

  @Test
  @DisplayName("RF25: a runtime exception of the HTTP client is a JCustosPropagationException with status 0, as before 00.84.00")
  void runtimeExceptionOfTheClientIsWrapped() {
    IllegalStateException clientFailure = new IllegalStateException("client is shut down");
    ClientCredentialsStrategy credentials = new ClientCredentialsStrategy(tokenEndpoint, "cid", "csecret",
        new FailingHttpClient(clientFailure), new InMemoryTokenExchangeCache(), ClientCredentialsStrategy.NAME);
    TokenExchangeStrategy exchange = new TokenExchangeStrategy(tokenEndpoint, "cid", "csecret",
        new FailingHttpClient(clientFailure), new InMemoryTokenExchangeCache());

    JCustosPropagationException refused = assertThrows(JCustosPropagationException.class,
        () -> credentials.resolve(call(), Optional.empty()));
    assertEquals(0, refused.httpStatus());
    assertEquals("Token endpoint call failed: IllegalStateException", refused.getMessage());
    assertInstanceOf(IllegalStateException.class, refused.getCause());
    assertThrows(JCustosPropagationException.class,
        () -> exchange.resolve(call(), Optional.of(new BearerToken("subject-4"))));
  }

  @Test
  @DisplayName("RF27: a negative expires_in counts as absent - the token is cached for the default lifetime, not as already expired")
  void negativeExpiresInCountsAsAbsent() {
    answer = "{\"access_token\":\"minted\",\"expires_in\":-5}";
    ClientCredentialsStrategy credentials = clientCredentials("cid", "csecret");

    credentials.resolve(call(), Optional.empty());
    HeaderValue second = credentials.resolve(call(), Optional.empty()).orElseThrow();

    assertEquals("Bearer minted", second.value());
    assertEquals(1, hits.get(), "until the exit review the entry expired before it was cached");
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

  /** A hand-written HTTP client whose {@code send} fails with a runtime exception. */
  private static final class FailingHttpClient extends HttpClient {
    private final RuntimeException failure;

    FailingHttpClient(RuntimeException failure) {
      this.failure = failure;
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
      throw failure;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
        HttpResponse.BodyHandler<T> handler) {
      throw failure;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
        HttpResponse.BodyHandler<T> handler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
      throw failure;
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
      return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
      return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
      return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
      return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
      throw new UnsupportedOperationException();
    }

    @Override
    public SSLParameters sslParameters() {
      return new SSLParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
      return Optional.empty();
    }

    @Override
    public Version version() {
      return Version.HTTP_1_1;
    }

    @Override
    public Optional<Executor> executor() {
      return Optional.empty();
    }
  }
}
