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
package eu.jsentinel.jcustos.rest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.rest.RestOriginGuard.MissingHeaders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RestOriginGuard} over HTTP (CSRF, CWE-352): a real JDK {@link HttpServer} on loopback
 * whose router runs the installed guard as its outermost filter, the JDK HTTP client playing
 * the browser (it sends the {@code Origin}, {@code Sec-Fetch-Site} and {@code Cookie} a browser
 * would) and a raw socket where a request needs a header the client does not let us choose.
 */
@DisplayName("RestOriginGuard over HTTP (CSRF, CWE-352)")
class RestOriginGuardHttpTest {

  private static final String SESSION_COOKIE = "APP_SESSION=4f1c2b9e77aa";
  private static final String FOREIGN_ORIGIN = "https://attacker.example";

  private final InMemoryAuditEventStore store = new InMemoryAuditEventStore();
  private final AtomicInteger handled = new AtomicInteger();
  private final HttpClient client = HttpClient.newHttpClient();
  private HttpServer server;
  private String base;
  private String ownOrigin;

  @BeforeEach
  void start() throws IOException {
    JCustosServiceResolver.setJCustosAuditService(new StoreBackedJCustosAuditService(store));
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext("/api", this::route);
    server.start();
    ownOrigin = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
        + server.getAddress().getPort();
    base = ownOrigin + "/api/documents";
  }

  @AfterEach
  void stop() {
    server.stop(0);
    RestOriginGuard.reset();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("a cross-origin POST with the session cookie is answered 403 and audited; the handler does not run")
  void crossOriginPostWithCookie_is403() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());

    HttpResponse<String> response = send("POST", Map.of(
        "Origin", FOREIGN_ORIGIN, "Sec-Fetch-Site", "cross-site", "Cookie", SESSION_COOKIE));

    assertEquals(HttpStatus.FORBIDDEN.code(), response.statusCode());
    assertEquals("Forbidden", response.body());
    assertEquals(0, handled.get());
    List<AuditEnvelope> envelopes = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, envelopes.size());
    AccessDenied denied = assertInstanceOf(AccessDenied.class, envelopes.getFirst().event());
    assertEquals("csrf:origin-mismatch", denied.reason());
    assertEquals("/api/documents", denied.route());
    assertNotNull(envelopes.getFirst().correlationId());
  }

  @Test
  @DisplayName("a same-origin POST passes, with Sec-Fetch-Site and with the Origin alone")
  void sameOriginPost_passes() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());

    assertEquals(HttpStatus.OK.code(), send("POST", Map.of(
        "Origin", ownOrigin, "Sec-Fetch-Site", "same-origin", "Cookie", SESSION_COOKIE)).statusCode());
    assertEquals(HttpStatus.OK.code(), send("DELETE", Map.of(
        "Origin", ownOrigin, "Cookie", SESSION_COOKIE)).statusCode(),
        "a browser without fetch metadata: the Origin matches Host");

    assertEquals(2, handled.get());
    assertTrue(store.query(TenantId.DEFAULT, AuditQuery.all()).isEmpty());
  }

  @Test
  @DisplayName("Sec-Fetch-Site: cross-site with an origin that starts like the own one is 403")
  void crossSiteLookalike_is403() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());

    String lookalike = "http://" + InetAddress.getLoopbackAddress().getHostAddress()
        + ".attacker.example:" + server.getAddress().getPort();
    HttpResponse<String> response = send("PUT", Map.of(
        "Origin", lookalike, "Sec-Fetch-Site", "cross-site", "Cookie", SESSION_COOKIE));

    assertEquals(HttpStatus.FORBIDDEN.code(), response.statusCode());
    assertEquals(0, handled.get());
  }

  @Test
  @DisplayName("without Origin (curl) the POST passes; in the strict setting it is 403")
  void requestWithoutOrigin_passesOrIsRefusedWhenStrict() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    assertEquals(HttpStatus.OK.code(), send("POST", Map.of()).statusCode());

    RestOriginGuard.install(RestOriginGuard.sameOrigin().withMissingHeaders(MissingHeaders.REFUSE));
    assertEquals(HttpStatus.FORBIDDEN.code(), send("POST", Map.of()).statusCode());

    assertEquals(1, handled.get());
  }

  @Test
  @DisplayName("GET is untouched, from a foreign origin and in the strict setting")
  void get_isUntouched() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin().withMissingHeaders(MissingHeaders.REFUSE));

    assertEquals(HttpStatus.OK.code(), send("GET", Map.of(
        "Origin", FOREIGN_ORIGIN, "Sec-Fetch-Site", "cross-site", "Cookie", SESSION_COOKIE)).statusCode());
    assertEquals(HttpStatus.OK.code(), send("GET", Map.of()).statusCode());
    assertEquals(2, handled.get());
  }

  @Test
  @DisplayName("behind a proxy: the allowlist decides, the internal Host is not an origin of the application")
  void allowlistBehindAProxy() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin()
        .withAllowedOrigins(Set.of("https://app.example")));

    assertEquals(HttpStatus.OK.code(), raw("https://app.example"), "the public origin");
    assertEquals(HttpStatus.FORBIDDEN.code(), raw(ownOrigin), "the internal origin");
    assertEquals(1, handled.get());
  }

  @Test
  @DisplayName("without an installed guard the router serves every request, as before")
  void noGuardInstalled_servesEverything() throws Exception {
    assertEquals(HttpStatus.OK.code(), send("POST", Map.of(
        "Origin", FOREIGN_ORIGIN, "Sec-Fetch-Site", "cross-site", "Cookie", SESSION_COOKIE)).statusCode());
    assertEquals(1, handled.get());
  }

  // ── the application side: a router whose outermost filter is the installed guard ──

  private void route(HttpExchange exchange) throws IOException {
    try (exchange) {
      Captured response = new Captured();
      Map<String, List<String>> lines = exchange.getRequestHeaders();
      if (RestHeaderLines.rejectDuplicates(lines, response)) {
        response.writeTo(exchange);
        return;
      }
      RestRequest request = new ExchangeRequest(exchange.getRequestMethod(),
          exchange.getRequestURI().getPath(), lines);
      if (RestOriginGuard.installed().map(guard -> !guard.allow(request, response)).orElse(false)) {
        response.writeTo(exchange);
        return;
      }
      handled.incrementAndGet();
      response.status(HttpStatus.OK.code());
      response.body("ok");
      response.writeTo(exchange);
    }
  }

  private HttpResponse<String> send(String method, Map<String, String> headers)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base))
        .method(method, "GET".equals(method)
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString("{}"));
    headers.forEach(builder::header);
    return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
  }

  /** A POST with a Host the client would not send: the public name a proxy forwards. */
  private int raw(String origin) throws IOException {
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), server.getAddress().getPort())) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(("POST /api/documents HTTP/1.1\r\n"
          + "Host: internal:8080\r\n"
          + "Origin: " + origin + "\r\n"
          + "Sec-Fetch-Site: cross-site\r\n"
          + "Cookie: " + SESSION_COOKIE + "\r\n"
          + "Content-Length: 0\r\n"
          + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      InputStream in = socket.getInputStream();
      String answer = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
      return Integer.parseInt(answer.substring("HTTP/1.1 ".length(), "HTTP/1.1 ".length() + 3));
    }
  }

  private record ExchangeRequest(String method, String path, Map<String, List<String>> lines)
      implements RestRequest {

    @Override
    public Map<String, String> headers() {
      return RestHeaderLines.joined(lines);
    }

    @Override
    public List<String> headerValues(String name) {
      return RestHeaderLines.values(lines, name);
    }

    @Override
    public Map<String, String> queryParameters() {
      return Map.of();
    }
  }

  private static final class Captured implements RestResponse {
    private int status = HttpStatus.OK.code();
    private String body = "";
    private final Map<String, String> headers = new LinkedHashMap<>();

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String value) {
      this.body = value == null ? "" : value;
    }

    @Override
    public void header(String name, String value) {
      headers.put(name, value);
    }

    void writeTo(HttpExchange exchange) throws IOException {
      headers.forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
      if (bytes.length > 0) {
        exchange.getResponseBody().write(bytes);
      }
    }
  }
}
