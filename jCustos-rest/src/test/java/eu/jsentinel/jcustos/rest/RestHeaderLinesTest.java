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
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.policy.api.JCustosPolicies;
import eu.jsentinel.jcustos.policy.api.PolicyContext;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-113 (CWE-348, CWE-290): a header that arrives on several lines.
 *
 * <p>The transport tests run a JDK {@link HttpServer} on loopback and send the
 * request through a raw socket, because no HTTP client lets a test put the same
 * header on two lines in a chosen order. The peer the server sees is
 * {@code 127.0.0.1}, which the resolver is told to trust — the position of a
 * reverse proxy that appended its own {@code X-Forwarded-For} line (HAProxy
 * {@code option forwardfor}) behind the line the client forged.
 */
@DisplayName("JS-SEC-113: multi-line request headers in the REST path")
class RestHeaderLinesTest {

  /** What the attacker wrote into the request. Inside the allow-listed network on purpose. */
  private static final String FORGED_CLIENT_LINE = "10.66.66.66";
  /** What the trusted proxy appended: the address it really saw. */
  private static final String PROXY_LINE = "203.0.113.50";
  private static final String OFFICE_POLICY = "office.only";
  /** Loopback only; also the peer address the resolver is told to trust. */
  private static final String LOOPBACK = "127.0.0.1";

  private HttpServer server;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(LOOPBACK));
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    registry.register(JCustosPolicies.ipAllowList(
        OFFICE_POLICY, RestAccessContextFactory.CLIENT_ADDRESS_ATTRIBUTE, "10.0.0.0/8"));
    JCustosServiceResolver.setPolicyRegistry(registry);
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop(0);
    }
    JCustosServiceResolver.resetAll();
    RestDecisionContext.reset();
  }

  // ── two X-Forwarded-For lines over a real socket ─────────────────

  @Test
  @DisplayName("adapter returning every line: the resolved address is the LAST line's value, ipAllowList denies")
  void twoForwardedForLines_headerValuesAdapter_lastLineWins() throws Exception {
    assertProxyLineWins(HeaderMode.ALL_LINES_FIRST_LINE_MAP);
  }

  @Test
  @DisplayName("adapter joining the lines into headers(): the default headerValues sees both, ipAllowList denies")
  void twoForwardedForLines_joinedMapAdapter_lastLineWins() throws Exception {
    assertProxyLineWins(HeaderMode.JOINED_MAP_DEFAULT_VALUES);
  }

  private void assertProxyLineWins(HeaderMode mode) throws Exception {
    AtomicReference<Optional<String>> resolved = new AtomicReference<>();
    AtomicReference<PolicyDecision> policyDecision = new AtomicReference<>();
    AtomicBoolean handlerRan = new AtomicBoolean();
    JCustosSubject alice = new JCustosSubject("u-alice", "alice", Set.of(), Set.of());
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.of(alice));

    startServer(exchange -> {
      RestRequest request = new ExchangeRestRequest(exchange, mode);
      ExchangeRestResponse response = new ExchangeRestResponse();
      resolved.set(RestClientAddress.resolve(request));

      AccessContext context = new RestAccessContextFactory()
          .create(request, Optional.of(alice), "get", Map.of());
      policyDecision.set(JCustosServiceResolver.policyRegistry()
          .evaluate(OFFICE_POLICY, new PolicyContext(context, OFFICE_POLICY)));

      filter.authorizeAndHandle(request, response, (req, res) -> {
        handlerRan.set(true);
        res.status(HttpStatus.NO_CONTENT.code());
      }, OfficeFixture.class.getDeclaredMethod("report"));
      response.send(exchange);
    });

    String statusLine = rawRequest(
        "X-Forwarded-For: " + FORGED_CLIENT_LINE,
        "X-Forwarded-For: " + PROXY_LINE);

    assertEquals(Optional.of(PROXY_LINE), resolved.get(),
        "the entry the trusted proxy appended decides, not the line the client sent first");
    assertInstanceOf(PolicyDecision.Denied.class, policyDecision.get(),
        "the proxy-reported address is outside 10.0.0.0/8");
    assertFalse(handlerRan.get(), "the forged in-network address must not open the route");
    assertTrue(statusLine.contains(" " + HttpStatus.FORBIDDEN.code() + " "), statusLine);
  }

  @Test
  @DisplayName("one merged line (nginx, Caddy) keeps working: the last entry wins")
  void mergedLine_lastEntryWins() throws Exception {
    AtomicReference<Optional<String>> resolved = new AtomicReference<>();
    startServer(exchange -> {
      resolved.set(RestClientAddress.resolve(
          new ExchangeRestRequest(exchange, HeaderMode.ALL_LINES_FIRST_LINE_MAP)));
      exchange.sendResponseHeaders(HttpStatus.NO_CONTENT.code(), -1);
    });

    rawRequest("X-Forwarded-For: " + FORGED_CLIENT_LINE + ", " + PROXY_LINE);

    assertEquals(Optional.of(PROXY_LINE), resolved.get());
  }

  // ── two Authorization lines over a real socket ───────────────────

  @Test
  @DisplayName("two Authorization lines: rejectDuplicates answers 400, neither filter nor handler runs")
  void twoAuthorizationLines_rejectedWith400() throws Exception {
    AtomicBoolean pipelineRan = new AtomicBoolean();
    startServer(exchange -> {
      ExchangeRestResponse response = new ExchangeRestResponse();
      if (!RestHeaderLines.rejectDuplicates(exchange.getRequestHeaders(), response)) {
        pipelineRan.set(true);
        response.status(HttpStatus.NO_CONTENT.code());
      }
      response.send(exchange);
    });

    String statusLine = rawRequest(
        "Authorization: Bearer token-of-the-victim",
        "Authorization: Bearer token-of-the-attacker");

    assertTrue(statusLine.contains(" " + HttpStatus.BAD_REQUEST.code() + " "), statusLine);
    assertFalse(pipelineRan.get(), "a request with two credentials must not reach the pipeline");
  }

  @Test
  @DisplayName("one Authorization line passes rejectDuplicates and yields its bearer token")
  void oneAuthorizationLine_passes() throws Exception {
    AtomicReference<Optional<String>> token = new AtomicReference<>();
    startServer(exchange -> {
      ExchangeRestResponse response = new ExchangeRestResponse();
      if (!RestHeaderLines.rejectDuplicates(exchange.getRequestHeaders(), response)) {
        token.set(new BearerTokenExtractor().extract(
            new ExchangeRestRequest(exchange, HeaderMode.ALL_LINES_FIRST_LINE_MAP)));
        response.status(HttpStatus.NO_CONTENT.code());
      }
      response.send(exchange);
    });

    String statusLine = rawRequest("Authorization: Bearer only-token");

    assertTrue(statusLine.contains(" " + HttpStatus.NO_CONTENT.code() + " "), statusLine);
    assertEquals(Optional.of("only-token"), token.get());
  }

  // ── helper and default-method contract, no socket ────────────────

  @Test
  @DisplayName("values(): every line in wire order, names case-insensitive, null-tolerant")
  void valuesReturnsEveryLine() {
    Map<String, List<String>> lines = new LinkedHashMap<>();
    lines.put("x-forwarded-for", List.of(FORGED_CLIENT_LINE, PROXY_LINE));
    lines.put("Accept", List.of("text/plain"));

    assertEquals(List.of(FORGED_CLIENT_LINE, PROXY_LINE), RestHeaderLines.values(lines, "X-Forwarded-For"));
    assertEquals(List.of(), RestHeaderLines.values(lines, "Authorization"));
    assertEquals(List.of(), RestHeaderLines.values(null, "Accept"));
    assertEquals(List.of(), RestHeaderLines.values(lines, null));
  }

  @Test
  @DisplayName("joined(): repeated lines are joined with \", \" (RFC 9110 §5.3), none is dropped")
  void joinedKeepsEveryLine() {
    Map<String, List<String>> lines = new LinkedHashMap<>();
    lines.put("X-Forwarded-For", List.of(FORGED_CLIENT_LINE, PROXY_LINE));
    lines.put("Accept", List.of("text/plain"));
    lines.put("Empty", List.of());

    Map<String, String> joined = RestHeaderLines.joined(lines);

    assertEquals(FORGED_CLIENT_LINE + ", " + PROXY_LINE, joined.get("X-Forwarded-For"));
    assertEquals("text/plain", joined.get("Accept"));
    assertFalse(joined.containsKey("Empty"));
    assertTrue(RestHeaderLines.joined(null).isEmpty());
  }

  @Test
  @DisplayName("repeatedSingleValueHeader(): Authorization, X-Api-Key and Cookie must not repeat; list headers may")
  void repeatedSingleValueHeaderIsFound() {
    assertEquals(Optional.of(RestHeaderLines.AUTHORIZATION), RestHeaderLines.repeatedSingleValueHeader(
        Map.of("authorization", List.of("Bearer a", "Bearer b"))));
    assertEquals(Optional.of(RestHeaderLines.X_API_KEY), RestHeaderLines.repeatedSingleValueHeader(
        Map.of("X-API-KEY", List.of("k1", "k2"))));
    assertEquals(Optional.of(RestHeaderLines.COOKIE), RestHeaderLines.repeatedSingleValueHeader(
        Map.of("Cookie", List.of("a=1", "b=2"))));
    assertEquals(Optional.empty(), RestHeaderLines.repeatedSingleValueHeader(
        Map.of("X-Forwarded-For", List.of(FORGED_CLIENT_LINE, PROXY_LINE),
            "Authorization", List.of("Bearer a"))));
    assertEquals(Optional.of("X-Tenant-Token"), RestHeaderLines.repeatedSingleValueHeader(
        Map.of("x-tenant-token", List.of("a", "b")), List.of("X-Tenant-Token")));
  }

  @Test
  @DisplayName("rejectDuplicates(request): 400 with a generic body through headerValues")
  void rejectDuplicatesOnRequest() {
    RestAuthorizationFilterTest.RecordingResponse response = new RestAuthorizationFilterTest.RecordingResponse();
    RestRequest twoCookieLines = new LinesRequest(Map.of("Cookie", List.of("a=1", "a=2")));

    assertTrue(RestHeaderLines.rejectDuplicates(twoCookieLines, response));
    assertEquals(HttpStatus.BAD_REQUEST.code(), response.status);
    assertEquals(RestHeaderLines.DUPLICATE_HEADER_BODY, response.body);

    RestAuthorizationFilterTest.RecordingResponse untouched = new RestAuthorizationFilterTest.RecordingResponse();
    assertFalse(RestHeaderLines.rejectDuplicates(
        new LinesRequest(Map.of("Cookie", List.of("a=1"))), untouched));
    assertEquals(HttpStatus.OK.code(), untouched.status);
  }

  @Test
  @DisplayName("BearerTokenExtractor: two Authorization lines yield no token (fail-closed backstop)")
  void bearerExtractorRefusesTwoAuthorizationLines() {
    RestRequest twoLines = new LinesRequest(
        Map.of("Authorization", List.of("Bearer first", "Bearer second")));
    RestRequest oneLine = new LinesRequest(Map.of("Authorization", List.of("Bearer first")));

    assertEquals(Optional.empty(), new BearerTokenExtractor().extract(twoLines));
    assertEquals(Optional.of("first"), new BearerTokenExtractor().extract(oneLine));
  }

  @Test
  @DisplayName("RestRequest.headerValues default: derived from headers(), case-insensitive, never null")
  void headerValuesDefaultDerivesFromHeaders() {
    RestRequest request = new RestAuthorizationFilterTest.SimpleRestRequest(
        "GET", "/x", Map.of("x-forwarded-for", FORGED_CLIENT_LINE + ", " + PROXY_LINE), Map.of());

    assertEquals(List.of(FORGED_CLIENT_LINE + ", " + PROXY_LINE), request.headerValues("X-Forwarded-For"));
    assertEquals(List.of(), request.headerValues("Authorization"));
    assertEquals(List.of(), request.headerValues(null));
  }

  // ── fixtures ─────────────────────────────────────────────────────

  static final class OfficeFixture {
    @RequiresPolicy(OFFICE_POLICY)
    void report() {
    }
  }

  /** How the test adapter exposes the header lines of the exchange. */
  private enum HeaderMode {
    /**
     * {@code headerValues} returns every line; {@code headers()} is the first-line map the
     * adapters shipped before 00.84.00 built. Only the multi-valued lookup can save this one.
     */
    ALL_LINES_FIRST_LINE_MAP,
    /** {@code headers()} is built with {@link RestHeaderLines#joined}; {@code headerValues} is the default. */
    JOINED_MAP_DEFAULT_VALUES
  }

  /** A {@link RestRequest} over a JDK {@link HttpExchange}, built with the helper under test. */
  private static final class ExchangeRestRequest implements RestRequest {
    private final HttpExchange exchange;
    private final HeaderMode mode;

    ExchangeRestRequest(HttpExchange exchange, HeaderMode mode) {
      this.exchange = exchange;
      this.mode = mode;
    }

    @Override
    public String method() {
      return exchange.getRequestMethod();
    }

    @Override
    public String path() {
      return exchange.getRequestURI().getPath();
    }

    @Override
    public Map<String, String> headers() {
      if (mode == HeaderMode.JOINED_MAP_DEFAULT_VALUES) {
        return RestHeaderLines.joined(exchange.getRequestHeaders());
      }
      Map<String, String> firstLines = new LinkedHashMap<>();
      exchange.getRequestHeaders().forEach((name, lines) -> {
        if (!lines.isEmpty()) {
          firstLines.put(name, lines.get(0));
        }
      });
      return firstLines;
    }

    @Override
    public List<String> headerValues(String name) {
      if (mode == HeaderMode.JOINED_MAP_DEFAULT_VALUES) {
        return RestRequest.super.headerValues(name);
      }
      return RestHeaderLines.values(exchange.getRequestHeaders(), name);
    }

    @Override
    public Map<String, String> queryParameters() {
      return Map.of();
    }

    @Override
    public Optional<String> remoteAddress() {
      InetSocketAddress remote = exchange.getRemoteAddress();
      return remote == null || remote.getAddress() == null
          ? Optional.empty() : Optional.of(remote.getAddress().getHostAddress());
    }
  }

  /** Buffers status and body, then writes them to the exchange. */
  private static final class ExchangeRestResponse implements RestResponse {
    private int status = HttpStatus.OK.code();
    private String body = "";

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body == null ? "" : body;
    }

    void send(HttpExchange exchange) throws IOException {
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      boolean noBody = status == HttpStatus.NO_CONTENT.code() || bytes.length == 0;
      exchange.sendResponseHeaders(status, noBody ? -1 : bytes.length);
      if (!noBody) {
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(bytes);
        }
      }
    }
  }

  /** A request that knows its header lines without any transport. */
  private record LinesRequest(Map<String, List<String>> lines) implements RestRequest {
    @Override
    public String method() {
      return "GET";
    }

    @Override
    public String path() {
      return "/x";
    }

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

  @FunctionalInterface
  private interface ExchangeLogic {
    void handle(HttpExchange exchange) throws Exception;
  }

  private void startServer(ExchangeLogic logic) throws IOException {
    server = HttpServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
    server.createContext("/", exchange -> {
      try (exchange) {
        logic.handle(exchange);
      } catch (IOException e) {
        throw e;
      } catch (Exception e) {
        throw new IOException(e);
      }
    });
    server.start();
  }

  /**
   * Sends one GET with exactly the given header lines, in this order, and
   * returns the status line of the answer.
   */
  private String rawRequest(String... headerLines) throws IOException {
    int port = server.getAddress().getPort();
    StringBuilder request = new StringBuilder("GET /api/report HTTP/1.1\r\n")
        .append("Host: ").append(LOOPBACK).append(':').append(port).append("\r\n");
    for (String line : headerLines) {
      request.append(line).append("\r\n");
    }
    request.append("Connection: close\r\n\r\n");
    try (Socket socket = new Socket(LOOPBACK, port)) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      InputStream in = socket.getInputStream();
      String response = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
      int lineEnd = response.indexOf("\r\n");
      return lineEnd < 0 ? response : response.substring(0, lineEnd);
    }
  }
}
