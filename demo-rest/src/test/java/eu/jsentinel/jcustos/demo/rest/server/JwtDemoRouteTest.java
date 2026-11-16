package eu.jsentinel.jcustos.demo.rest.server;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("demo-rest /jwt/demo — end-to-end JWT validation against a stub IDP (no mocks)")
class JwtDemoRouteTest {

  private static final Instant NOW = Instant.parse("2026-06-25T12:00:00Z");

  private DemoRestServer server;
  private JwtIssuerStub stub;
  private String base;
  private final HttpClient http = HttpClient.newHttpClient();

  @BeforeEach
  void start() throws Exception {
    stub = new JwtIssuerStub();
    // wire the stub's validator the way a .jwt(...) bootstrap would install it
    JCustosServiceResolver.setJwtValidator(stub.validator(NOW));
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    base = "http://127.0.0.1:" + server.port();
  }

  @AfterEach
  void stop() {
    server.stop();
    JCustosServiceResolver.setJwtValidator(null);
  }

  private HttpResponse<String> postJwtDemo(String bearer) throws Exception {
    HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + DemoEndpoints.JWT_DEMO))
        .POST(HttpRequest.BodyPublishers.noBody());
    if (bearer != null) {
      b.header("Authorization", "Bearer " + bearer);
    }
    return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
  }

  @Test
  @DisplayName("a valid stub-issued token is accepted and the subject is returned")
  void validTokenAccepted() throws Exception {
    HttpResponse<String> response = postJwtDemo(stub.issue("alice", NOW));
    assertEquals(HttpStatus.OK.code(), response.statusCode());
    assertTrue(response.body().contains("alice"), "the subject is echoed: " + response.body());
    assertTrue(response.body().contains("RS256"));
  }

  @Test
  @DisplayName("a tampered token is rejected with 401")
  void tamperedTokenRejected() throws Exception {
    String token = stub.issue("alice", NOW);
    // flip the FIRST signature char so the RS256 signature no longer verifies.
    // (The last base64url char of a 256-byte signature carries only non-significant
    // padding bits, so flipping it leaves the decoded signature bytes unchanged ~1/4
    // of the time — a flaky false-200. The first char's six bits are all significant.)
    int sigStart = token.lastIndexOf('.') + 1;
    char first = token.charAt(sigStart);
    String tampered = token.substring(0, sigStart)
        + (first == 'A' ? 'B' : 'A')
        + token.substring(sigStart + 1);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), postJwtDemo(tampered).statusCode());
  }

  @Test
  @DisplayName("a request without a bearer token is rejected with 401")
  void noBearerRejected() throws Exception {
    assertEquals(HttpStatus.UNAUTHORIZED.code(), postJwtDemo(null).statusCode());
  }
}
