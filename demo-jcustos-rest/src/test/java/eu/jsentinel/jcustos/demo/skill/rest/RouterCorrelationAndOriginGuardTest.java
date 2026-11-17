package eu.jsentinel.jcustos.demo.skill.rest;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The demo's {@link Router} over the real JDK {@code HttpServer} on loopback: the whole dispatch
 * runs in one audit correlation scope (R5, JS-SEC-066), so the login handler's own audit events
 * carry the request's id; and a {@link RestOriginGuard} installed for the process is the
 * router's outermost filter (CSRF, CWE-352). The demo itself installs no guard - its session is
 * a bearer token - so the test installs one, as an application with a cookie session would.
 */
class RouterCorrelationAndOriginGuardTest {

  private static final String ADMIN = "admin";
  private static final String ADMIN_PASSWORD = "admin";
  private static final String LOGIN_BODY =
      "{\"username\":\"" + ADMIN + "\",\"password\":\"" + ADMIN_PASSWORD + "\"}";

  private static RestServer server;
  private static String ownOrigin;
  private static DemoHttp http;

  private final HttpClient client = HttpClient.newHttpClient();
  private final List<Recorded> recorded = new CopyOnWriteArrayList<>();
  private JCustosAuditService original;

  @BeforeAll
  static void startServer() throws Exception {
    TokenStore.INSTANCE.clear();
    AuthHandler.useLoginRateLimit(null);
    InMemoryUserDirectory directory = new InMemoryUserDirectory();
    UserDirectoryProvider.setDirectory(directory);
    server = RestServer.start(0);
    directory.seedInsecureDemoAccounts();
    http = new DemoHttp(server.port());
    ownOrigin = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + server.port();
  }

  @AfterAll
  static void stopServer() {
    server.stop();
    TokenStore.INSTANCE.clear();
    UserDirectoryProvider.reset();
  }

  /** Records, next to every event the handlers publish, the correlation id current at that moment. */
  @BeforeEach
  void recordAudit() {
    original = JCustosServiceResolver.securityAuditService();
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        recorded.add(new Recorded(event, AuditCorrelation.current()));
        original.publish(event);
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return original.query(query);
      }
    });
  }

  @AfterEach
  void restore() {
    JCustosServiceResolver.setJCustosAuditService(original);
    RestOriginGuard.reset();
  }

  @Test
  @DisplayName("R5: the login's and the logout's own audit events carry a correlation id")
  void loginAndLogoutAudit_carryTheCorrelationId() throws Exception {
    String token = http.login(ADMIN, ADMIN_PASSWORD);
    http.post("/api/auth/logout", null, token);

    Recorded login = single(LoginSucceeded.class);
    Recorded logout = single(LogoutPerformed.class);
    assertTrue(login.correlationId().isPresent(), "LoginSucceeded was audited outside a scope");
    assertTrue(logout.correlationId().isPresent(), "LogoutPerformed was audited outside a scope");
    assertEquals(36, login.correlationId().get().length(), "a server-side UUID per request");
    assertNotEquals(login.correlationId(), logout.correlationId(), "one id per request");
  }

  @Test
  @DisplayName("CSRF: an installed guard refuses a cross-origin login with 403 before the login handler runs")
  void installedGuard_refusesACrossOriginLogin() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());

    HttpResponse<String> refused = post("/api/auth/login", Map.of(
        "Origin", "https://attacker.example", "Sec-Fetch-Site", "cross-site",
        "Cookie", "APP_SESSION=1f2e"));

    assertEquals(403, refused.statusCode());
    assertTrue(recorded.stream().noneMatch(r -> r.event() instanceof LoginSucceeded
        || r.event() instanceof LoginFailed), "the login handler must not run: " + recorded);
    Recorded denied = recorded.stream()
        .filter(r -> r.event() instanceof AccessDenied d
            && RestOriginGuard.REASON_ORIGIN_MISMATCH.equals(d.reason()))
        .findFirst().orElseThrow(() -> new AssertionError("no csrf audit event: " + recorded));
    assertTrue(denied.correlationId().isPresent());
  }

  @Test
  @DisplayName("CSRF: with the guard installed, a same-origin login, a login without Origin and a cross-origin GET pass")
  void installedGuard_letsTheOwnOriginAndNonBrowsersThrough() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());

    assertEquals(200, post("/api/auth/login", Map.of("Origin", ownOrigin,
        "Sec-Fetch-Site", "same-origin")).statusCode());
    String token = http.login(ADMIN, ADMIN_PASSWORD);
    assertNotNull(token, "a client without Origin (curl) logs in");
    HttpResponse<String> whoami = client.send(HttpRequest.newBuilder(URI.create(ownOrigin + "/api/whoami"))
        .header("Authorization", "Bearer " + token)
        .header("Origin", "https://attacker.example")
        .header("Sec-Fetch-Site", "cross-site")
        .GET().build(), HttpResponse.BodyHandlers.ofString());
    assertEquals(200, whoami.statusCode(), "a GET is not checked");
  }

  private HttpResponse<String> post(String path, Map<String, String> headers) throws Exception {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(ownOrigin + path))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(LOGIN_BODY));
    headers.forEach(builder::header);
    return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
  }

  private Recorded single(Class<? extends AuditEvent> type) {
    List<Recorded> matching = recorded.stream().filter(r -> type.isInstance(r.event())).toList();
    assertEquals(1, matching.size(), type.getSimpleName() + ": " + recorded);
    return matching.getFirst();
  }

  private record Recorded(AuditEvent event, Optional<String> correlationId) {
  }
}
