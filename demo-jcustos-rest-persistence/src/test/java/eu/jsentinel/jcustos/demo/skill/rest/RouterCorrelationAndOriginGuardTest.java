package eu.jsentinel.jcustos.demo.skill.rest;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.InMemoryBootstrapTokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.JCustosStorageProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.InMemoryUserDirectoryPersistence;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.PersistentUserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStorageFactory;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStoragePair;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The persistence demo's {@link Router} over the real JDK {@code HttpServer} on loopback,
 * audited into the real Eclipse-Store audit store: the login handler's {@code LoginSucceeded}
 * carries the request's correlation id (R5, JS-SEC-066),
 * and a {@link RestOriginGuard} installed for the process is the router's outermost filter
 * (CSRF, CWE-352). The demo itself installs no guard - its session is a bearer token.
 */
class RouterCorrelationAndOriginGuardTest {

  private static final String ADMIN = "corr-admin";
  private static final String ADMIN_PASSWORD = "Corr-admin-pass-2026";
  private static final String CSRF_USER = "erin-csrf";
  private static final String CSRF_PASSWORD = "Erin-csrf-pass-2026";

  @TempDir
  static Path storageDir;

  private static RestServer server;
  private static DemoHttp http;
  private static JCustosStoragePair storage;
  private static String ownOrigin;

  private final HttpClient client = HttpClient.newHttpClient();

  @BeforeAll
  static void startServer() throws Exception {
    TokenStore.INSTANCE.clear();
    AuthHandler.useLoginRateLimit(null);
    storage = JCustosStorageFactory.openAt(storageDir);
    JCustosStorageProvider.setPair(storage);
    UserDirectoryProvider.setDirectory(new PersistentUserDirectory(new InMemoryUserDirectoryPersistence()));
    AtomicReference<String> bootstrapToken = new AtomicReference<>();
    BootstrapWiring.setInstance(BootstrapWiring.create(
        new BootstrapConfiguration(BootstrapMode.TRANSIENT_CONSOLE, null,
            BootstrapConfiguration.DEFAULT_VALIDITY),
        new InMemoryBootstrapTokenStore(),
        (token, configuration) -> bootstrapToken.set(token.value())));
    server = RestServer.start(0);
    http = new DemoHttp(server.port());
    ownOrigin = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + server.port();
    DemoHttp.Response setup = http.post("/api/setup", "{\"token\":\"" + bootstrapToken.get()
        + "\",\"username\":\"" + ADMIN + "\",\"password\":\"" + ADMIN_PASSWORD + "\"}", null);
    assertEquals(201, setup.status(), setup.body());
    http.createUser(http.login(ADMIN, ADMIN_PASSWORD), CSRF_USER, CSRF_PASSWORD, "USER");
  }

  @AfterAll
  static void stopServer() {
    server.stop();
    TokenStore.INSTANCE.clear();
    UserDirectoryProvider.reset();
    BootstrapWiring.setInstance(null);
    JCustosStorageProvider.setPair(null);
    storage.close();
  }

  @AfterEach
  void removeGuard() {
    RestOriginGuard.reset();
  }

  @Test
  @DisplayName("R5: the login handler's LoginSucceeded carries a correlation id")
  void loginSucceeded_carriesTheCorrelationId() throws Exception {
    http.login(ADMIN, ADMIN_PASSWORD);

    List<AuditEnvelope> logins = envelopes(LoginSucceeded.class);
    assertFalse(logins.isEmpty());
    logins.forEach(envelope -> assertTrue(envelope.correlationId() != null, envelope.toString()));
  }

  @Test
  @DisplayName("CSRF: an installed guard refuses a cross-origin login with 403 before the login handler runs")
  void installedGuard_refusesACrossOriginLogin() throws Exception {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());

    HttpResponse<String> refused = client.send(HttpRequest.newBuilder(URI.create(ownOrigin + "/api/auth/login"))
        .header("Content-Type", "application/json")
        .header("Origin", "https://attacker.example")
        .header("Sec-Fetch-Site", "cross-site")
        .POST(HttpRequest.BodyPublishers.ofString(
            "{\"username\":\"" + CSRF_USER + "\",\"password\":\"" + CSRF_PASSWORD + "\"}"))
        .build(), HttpResponse.BodyHandlers.ofString());

    assertEquals(403, refused.statusCode());
    assertTrue(envelopes(LoginSucceeded.class).stream()
        .noneMatch(envelope -> CSRF_USER.equals(((LoginSucceeded) envelope.event()).username())),
        "the login handler must not run");
    assertTrue(envelopes(AccessDenied.class).stream()
        .anyMatch(envelope -> RestOriginGuard.REASON_ORIGIN_MISMATCH
            .equals(((AccessDenied) envelope.event()).reason()) && envelope.correlationId() != null));
    assertEquals(200, http.post("/api/auth/login", "{\"username\":\"" + CSRF_USER
        + "\",\"password\":\"" + CSRF_PASSWORD + "\"}", null).status(), "without Origin (curl) it passes");
  }

  private static List<AuditEnvelope> envelopes(Class<? extends AuditEvent> type) {
    return JCustosStorageProvider.framework().auditEventStore()
        .query(TenantId.DEFAULT, AuditQuery.all()).stream()
        .filter(envelope -> type.isInstance(envelope.event()))
        .toList();
  }
}
