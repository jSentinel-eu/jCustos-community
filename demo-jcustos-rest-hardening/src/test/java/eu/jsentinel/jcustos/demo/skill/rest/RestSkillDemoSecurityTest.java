package eu.jsentinel.jcustos.demo.skill.rest;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.InMemoryBootstrapTokenStore;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.compromised.NoOpCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.MyRestSubjectResolver;
import eu.jsentinel.jcustos.demo.skill.rest.security.SessionStoreProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.JCustosStorageProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.InMemoryUserDirectoryPersistence;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.PersistentUserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.PasswordPreflight;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStorageFactory;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStoragePair;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests of the hardening-layer REST skill demo over the real JDK
 * {@code HttpServer} on loopback: the fixes for JS-SEC-132 (token bound to
 * a frozen user, duplicate route keys), JS-SEC-117 (no token outside the
 * login response), JS-SEC-131 (revoked session record), JS-SEC-113
 * (repeated credential header), JS-SEC-086 (Bearer challenge) and the
 * login protocol of JS-SEC-123/124/126.
 */
class RestSkillDemoSecurityTest {

  private static final String ADMIN = "root-admin";
  private static final String ADMIN_PASSWORD = "Root-admin-pass-2026";
  private static final String USER = "user";
  private static final String USER_PASSWORD = "User-pass-2026";

  @TempDir
  static Path storageDir;

  private static RestServer server;
  private static long adminId;
  private static int weakSetupStatus;
  private static String adminHashAfterSetup;
  private static DemoHttp http;
  private static PersistentUserDirectory directory;
  private static JCustosStoragePair storage;

  @BeforeAll
  static void startServer() throws Exception {
    TokenStore.INSTANCE.clear();
    AuthHandler.useLoginRateLimit(null);
    // No HaveIBeenPwned calls from tests; the local blocklist stays active.
    PasswordPreflight.useOnlineChecker(NoOpCompromisedPasswordChecker.INSTANCE);
    storage = JCustosStorageFactory.openAt(storageDir);
    JCustosStorageProvider.setPair(storage);
    directory = new PersistentUserDirectory(new InMemoryUserDirectoryPersistence());
    UserDirectoryProvider.setDirectory(directory);
    AtomicReference<String> bootstrapToken = new AtomicReference<>();
    BootstrapWiring.setInstance(BootstrapWiring.create(
        new BootstrapConfiguration(BootstrapMode.TRANSIENT_CONSOLE, null,
            BootstrapConfiguration.DEFAULT_VALIDITY),
        new InMemoryBootstrapTokenStore(),
        (token, configuration) -> bootstrapToken.set(token.value())));
    server = RestServer.start(0);
    http = new DemoHttp(server.port());

    assertEquals(503, http.get("/api/whoami", null).status(), "guarded until the first admin exists");
    weakSetupStatus = http.post("/api/setup", "{\"token\":\"" + bootstrapToken.get()
        + "\",\"username\":\"" + ADMIN + "\",\"password\":\"administrator\"}", null).status();
    DemoHttp.Response setup = http.post("/api/setup", "{\"token\":\"" + bootstrapToken.get()
        + "\",\"username\":\"" + ADMIN + "\",\"password\":\"" + ADMIN_PASSWORD + "\"}", null);
    assertEquals(201, setup.status(), setup.body());
    // Before the first login: a login would replace an outdated hash.
    adminHashAfterSetup = directory.storedPasswordHash(ADMIN).orElseThrow();
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    adminId = Long.parseLong(http.get("/api/whoami", admin).body().replaceAll(".*\"id\":\"(\\d+)\".*", "$1"));
    http.createUser(admin, USER, USER_PASSWORD, "USER");
  }

  @AfterAll
  static void stopServer() {
    server.stop();
    TokenStore.INSTANCE.clear();
    UserDirectoryProvider.reset();
    BootstrapWiring.setInstance(null);
    JCustosStorageProvider.setPair(null);
    PasswordPreflight.useOnlineChecker(null);
    storage.close();
  }

  @Test
  @DisplayName("JS-SEC-134: the first administrator is hashed with Argon2id and can log in")
  void firstAdministratorIsArgon2id() throws Exception {
    assertTrue(adminHashAfterSetup.contains("alg=Argon2id"), "first administrator");
    assertEquals(200, http.get("/api/whoami", http.login(ADMIN, ADMIN_PASSWORD)).status());
  }

  @Test
  @DisplayName("JS-SEC-134: a newly created user is hashed with Argon2id")
  void newUserIsArgon2id() {
    assertTrue(directory.storedPasswordHash(USER).orElseThrow().contains("alg=Argon2id"), "new user");
  }

  @Test
  @DisplayName("JS-SEC-134: the preflight refuses a known-bad first-administrator password")
  void weakFirstAdministratorPasswordIsRefused() {
    assertEquals(422, weakSetupStatus);
  }

  @Test
  @DisplayName("JS-SEC-132: a role change drifts the open token; the version filter refuses it")
  void roleChangeDriftsTheOpenToken() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    long kim = http.createUser(admin, "kim-drift", "Kim-pass-2026", "USER");
    String kimToken = http.login("kim-drift", "Kim-pass-2026");
    assertEquals(200, http.get("/api/whoami", kimToken).status());
    assertEquals(200, http.send("POST", "/api/users/" + kim + "/roles/ADMIN", admin, null).status());
    DemoHttp.Response stale = http.get("/api/whoami", kimToken);
    assertEquals(401, stale.status());
    assertEquals("SessionStale", stale.header("WWW-Authenticate"));
  }

  @Test
  @DisplayName("Hardening: a known-bad password is refused when a user is created")
  void knownBadPasswordIsRefusedOnCreate() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    DemoHttp.Response refused = http.post("/api/users",
        "{\"username\":\"lea-weak\",\"password\":\"password123\",\"role\":\"USER\"}", admin);
    assertEquals(422, refused.status());
  }

  @Test
  @DisplayName("JS-SEC-132: revoking a role takes effect for an open token; the user is kept")
  void roleRevocationTakesEffectForAnOpenToken() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    long carol = http.createUser(admin, "carol-role", "Carol-pass-2026", "ADMIN");
    String carolToken = http.login("carol-role", "Carol-pass-2026");
    assertEquals(200, http.get("/api/audit", carolToken).status());

    DemoHttp.Response revoke = http.send("DELETE", "/api/users/" + carol + "/roles/ADMIN", admin, null);
    assertEquals(200, revoke.status(), revoke.body());

    assertTrue(http.get("/api/users", admin).body().contains("\"id\":" + carol),
        "revoking a role must not delete the user");
    DemoHttp.Response denied = http.get("/api/audit", carolToken);
    assertTrue(denied.status() == 403 || denied.status() == 401,
        "the open token must lose the revoked role, got " + denied.status());
  }

  @Test
  @DisplayName("JS-SEC-132: assigning a role reaches assignRole, not create")
  void roleAssignmentReachesItsHandler() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    long dora = http.createUser(admin, "dora-assign", "Dora-pass-2026", "USER");
    DemoHttp.Response assign = http.send("POST", "/api/users/" + dora + "/roles/ADMIN", admin, null);
    assertEquals(200, assign.status(), assign.body());
    String users = http.get("/api/users", admin).body();
    assertTrue(users.contains("\"id\":" + dora + ",\"name\":\"dora-assign\",\"roles\":[\"ADMIN\",\"USER\"]"),
        users);
  }

  @Test
  @DisplayName("JS-SEC-132: a deleted user's token is refused with a Bearer challenge")
  void deletedUserTokenIsRefused() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    long eve = http.createUser(admin, "eve-delete", "Eve-pass-2026", "USER");
    String eveToken = http.login("eve-delete", "Eve-pass-2026");
    assertEquals(200, http.get("/api/whoami", eveToken).status());

    assertEquals(200, http.send("DELETE", "/api/users/" + eve, admin, null).status());
    DemoHttp.Response refused = http.get("/api/whoami", eveToken);
    assertEquals(401, refused.status());
    assertEquals("Bearer", refused.header("WWW-Authenticate"));
  }

  @Test
  @DisplayName("JS-SEC-132: a path with extra segments matches no route and deletes nothing")
  void extraSegmentsDeleteNothing() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    long fred = http.createUser(admin, "fred-extra", "Fred-pass-2026", "USER");
    assertEquals(404, http.send("DELETE", "/api/users/" + fred + "/extra", admin, null).status());
    assertTrue(http.get("/api/users", admin).body().contains("\"id\":" + fred));
  }

  @Test
  @DisplayName("JS-SEC-132: the last administrator can be neither deleted nor demoted")
  void lastAdministratorIsKept() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    assertEquals(409, http.send("DELETE", "/api/users/" + adminId, admin, null).status());
    assertEquals(409, http.send("DELETE", "/api/users/" + adminId + "/roles/ADMIN", admin, null).status());
  }

  @Test
  @DisplayName("JS-SEC-132: a route table with a duplicate key fails at start-up")
  void duplicateRouteKeyFailsAtStartUp() {
    Router.Builder builder = new Router.Builder()
        .add("DELETE", "/api/users/{id}", eu.jsentinel.jcustos.demo.skill.rest.handlers.UsersHandler.class, "delete")
        .add("DELETE", "/api/users/{userId}", eu.jsentinel.jcustos.demo.skill.rest.handlers.UsersHandler.class, "revokeRole");
    IllegalStateException failure = assertThrows(IllegalStateException.class, builder::build);
    assertTrue(failure.getMessage().contains("DELETE /api/users/{}"), failure.getMessage());
    assertFalse(RestServer.routes().isEmpty(), "the shipped route table has no duplicate");
  }

  @Test
  @DisplayName("JS-SEC-132: a token past its lifetime is refused")
  void expiredTokenIsRefused() throws Exception {
    TokenStore.INSTANCE.useClock(Clock.offset(Clock.systemUTC(), Duration.ofHours(-13)));
    String stale;
    try {
      stale = http.login(USER, USER_PASSWORD);
    } finally {
      TokenStore.INSTANCE.useClock(Clock.systemUTC());
    }
    assertEquals(401, http.get("/api/whoami", stale).status());
  }

  @Test
  @DisplayName("JS-SEC-117: sessions and audit name a session by reference, never by token")
  void noTokenLeavesTheLoginResponse() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    String reference = SessionRef.of(admin);
    DemoHttp.Response sessions = http.get("/api/sessions", admin);
    assertEquals(200, sessions.status());
    assertFalse(sessions.body().contains(admin), "GET /api/sessions must not return tokens");
    assertTrue(sessions.body().contains(reference), sessions.body());
    DemoHttp.Response audit = http.get("/api/audit", admin);
    assertFalse(audit.body().contains(admin), "GET /api/audit must not return tokens");
    assertTrue(audit.body().contains(reference), "the login is audited under its reference");
    assertTrue(auditEvents().stream()
        .anyMatch(e -> e instanceof LoginSucceeded s && reference.equals(s.sessionId())));
  }

  @Test
  @DisplayName("JS-SEC-117: sessions are revoked by reference; a token in the URL is refused")
  void sessionsAreRevokedByReference() throws Exception {
    String admin = http.login(ADMIN, ADMIN_PASSWORD);
    String user = http.login(USER, USER_PASSWORD);
    assertEquals(400, http.send("DELETE", "/api/sessions/" + user, admin, null).status());
    assertEquals(200, http.get("/api/whoami", user).status(), "a token in the URL revokes nothing");
    assertEquals(200, http.send("DELETE", "/api/sessions/" + SessionRef.of(user), admin, null).status());
    assertEquals(401, http.get("/api/whoami", user).status());
  }

  @Test
  @DisplayName("JS-SEC-131: a session whose record was revoked in the store gets 401 on its next request")
  void revokedRecordEndsTheSession() throws Exception {
    String user = http.login(USER, USER_PASSWORD);
    assertEquals(200, http.get("/api/whoami", user).status());
    SessionStore store = SessionStoreProvider.sessionStore();
    SessionId id = SessionId.of(SessionRef.of(user));
    SessionRecord record = store.findById(id).orElseThrow();
    // Revoked by another node or a tool: the local token store still knows the token.
    store.save(record.withStatus(SessionStatus.REVOKED));

    DemoHttp.Response refused = http.get("/api/whoami", user);
    assertEquals(401, refused.status());
    assertEquals("Bearer", refused.header("WWW-Authenticate"));
    assertTrue(auditEvents().stream().anyMatch(e -> e instanceof SessionInvalidated s
        && id.value().equals(s.sessionId())));
  }

  @Test
  @DisplayName("JS-SEC-113: two Authorization lines are refused with 400 before any handler runs")
  void repeatedAuthorizationHeaderIsRefused() throws Exception {
    String user = http.login(USER, USER_PASSWORD);
    String raw = http.raw("POST /api/auth/logout HTTP/1.1\r\n"
        + "Host: 127.0.0.1\r\n"
        + "Authorization: Bearer " + user + "\r\n"
        + "Authorization: Bearer forged\r\n"
        + "Content-Length: 0\r\n"
        + "Connection: close\r\n\r\n");
    assertTrue(raw.startsWith("HTTP/1.1 400"), raw);
    assertEquals(200, http.get("/api/whoami", user).status(), "the logout handler must not have run");
  }

  @Test
  @DisplayName("JS-SEC-114: a restriction on the handler class reaches an inherited handler method")
  void classRestrictionReachesInheritedHandler() throws Exception {
    List<Router.Route> probe = new Router.Builder()
        .add("GET", "/api/probe", ProbeHandlers.AdminProbe.class, "probe")
        .build();
    com.sun.net.httpserver.HttpServer probeServer = com.sun.net.httpserver.HttpServer.create(
        new java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), 0), 0);
    probeServer.createContext("/api", new Router(new MyRestSubjectResolver(), probe));
    probeServer.start();
    try {
      DemoHttp probeHttp = new DemoHttp(probeServer.getAddress().getPort());
      String user = http.login(USER, USER_PASSWORD);
      String admin = http.login(ADMIN, ADMIN_PASSWORD);
      assertEquals(403, probeHttp.get("/api/probe", user).status());
      assertEquals(200, probeHttp.get("/api/probe", admin).status());
    } finally {
      probeServer.stop(0);
    }
  }

  @Test
  @DisplayName("JS-SEC-086: a failed login is a 401 with a Bearer challenge and a LoginFailed event")
  void failedLoginIsChallengedAndAudited() throws Exception {
    DemoHttp.Response failed = http.post("/api/auth/login",
        "{\"username\":\"" + USER + "\",\"password\":\"wrong\"}", null);
    assertEquals(401, failed.status());
    assertEquals("Bearer", failed.header("WWW-Authenticate"));
    assertTrue(auditEvents().stream().anyMatch(e -> e instanceof LoginFailed f
        && USER.equals(f.username())));
  }

  @Test
  @DisplayName("JS-SEC-124: repeated failures lock the key out with 429")
  void repeatedFailuresLockOut() throws Exception {
    int last = 0;
    for (int i = 0; i < 6; i++) {
      last = http.post("/api/auth/login",
          "{\"username\":\"nobody-lockout\",\"password\":\"guess-" + i + "\"}", null).status();
    }
    assertEquals(429, last);
  }

  @Test
  @DisplayName("JS-SEC-126: a shed verification is 503 and counts as no failed attempt")
  void shedVerificationIsTryAgainLater() throws Exception {
    KdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    PersistentUserDirectory shedding = new PersistentUserDirectory(new InMemoryUserDirectoryPersistence(),
        PasswordHashingServices.defaults(Pbkdf2Defaults.referencePolicy(), limiter));
    shedding.addUser("judy-shed", "Judy-pass-2026",
        new User(77L, "Judy", EnumSet.of(AuthorizationRole.USER)));
    UserDirectoryProvider.setDirectory(shedding);
    try {
      String body = "{\"username\":\"judy-shed\",\"password\":\"Judy-pass-2026\"}";
      KdfExecutionLimiter.Lease held = limiter.acquire().orElseThrow();
      try {
        for (int i = 0; i < 6; i++) {
          DemoHttp.Response shed = http.post("/api/auth/login", body, null);
          assertEquals(503, shed.status(), shed.body());
          assertTrue(shed.header("Retry-After") != null);
        }
      } finally {
        held.close();
      }
      // Six shed attempts counted as failures would have locked the key (threshold 5).
      assertEquals(200, http.post("/api/auth/login", body, null).status());
    } finally {
      UserDirectoryProvider.setDirectory(directory);
    }
  }

  @Test
  @DisplayName("JS-SEC-063: a credential check the gate defers is 429 with Retry-After and counts nothing")
  void deferredCredentialCheckIsTooManyRequests() throws Exception {
    AuthHandler.useLoginRateLimit(null);   // a fresh per-address limit: the 429 must be the gate's
    LoginAttemptPolicy previous = JCustosServiceResolver.loginAttemptPolicy();
    InMemoryLoginAttemptPolicy gated = new InMemoryLoginAttemptPolicy(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(1)
        .withGateWait(Duration.ZERO)
        .withGateRetryAfter(Duration.ofMillis(2500)), Clock.systemUTC(), null);
    JCustosServiceResolver.setLoginAttemptPolicy(gated);
    try {
      String body = "{\"username\":\"" + USER + "\",\"password\":\"" + USER_PASSWORD + "\"}";
      CredentialCheckGate.Admission.Entered busy =
          (CredentialCheckGate.Admission.Entered) gated.credentialCheckGate().enter();
      try {
        for (int i = 0; i < 6; i++) {
          DemoHttp.Response deferred = http.post("/api/auth/login", body, null);
          assertEquals(429, deferred.status(), deferred.body());
          assertEquals("3", deferred.header("Retry-After"), "2.5 s rounds up to 3 s");
        }
      } finally {
        busy.close();
      }
      // Six deferrals counted as failures, or left in flight, would have locked the key.
      assertEquals(200, http.post("/api/auth/login", body, null).status());
      assertEquals(0, gated.credentialCheckGate().inUse());
    } finally {
      JCustosServiceResolver.setLoginAttemptPolicy(previous);
    }
  }

  @Test
  @DisplayName("JS-SEC-137: the server listens on loopback only")
  void listensOnLoopbackOnly() {
    assertTrue(server.address().getAddress().isLoopbackAddress(), server.address().toString());
  }

  private static List<AuditEvent> auditEvents() {
    return JCustosServiceResolver.securityAuditService().query(AuditQuery.all());
  }
}
