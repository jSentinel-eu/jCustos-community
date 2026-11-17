package eu.jsentinel.jcustos.demo.skill.rest;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.MyRestSubjectResolver;
import eu.jsentinel.jcustos.demo.skill.rest.security.SessionStoreProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests of the layer-1 REST skill demo over the real JDK
 * {@code HttpServer} on loopback: the fixes for JS-SEC-132 (token bound to
 * a frozen user, duplicate route keys), JS-SEC-117 (no token outside the
 * login response), JS-SEC-131 (revoked session record), JS-SEC-113
 * (repeated credential header), JS-SEC-086 (Bearer challenge) and the
 * login protocol of JS-SEC-123/124/126.
 */
class RestSkillDemoSecurityTest {

  private static final String ADMIN = "admin";
  private static final String ADMIN_PASSWORD = "admin";
  private static final String USER = "user";
  private static final String USER_PASSWORD = "user";

  private static RestServer server;
  private static long adminId;
  private static DemoHttp http;
  private static InMemoryUserDirectory directory;

  @BeforeAll
  static void startServer() throws Exception {
    TokenStore.INSTANCE.clear();
    AuthHandler.useLoginRateLimit(null);
    directory = new InMemoryUserDirectory();
    UserDirectoryProvider.setDirectory(directory);
    server = RestServer.start(0);
    directory.seedInsecureDemoAccounts();
    http = new DemoHttp(server.port());
    adminId = 1L;
  }

  @AfterAll
  static void stopServer() {
    server.stop();
    TokenStore.INSTANCE.clear();
    UserDirectoryProvider.reset();
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
  @DisplayName("XR09-6: a credential check that throws is a failed attempt - 401 until the threshold, then 429")
  void throwingCheckIsAFailedAttempt() throws Exception {
    UserDirectory previous = UserDirectoryProvider.directory();
    UserDirectoryProvider.setDirectory(new BreakingUserDirectory("kim-breaks", previous));
    try {
      String body = "{\"username\":\"kim-breaks\",\"password\":\"any-guess\"}";
      for (int i = 0; i < 5; i++) {
        DemoHttp.Response failed = http.post("/api/auth/login", body, null);
        assertEquals(401, failed.status(), "attempt " + (i + 1) + ": " + failed.body());
        assertEquals("Bearer", failed.header("WWW-Authenticate"));
      }
      assertEquals(429, http.post("/api/auth/login", body, null).status(),
          "the throwing checks were counted: the key is locked");
      assertTrue(auditEvents().stream().anyMatch(e -> e instanceof LoginFailed f
          && "kim-breaks".equals(f.username())
          && AuthHandler.CHECK_FAILED_REASON.equals(f.reason())));
    } finally {
      UserDirectoryProvider.setDirectory(previous);
    }
  }

  @Test
  @DisplayName("JS-SEC-126: a shed verification is 503 and counts as no failed attempt")
  void shedVerificationIsTryAgainLater() throws Exception {
    KdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    InMemoryUserDirectory shedding = new InMemoryUserDirectory(
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
  @DisplayName("JS-SEC-137: without the development switch the directory has no fixed-password accounts")
  void noSeedAccountsByDefault() {
    assertFalse(InMemoryUserDirectory.insecureSeedAccountsRequested());
    UserDirectoryProvider.reset();
    try {
      assertEquals(0L, UserDirectoryProvider.directory().all().count());
    } finally {
      UserDirectoryProvider.setDirectory(directory);
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
