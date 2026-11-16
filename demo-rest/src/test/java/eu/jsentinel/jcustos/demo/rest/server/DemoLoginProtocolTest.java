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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.demo.rest.cli.CliOperationClient;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRole;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import eu.jsentinel.jcustos.rest.HttpStatusDecisionMapper;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static com.svenruppert.dependencies.core.net.HttpStatus.SERVICE_UNAVAILABLE;
import static com.svenruppert.dependencies.core.net.HttpStatus.TOO_MANY_REQUESTS;
import static com.svenruppert.dependencies.core.net.HttpStatus.UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The login of the demo follows the login-attempt protocol (JS-SEC-123, JS-SEC-124,
 * JS-SEC-126) and renders its 401 through the published decision mapper (JS-SEC-086).
 * Real {@link DemoUserStore}, real {@link InMemoryLoginAttemptPolicy}, real PBKDF2 pipeline
 * and real KDF limiter; the only hand-written piece is a hashing service that delegates to
 * the real one and runs a hook in the middle of the verification, to make a lockout happen
 * while an attempt is in flight.
 */
@DisplayName("Demo REST login — attempt protocol, shed verification, 401 challenge")
class DemoLoginProtocolTest {

  private static final String CLIENT = "203.0.113.50";

  @BeforeEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("wrong password over HTTP: 401 with a Bearer challenge and a LoginFailed audit event")
  void wrongPasswordIsChallengedAndAudited() throws IOException, InterruptedException {
    DemoRestServer server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    try {
      CliOperationClient client = new CliOperationClient("http://localhost:" + server.port());
      HttpResponse<String> rejected = client.login("editor", "not-the-password");

      assertEquals(UNAUTHORIZED.code(), rejected.statusCode());
      assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
          rejected.headers().firstValue("WWW-Authenticate").orElse(null),
          "the 401 of a failed login must carry the Bearer challenge (JS-SEC-086)");

      HttpResponse<String> adminLogin = client.login("admin", "admin");
      String adminToken = String.valueOf(DemoJson.decodeObject(adminLogin.body()).get("token"));
      HttpResponse<String> audit = client.call(
          "GET", "/api/audit?type=LoginFailed", adminToken, null);
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> events =
          (List<Map<String, Object>>) DemoJson.decodeObject(audit.body()).get("events");
      assertTrue(events.stream().anyMatch(e -> "editor".equals(e.get("username"))),
          "the rejected password must be audited as LoginFailed: " + events);
    } finally {
      server.stop();
    }
  }

  @Test
  @DisplayName("a verification the KDF limiter shed is 503 + Retry-After, counts no failure and audits no LoginFailed")
  void shedVerificationIsUnavailableNotWrong() {
    KdfExecutionLimiter limiter =
        new SemaphoreKdfExecutionLimiter(new KdfResourceBudget(1, Duration.ofMillis(20)));
    DemoUserStore users = new DemoUserStore(PasswordHashingServices.defaults(fastPolicy(), limiter));
    users.create("shed-user", "correct horse", "Shed User", DemoRole.ROLE_VIEWER);
    // threshold 1: a counted failure locks the key, an attempt left in flight saturates it
    LoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(
        new LoginAttemptConfiguration(1, Duration.ofMinutes(5),
            Duration.ofMinutes(5), Duration.ofMinutes(10)),
        Clock.systemUTC(), null);
    DemoHandlers handlers = handlers(users, policy);

    try (KdfExecutionLimiter.Lease busy = limiter.acquire().orElseThrow()) {
      DemoHttpResponse shed = login(handlers, "shed-user", "correct horse");
      assertEquals(SERVICE_UNAVAILABLE.code(), shed.status(),
          "a shed verification is 'try again later', not a wrong password");
      assertTrue(shed.getHeaders().containsKey("Retry-After"));
      DemoHttpResponse shedUnknown = login(handlers, "nobody-at-all", "whatever");
      assertEquals(SERVICE_UNAVAILABLE.code(), shedUnknown.status(),
          "the dummy KDF for an unknown user is shed the same way");
    }

    assertTrue(events(LoginFailed.class, "shed-user").isEmpty(),
        "a shed verification must not be audited as LoginFailed");
    DemoHttpResponse after = login(handlers, "shed-user", "correct horse");
    assertEquals(OK.code(), after.status(),
        "the shed attempt must neither count as a failure nor stay in flight");
  }

  @Test
  @DisplayName("a lockout that sets in while the password is checked denies the login: 429, no token, LoginFailed")
  void lockoutDuringTheCheckDeniesTheLogin() {
    int threshold = 3;
    LoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(
        new LoginAttemptConfiguration(threshold, Duration.ofMinutes(5),
            Duration.ofMinutes(5), Duration.ofMinutes(10)),
        Clock.systemUTC(), null);
    LoginAttemptContext sameKey = LoginAttemptContext.now("racer", CLIENT, null);
    // two parallel guesses are in flight when the demo's own attempt is admitted
    policy.beforeAttempt(sameKey);
    policy.beforeAttempt(sameKey);

    // while the demo is still verifying the right password, the two guesses fail and a third
    // failure arrives from a guess whose reservation had lapsed: the key locks mid-check
    HookedHashingService hashing = new HookedHashingService(
        PasswordHashingServices.defaults(fastPolicy()));
    DemoUserStore users = new DemoUserStore(hashing);
    users.create("racer", "right password", "Racer", DemoRole.ROLE_VIEWER);
    hashing.onVerify(() -> {
      for (int i = 0; i < threshold; i++) {
        policy.recordFailure(sameKey);
      }
    });

    DemoHttpResponse response = login(handlers(users, policy), "racer", "right password");

    assertEquals(TOO_MANY_REQUESTS.code(), response.status(),
        "a correct password must not pass a lockout that set in during the check");
    assertTrue(response.getHeaders().containsKey("Retry-After"));
    assertFalse(response.getBody().contains("token"), "no token may be issued");
    assertTrue(events(LoginSucceeded.class, "racer").isEmpty(), "no LoginSucceeded");
    assertTrue(events(LoginFailed.class, "racer").stream()
            .map(LoginFailed.class::cast)
            .anyMatch(e -> e.reason().contains("Locked out while the attempt was in flight")),
        "the refused login must be audited as LoginFailed");
  }

  // ── Fixtures ───────────────────────────────────────────────────

  private static DemoHandlers handlers(DemoUserStore users, LoginAttemptPolicy policy) {
    DemoTokenStore tokens = new DemoTokenStore();
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, new DemoRolePermissionMapping());
    return new DemoHandlers(users, tokens, new DemoDocumentStore(), new DemoOperationRegistry(),
        resolver, policy, new InMemoryJCustosVersionStore(), null, null);
  }

  private static DemoHttpResponse login(DemoHandlers handlers, String username, String password) {
    DemoHttpRequest request = new DemoHttpRequest("POST", "/api/login", Map.of(), Map.of(),
        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}", CLIENT);
    DemoHttpResponse response = new DemoHttpResponse();
    handlers.login(request, response);
    return response;
  }

  private static List<AuditEvent> events(Class<? extends AuditEvent> type, String username) {
    return JCustosServiceResolver.securityAuditService().query(AuditQuery.all()).stream()
        .filter(type::isInstance)
        .filter(e -> e instanceof LoginFailed f ? username.equals(f.username())
            : e instanceof LoginSucceeded s && username.equals(s.username()))
        .toList();
  }

  private static PasswordHashPolicy fastPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Pbkdf2ParameterNames.ITERATIONS, "500");
    min.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "10000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  /** Delegates to a real pipeline and runs a hook before each password verification. */
  private static final class HookedHashingService implements PasswordHashingService {

    private final PasswordHashingService delegate;
    private Runnable hook = () -> { };

    private HookedHashingService(PasswordHashingService delegate) {
      this.delegate = delegate;
    }

    void onVerify(Runnable action) {
      this.hook = action;
    }

    @Override
    public PasswordHashResult hash(char[] password) {
      return delegate.hash(password);
    }

    @Override
    public CredentialVerificationResult verify(char[] password, String encodedHash) {
      hook.run();
      return delegate.verify(password, encodedHash);
    }

    @Override
    public RehashDecision needsRehash(String encodedHash) {
      return delegate.needsRehash(encodedHash);
    }

    @Override
    public CredentialVerificationResult verifyAgainstNothing(char[] password) {
      return delegate.verifyAgainstNothing(password);
    }
  }
}
