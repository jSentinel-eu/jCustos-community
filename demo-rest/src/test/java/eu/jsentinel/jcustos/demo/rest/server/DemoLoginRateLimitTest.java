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

import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicy;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitStore;
import eu.jsentinel.jcustos.ratelimiting.RateLimitDecision;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the V00.70 Phase-7c per-IP login rate-limit wiring
 * inside {@link DemoHandlers#login}. Drives the handler directly
 * against synthetic {@link DemoHttpRequest} / {@link DemoHttpResponse}
 * pairs so the test owns the rate-limit store and can assert the
 * exact boundary (limit + 1) without timing flakiness.
 */
@DisplayName("DemoHandlers.login — Phase-7c per-IP rate limit")
class DemoLoginRateLimitTest {

  private static final int LIMIT = 3;
  private static final Duration WINDOW = Duration.ofMinutes(1);
  private static final String IP = "10.0.0.42";

  private RateLimitPolicy policy;
  private DemoHandlers handlers;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosAuditService audit = JCustosServiceResolver.securityAuditService();
    DemoTokenStore tokens = new DemoTokenStore();
    DemoUserStore users = new DemoUserStore(
        PasswordHashingServices.defaults(), false);
    DemoDocumentStore documents = new DemoDocumentStore();
    DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, mapping);
    DemoOperationRegistry registry = new DemoOperationRegistry();
    policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), audit, LIMIT, WINDOW);
    handlers = new DemoHandlers(
        users, tokens, documents, registry, resolver,
        NoopLoginAttemptPolicy.INSTANCE,
        new InMemoryJCustosVersionStore(),
        null,
        policy);
  }

  @Test
  @DisplayName("LIMIT requests pass through, the LIMIT+1th yields 429 + Retry-After")
  void thresholdEnforcedAtLimitPlusOne() {
    for (int i = 0; i < LIMIT; i++) {
      DemoHttpResponse response = runLogin("admin", "wrong-password");
      assertEquals(UNAUTHORIZED.code(), response.status(),
          "attempt #" + (i + 1) + " must reach the credential check (401 for wrong password)");
    }

    DemoHttpResponse throttled = runLogin("admin", "wrong-password");
    assertEquals(TOO_MANY_REQUESTS.code(), throttled.status(),
        "attempt LIMIT+1 must be refused with 429 Too Many Requests");
    assertTrue(throttled.getHeaders().containsKey("Retry-After"),
        "throttled response must advertise Retry-After");
  }

  @Test
  @DisplayName("Allowed decisions surface the configured limit + window")
  void allowedDecisionShape() {
    RateLimitKey key = new RateLimitKey(TenantId.DEFAULT, "login:ip:" + IP);
    RateLimitDecision decision = policy.tryAcquire(key);
    RateLimitDecision.Allowed allowed = assertInstanceOf(
        RateLimitDecision.Allowed.class, decision);
    assertEquals(LIMIT, allowed.limit());
    assertEquals(WINDOW, allowed.window());
  }

  private DemoHttpResponse runLogin(String username, String password) {
    DemoHttpRequest req = new DemoHttpRequest(
        "POST", "/api/login",
        Map.of(),
        Map.of(),
        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}",
        IP);
    DemoHttpResponse res = new DemoHttpResponse();
    handlers.login(req, res);
    return res;
  }
}
