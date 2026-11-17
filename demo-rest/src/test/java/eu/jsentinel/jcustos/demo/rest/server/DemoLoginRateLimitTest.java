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
import eu.jsentinel.jcustos.ratelimiting.RateLimitEscalation;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;
import eu.jsentinel.jcustos.rest.RestThrottleResponses;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
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
  /** Password of the seeded demo administrator ({@code InsecureSeed}). */
  private static final String ADMIN_PASSWORD = "admin";

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private RateLimitPolicy policy;
  private DemoHandlers handlers;
  private JCustosAuditService audit;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    audit = JCustosServiceResolver.securityAuditService();
    policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), audit, LIMIT, WINDOW);
    handlers = handlers(policy);
  }

  private static DemoHandlers handlers(RateLimitPolicy loginRateLimit) {
    DemoTokenStore tokens = new DemoTokenStore();
    DemoUserStore users = new DemoUserStore(
        PasswordHashingServices.defaults(),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);
    DemoDocumentStore documents = new DemoDocumentStore();
    DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, mapping);
    DemoOperationRegistry registry = new DemoOperationRegistry();
    return new DemoHandlers(
        users, tokens, documents, registry, resolver,
        NoopLoginAttemptPolicy.INSTANCE,
        new InMemoryJCustosVersionStore(),
        null,
        loginRateLimit);
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
  @DisplayName("Retry-After is the time until the oldest attempt leaves the window, rounded up - not the window")
  void retryAfterFollowsTheOldestAttempt() {
    MutableClock clock = new MutableClock(T0);
    handlers = handlers(new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), audit, LIMIT, WINDOW, clock));
    for (Instant at : new Instant[] {T0, T0.plusSeconds(10), T0.plusSeconds(20)}) {
      clock.set(at);
      assertEquals(UNAUTHORIZED.code(), runLogin("admin", "wrong-password").status());
    }
    clock.set(T0.plusMillis(30_500));
    DemoHttpResponse throttled = runLogin("admin", "wrong-password");
    assertEquals(TOO_MANY_REQUESTS.code(), throttled.status());
    // oldest (T0) + window (60 s) - now (T0+30.5 s) = 29.5 s, rounded up
    assertEquals("30", throttled.getHeaders().get(RestThrottleResponses.RETRY_AFTER));

    clock.set(T0.plusSeconds(60).plusNanos(1));
    assertEquals(UNAUTHORIZED.code(), runLogin("admin", "wrong-password").status(),
        "a client that waited that long reaches the credential check again");
  }

  @Test
  @DisplayName("an escalating policy blocks the address: 429 for the block's duration, even with the right password")
  void blockedAddressIsRefusedLikeAThrottle() {
    MutableClock clock = new MutableClock(T0);
    handlers = handlers(new InMemoryRateLimitPolicy(new InMemoryRateLimitStore(), audit, 1,
        WINDOW, clock, new RateLimitEscalation(2, Duration.ofMinutes(5), Duration.ofMinutes(10))));
    assertEquals(UNAUTHORIZED.code(), runLogin("admin", "wrong-password").status());
    clock.set(T0.plusSeconds(1));
    DemoHttpResponse throttled = runLogin("admin", "wrong-password");
    assertEquals(TOO_MANY_REQUESTS.code(), throttled.status());
    assertEquals("60", throttled.getHeaders().get(RestThrottleResponses.RETRY_AFTER));

    clock.set(T0.plusSeconds(2));
    DemoHttpResponse blocked = runLogin("admin", "wrong-password");
    assertEquals(TOO_MANY_REQUESTS.code(), blocked.status(), "the second throttle blocks");
    assertEquals("600", blocked.getHeaders().get(RestThrottleResponses.RETRY_AFTER));

    clock.set(T0.plusSeconds(120)); // the window is empty again, the block is not over
    DemoHttpResponse stillBlocked = runLogin("admin", ADMIN_PASSWORD);
    assertEquals(TOO_MANY_REQUESTS.code(), stillBlocked.status(),
        "a blocked address does not reach the credential check, not even with the right password");
    assertEquals("482", stillBlocked.getHeaders().get(RestThrottleResponses.RETRY_AFTER));

    clock.set(T0.plusSeconds(2).plus(Duration.ofMinutes(10)));
    assertEquals(OK.code(), runLogin("admin", ADMIN_PASSWORD).status(),
        "the block ends after its duration");
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

  /** Mutable clock that returns whatever instant the test set. */
  private static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    void set(Instant at) {
      this.now = at;
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
