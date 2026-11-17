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

import eu.jsentinel.jcustos.accountlifecycle.InMemoryPasswordResetTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.LoggingNotificationSender;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetService;
import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.PasswordResetRequested;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.audit.TokenRotated;
import eu.jsentinel.jcustos.authentication.InMemoryRefreshTokenStore;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicy;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitStore;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static com.svenruppert.dependencies.core.net.HttpStatus.TOO_MANY_REQUESTS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R5 follow-up (JS-SEC-066, CWE-778): the demo handlers that run without the REST
 * filters - the login, the password-reset request, the refresh-token rotation - open the
 * request's correlation scope themselves, so the audit events they cause carry its id. Real
 * handlers, policy, reset and token services and audit store; the request is the demo's own.
 */
@DisplayName("DemoHandlers - audit events of the public handlers carry the correlation id (R5)")
class DemoAuditCorrelationTest {

  private static final String CLIENT = "203.0.113.5";

  private final InMemoryAuditEventStore auditStore = new InMemoryAuditEventStore();
  private DemoHandlers handlers;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    StoreBackedJCustosAuditService audit = new StoreBackedJCustosAuditService(auditStore);
    JCustosServiceResolver.setJCustosAuditService(audit);
    DemoTokenStore tokens = new DemoTokenStore();
    DemoUserStore users = new DemoUserStore(PasswordHashingServices.defaults(),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);
    PasswordResetService reset = new PasswordResetService(new InMemoryPasswordResetTokenStore(),
        new Sha256TokenHasher(), audit, new LoggingNotificationSender());
    handlers = new DemoHandlers(users, tokens, new DemoDocumentStore(),
        new DemoOperationRegistry(),
        new DemoSubjectResolver(tokens, new DemoRolePermissionMapping()),
        NoopLoginAttemptPolicy.INSTANCE, new InMemoryJCustosVersionStore(), reset,
        new InMemoryRateLimitPolicy(new InMemoryRateLimitStore(), audit, 1, Duration.ofMinutes(1)),
        null, null,
        new TokenService(new InMemoryRefreshTokenStore(), new Sha256TokenHasher(), audit));
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    assertTrue(AuditCorrelation.current().isEmpty(), "a correlation scope leaked out of a handler");
  }

  @Test
  @DisplayName("a login and a throttled login: each event carries a server-side id of its own request")
  void loginEventsCarryTheCorrelationId() {
    assertEquals(OK.code(), login("admin", "admin").status());
    assertEquals(TOO_MANY_REQUESTS.code(), login("admin", "admin").status());

    List<AuditEnvelope> envelopes = auditStore.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(2, envelopes.size(), envelopes.toString());
    AuditEnvelope succeeded = envelopes.get(0);
    AuditEnvelope throttled = envelopes.get(1);
    assertInstanceOf(LoginSucceeded.class, succeeded.event());
    assertInstanceOf(RateLimitExceeded.class, throttled.event());
    assertNotNull(succeeded.correlationId(), "the login audits inside its request's scope");
    assertNotNull(throttled.correlationId(), "the rate limit audits inside its request's scope");
    assertEquals(36, succeeded.correlationId().length(), "a server-side UUID: no trusted proxy");
    assertNotEquals(succeeded.correlationId(), throttled.correlationId(),
        "two requests, two ids");
  }

  @Test
  @DisplayName("a password-reset request is audited with the id of its request")
  void passwordResetRequestCarriesTheCorrelationId() {
    DemoHttpRequest request = new DemoHttpRequest("POST", "/api/password-reset/request", Map.of(),
        Map.of(), "{\"subjectId\":\"viewer\"}", CLIENT);
    DemoHttpResponse response = new DemoHttpResponse();
    handlers.requestPasswordReset(request, response);
    assertEquals(OK.code(), response.status());

    List<AuditEnvelope> envelopes = auditStore.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, envelopes.size(), envelopes.toString());
    assertInstanceOf(PasswordResetRequested.class, envelopes.getFirst().event());
    assertNotNull(envelopes.getFirst().correlationId());
  }

  @Test
  @DisplayName("a refresh-token rotation is audited with the id of its request")
  void tokenRotationCarriesTheCorrelationId() {
    DemoHttpResponse issued = post("/api/auth/token/issue", "{\"subjectId\":\"viewer\"}",
        handlers::issueTokenPair);
    assertEquals(OK.code(), issued.status());
    Object refreshToken = DemoJson.decodeObject(issued.getBody()).get("refreshToken");
    DemoHttpResponse rotated = post("/api/auth/token/refresh",
        "{\"refreshToken\":\"" + refreshToken + "\"}", handlers::rotateTokenPair);
    assertEquals(OK.code(), rotated.status());

    List<AuditEnvelope> envelopes = auditStore.query(TenantId.DEFAULT, AuditQuery.all());
    AuditEnvelope rotation = envelopes.stream()
        .filter(envelope -> envelope.event() instanceof TokenRotated)
        .findFirst().orElseThrow();
    assertNotNull(rotation.correlationId());
  }

  private DemoHttpResponse post(String path, String body,
                                BiConsumer<DemoHttpRequest, DemoHttpResponse> handler) {
    DemoHttpRequest request = new DemoHttpRequest("POST", path, Map.of(), Map.of(), body, CLIENT);
    DemoHttpResponse response = new DemoHttpResponse();
    handler.accept(request, response);
    return response;
  }

  private DemoHttpResponse login(String username, String password) {
    DemoHttpRequest request = new DemoHttpRequest("POST", "/api/login", Map.of(), Map.of(),
        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}", CLIENT);
    DemoHttpResponse response = new DemoHttpResponse();
    handlers.login(request, response);
    return response;
  }
}
