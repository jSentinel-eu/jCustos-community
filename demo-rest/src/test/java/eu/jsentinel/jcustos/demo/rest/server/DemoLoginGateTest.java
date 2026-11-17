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

import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRole;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.rest.RestThrottleResponses;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static com.svenruppert.dependencies.core.net.HttpStatus.TOO_MANY_REQUESTS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-063 (CWE-770): the demo login runs its password check inside the policy's
 * credential-check gate and answers a deferral with {@code 429} and {@code Retry-After} through
 * {@link RestThrottleResponses}. Real {@link DemoUserStore}, real PBKDF2 pipeline, real
 * {@link InMemoryLoginAttemptPolicy} with a gate of one permit.
 */
@DisplayName("Demo REST login - the credential-check gate answers 429 + Retry-After")
class DemoLoginGateTest {

  private static final String CLIENT = "203.0.113.50";

  @BeforeEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the only permit is busy: 429, Retry-After rounded up, no LoginFailed; once it is free the login succeeds")
  void busyGateIsTooManyRequests() {
    DemoUserStore users = new DemoUserStore(PasswordHashingServices.defaults());
    users.create("gate-user", "correct horse", "Gate User", DemoRole.ROLE_VIEWER);
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(1)
        .withGateWait(Duration.ZERO)
        .withGateRetryAfter(Duration.ofMillis(2500)), Clock.systemUTC(), null);
    DemoHandlers handlers = handlers(users, policy);

    CredentialCheckGate.Admission.Entered busy = assertInstanceOf(
        CredentialCheckGate.Admission.Entered.class, policy.credentialCheckGate().enter());
    DemoHttpResponse deferred = login(handlers, "gate-user", "correct horse");
    busy.close();

    assertEquals(TOO_MANY_REQUESTS.code(), deferred.status());
    assertEquals("3", deferred.getHeaders().get(RestThrottleResponses.RETRY_AFTER),
        "2.5 s is announced as 3 s, never as 2");
    assertEquals(RestThrottleResponses.DEFAULT_BODY, deferred.getBody());
    assertTrue(JCustosServiceResolver.securityAuditService().query(AuditQuery.all()).stream()
        .noneMatch(LoginFailed.class::isInstance), "a deferral is no failed login");
    assertTrue(JCustosServiceResolver.securityAuditService().query(AuditQuery.all()).stream()
        .anyMatch(RateLimitExceeded.class::isInstance), "the deferral is audited");

    DemoHttpResponse after = login(handlers, "gate-user", "correct horse");
    assertEquals(OK.code(), after.status());
    assertEquals(0, policy.credentialCheckGate().inUse(), "the permit was given back");
  }

  private static DemoHandlers handlers(DemoUserStore users, InMemoryLoginAttemptPolicy policy) {
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
}
