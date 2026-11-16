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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link LoginAttemptPolicy#recordFailure} is the single audit point of a rejected login: each
 * shipped policy publishes exactly one {@link LoginFailed} per call, with user name, client
 * address and the caller's reason. Until 00.84.00 only the in-memory policy published it, with
 * a fixed reason, and {@code StandaloneLoginFlow} published a second one.
 */
@DisplayName("LoginAttemptPolicy.recordFailure - one LoginFailed per rejected login")
class LoginFailedAuditPointTest {

  private final Recording audit = new Recording();

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("in-memory, store-backed and no-op policy publish one LoginFailed with user name, address and reason")
  void everyShippedPolicyPublishesOne() {
    List<LoginAttemptPolicy> policies = List.of(
        new InMemoryLoginAttemptPolicy(),
        new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore()),
        NoopLoginAttemptPolicy.INSTANCE);
    for (LoginAttemptPolicy policy : policies) {
      audit.events.clear();
      LoginAttemptContext attempt = LoginAttemptContext.now("alice", "203.0.113.7", null);
      assertTrue(policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.Allowed);

      policy.recordFailure(attempt, "Subject lookup returned null");
      policy.beforeAttempt(attempt);
      policy.recordFailure(attempt);

      String name = policy.getClass().getSimpleName();
      List<LoginFailed> failed = audit.events.stream()
          .filter(LoginFailed.class::isInstance).map(LoginFailed.class::cast).toList();
      assertEquals(2, failed.size(), name + ": one event per call, got " + audit.events);
      assertEquals("alice", failed.get(0).username(), name);
      assertEquals("203.0.113.7", failed.get(0).clientAddress(), name);
      assertEquals("Subject lookup returned null", failed.get(0).reason(), name);
      assertEquals(LoginAttemptPolicy.REASON_CREDENTIALS_REJECTED, failed.get(1).reason(), name);
    }
  }

  @Test
  @DisplayName("an audit service passed to the store-backed policy receives the event; a blank reason falls back")
  void storeBackedWithExplicitAuditService() {
    Recording own = new Recording();
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), LoginAttemptConfiguration.defaults(), TenantId.DEFAULT,
        Clock.systemUTC(), SubjectKeyCanonicalizer.defaults(), own);
    LoginAttemptContext attempt = LoginAttemptContext.now("bob", null, null);
    policy.beforeAttempt(attempt);

    policy.recordFailure(attempt, " ");

    assertEquals(1, own.events.size(), own.events.toString());
    assertEquals(LoginAttemptPolicy.REASON_CREDENTIALS_REJECTED,
        ((LoginFailed) own.events.getFirst()).reason());
    assertTrue(audit.events.isEmpty(), "the registered service is not used: " + audit.events);
  }

  @Test
  @DisplayName("a policy that does not override the reason overload still sees the failure")
  void defaultOverloadDelegates() {
    List<LoginAttemptContext> recorded = new ArrayList<>();
    LoginAttemptPolicy custom = new LoginAttemptPolicy() {
      @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
        return LoginAttemptDecision.allowed();
      }

      @Override public void recordSuccess(LoginAttemptContext context) {
      }

      @Override public void recordFailure(LoginAttemptContext context) {
        recorded.add(context);
      }
    };
    LoginAttemptContext attempt = LoginAttemptContext.now("carol", null, null);

    custom.recordFailure(attempt, "any reason");

    assertEquals(List.of(attempt), recorded);
  }

  /** Hand-written audit service that keeps what it is given. */
  private static final class Recording implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }
  }
}
