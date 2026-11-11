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
package eu.jsentinel.jcustos.demo.app.security.services;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.app.security.model.Credentials;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("MyAuthenticationService — checkCredentials / loadSubject")
class MyAuthenticationServiceTest {

  private final MyAuthenticationService service = new MyAuthenticationService();
  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final CountingPolicy policy = new CountingPolicy();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    // Clear UserCreated events emitted by addUser + the seeded user/demo
    audit.clear();
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("null credentials → false, policy never consulted, no audit")
  void nullCredentialsRejected() {
    assertFalse(service.checkCredentials(null));
    assertEquals(0, policy.calls);
    assertEquals(0, audit.events().size());
  }

  @Test
  @DisplayName("JS-SEC-124: the service never consults the LoginAttemptPolicy — the library LoginView owns the protocol")
  void serviceLeavesThrottlingToTheView() {
    // A policy that would refuse everything: the service must not even ask it. Asked from
    // here as well, every attempt would be reserved and counted twice.
    policy.next = new LoginAttemptDecision.LockedOut(Duration.ofMinutes(5), 7);

    assertTrue(service.checkCredentials(new Credentials("admin", "admin")));
    assertFalse(service.checkCredentials(new Credentials("admin", "WRONG")));

    assertEquals(0, policy.calls,
        "beforeAttempt / recordSuccess / recordFailure / confirmSuccess / abandonAttempt "
            + "belong to LoginView.validate(), not to the AuthenticationService");
  }

  @Test
  @DisplayName("Valid credentials → true + LoginSucceeded audit carrying the user name")
  void successPathAudits() {
    assertTrue(service.checkCredentials(new Credentials("admin", "admin")));

    LoginSucceeded event = audit.events().stream()
        .filter(LoginSucceeded.class::isInstance)
        .map(LoginSucceeded.class::cast)
        .findFirst()
        .orElseThrow();
    assertEquals("admin", event.username());
  }

  @Test
  @DisplayName("Wrong password → false, no audit from the service")
  void failurePathIsSilent() {
    assertFalse(service.checkCredentials(new Credentials("admin", "WRONG")));

    assertTrue(audit.events().stream().noneMatch(LoginSucceeded.class::isInstance),
        "failed logins must not emit LoginSucceeded");
  }

  @Test
  @DisplayName("Audit-sink RuntimeException is swallowed — login still returns true")
  void auditFailureDoesNotBlockLogin() {
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
    });

    assertTrue(service.checkCredentials(new Credentials("admin", "admin")),
        "successful credentials must still authenticate even if audit publish throws");
  }

  @Test
  @DisplayName("loadSubject returns the directory user; missing creds → null")
  void loadSubjectMirrorsDirectory() {
    MyUser loaded = service.loadSubject(new Credentials("admin", "admin"));
    assertNotNull(loaded);
    assertEquals(1L, loaded.id());

    assertNull(service.loadSubject(new Credentials("admin", "wrong")));
    assertNull(service.loadSubject(new Credentials("missing", "x")));
  }

  @Test
  @DisplayName("subjectType is MyUser.class")
  void subjectTypeIsExpected() {
    assertSame(MyUser.class, service.subjectType());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  /** Counts every call of the protocol, including the 00.84.00 default methods. */
  private static final class CountingPolicy implements LoginAttemptPolicy {
    LoginAttemptDecision next = new LoginAttemptDecision.Allowed();
    int calls = 0;

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      calls++;
      return next;
    }

    @Override public LoginAttemptDecision peek(LoginAttemptContext ctx) {
      calls++;
      return next;
    }

    @Override public void recordSuccess(LoginAttemptContext ctx) { calls++; }

    @Override public void recordFailure(LoginAttemptContext ctx) { calls++; }

    @Override public LoginAttemptDecision confirmSuccess(LoginAttemptContext ctx) {
      calls++;
      return next;
    }

    @Override public void abandonAttempt(LoginAttemptContext ctx) { calls++; }
  }
}
