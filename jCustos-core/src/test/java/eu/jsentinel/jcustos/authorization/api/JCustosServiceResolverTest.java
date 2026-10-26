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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.action.ActionAuthorizationService;
import eu.jsentinel.jcustos.action.ActionPermission;
import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.logout.LogoutListener;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.NoopLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.DefaultClientAddressResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.NoopSessionPolicy;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JCustosServiceResolver")
class JCustosServiceResolverTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("missing AuthenticationService SPI produces actionable error message")
  void missingAuthenticationService_throwsWithMessage() {
    // In a test environment without META-INF/services registration,
    // the resolver should throw with a clear, actionable message.
    var ex = assertThrows(IllegalStateException.class,
        JCustosServiceResolver::authenticationService);

    assertTrue(ex.getMessage().contains("AuthenticationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthenticationService returns empty when no SPI registered")
  void findAuthenticationService_empty() {
    var result = JCustosServiceResolver.findAuthenticationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthenticationService implementations fail explicitly")
  void multipleAuthenticationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> JCustosServiceResolver.requireSingleService(
            AuthenticationService.class,
            java.util.List.of(new FirstAuthenticationService(), new SecondAuthenticationService())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstAuthenticationService.class.getName()));
    assertTrue(ex.getMessage().contains(SecondAuthenticationService.class.getName()));
  }

  @Test
  @DisplayName("missing AuthorizationService SPI produces actionable error message")
  void missingAuthorizationService_throwsWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        JCustosServiceResolver::authorizationService);

    assertTrue(ex.getMessage().contains("AuthorizationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthorizationService returns empty when no SPI registered")
  void findAuthorizationService_empty() {
    var result = JCustosServiceResolver.findAuthorizationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthorizationService implementations fail explicitly")
  void multipleAuthorizationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> JCustosServiceResolver.requireSingleService(
            AuthorizationService.class,
            java.util.List.of(new FirstAuthorizationService(), new SecondAuthorizationService())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstAuthorizationService.class.getName()));
    assertTrue(ex.getMessage().contains(SecondAuthorizationService.class.getName()));
  }

  @Test
  @DisplayName("resetAll clears cached services")
  void resetAll_clearsCaches() {
    // After reset, a subsequent call should attempt SPI lookup again.
    // Since no SPI is registered in the test env, it should throw.
    JCustosServiceResolver.resetAll();
    assertThrows(IllegalStateException.class,
        JCustosServiceResolver::authenticationService);
  }

  @Test
  @DisplayName("resetAll also clears the SubjectStore cache")
  void resetAll_clearsSubjectStore() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    assertTrue(SubjectStores.findSubjectStore().isPresent(),
        "precondition: subject store cached");

    JCustosServiceResolver.resetAll();

    assertTrue(SubjectStores.findSubjectStore().isEmpty(),
        "resetAll() must reset SubjectStores too");
  }

  @Test
  @DisplayName("findSingleService returns the only registered service")
  void findSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    var found = JCustosServiceResolver.findSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertTrue(found.isPresent());
    assertSame(only, found.get());
  }

  @Test
  @DisplayName("findSingleService returns empty for an empty service iterable")
  void findSingleService_empty() {
    var found = JCustosServiceResolver.findSingleService(
        AuthenticationService.class, java.util.List.of());

    assertTrue(found.isEmpty());
  }

  @Test
  @DisplayName("requireSingleService returns the only registered service")
  void requireSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    AuthenticationService<?, ?> resolved = JCustosServiceResolver.requireSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertSame(only, resolved);
  }

  static class FirstAuthenticationService implements AuthenticationService<String, String> {
    @Override
    public boolean checkCredentials(String credentials) {
      return false;
    }

    @Override
    public String loadSubject(String credentials) {
      return credentials;
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  static final class SecondAuthenticationService extends FirstAuthenticationService {
  }

  static class FirstAuthorizationService implements AuthorizationService<String> {
    @Override
    public eu.jsentinel.jcustos.authorization.api.roles.HasRoles rolesFor(String subject) {
      return java.util.List::of;
    }
  }

  static final class SecondAuthorizationService extends FirstAuthorizationService {
  }

  // ── JCustosAuditService ─────────────────────────────────────

  @Test
  @DisplayName("securityAuditService falls back to NoopJCustosAuditService when no SPI is registered")
  void auditService_defaultsToNoop() {
    JCustosAuditService service = JCustosServiceResolver.securityAuditService();
    assertSame(NoopJCustosAuditService.INSTANCE, service);
  }

  @Test
  @DisplayName("findJCustosAuditService returns empty when no SPI is registered")
  void findAuditService_emptyByDefault() {
    assertTrue(JCustosServiceResolver.findJCustosAuditService().isEmpty());
  }

  @Test
  @DisplayName("setJCustosAuditService overrides the cached service for both accessors")
  void setJCustosAuditService_overrides() {
    RecordingAuditService recorder = new RecordingAuditService();
    JCustosServiceResolver.setJCustosAuditService(recorder);

    assertSame(recorder, JCustosServiceResolver.securityAuditService());
    assertSame(recorder, JCustosServiceResolver.findJCustosAuditService().orElseThrow());
  }

  @Test
  @DisplayName("recorded events flow through the configured audit service")
  void recordedEventsAreCaptured() {
    RecordingAuditService recorder = new RecordingAuditService();
    JCustosServiceResolver.setJCustosAuditService(recorder);

    JCustosServiceResolver.securityAuditService()
        .publish(new LoginSucceeded(Instant.now(), "alice", null, null));

    assertEquals(1, recorder.events.size());
    assertTrue(recorder.events.get(0) instanceof LoginSucceeded);
  }

  @Test
  @DisplayName("resetAll clears the audit-service cache")
  void resetAll_clearsAuditService() {
    JCustosServiceResolver.setJCustosAuditService(new RecordingAuditService());

    JCustosServiceResolver.resetAll();

    assertSame(NoopJCustosAuditService.INSTANCE,
        JCustosServiceResolver.securityAuditService());
  }

  static final class RecordingAuditService implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  // ── ActionAuthorizationService ───────────────────────────────

  @Test
  @DisplayName("actionAuthorizationService throws when no SPI is registered")
  void actionAuthorizationService_missing_throws() {
    assertThrows(IllegalStateException.class,
        JCustosServiceResolver::actionAuthorizationService);
  }

  @Test
  @DisplayName("findActionAuthorizationService returns empty when no SPI is registered")
  void findActionAuthorizationService_emptyByDefault() {
    assertTrue(JCustosServiceResolver.findActionAuthorizationService().isEmpty());
  }

  @Test
  @DisplayName("setActionAuthorizationService overrides the cached service for both accessors")
  void setActionAuthorizationService_overrides() {
    AlwaysDeny<String> svc = new AlwaysDeny<>();
    JCustosServiceResolver.setActionAuthorizationService(svc);

    assertSame(svc, JCustosServiceResolver.<String>actionAuthorizationService());
    assertSame(svc, JCustosServiceResolver.<String>findActionAuthorizationService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the action-authorization-service cache")
  void resetAll_clearsActionAuthService() {
    JCustosServiceResolver.setActionAuthorizationService(new AlwaysDeny<>());

    JCustosServiceResolver.resetAll();

    assertThrows(IllegalStateException.class,
        JCustosServiceResolver::actionAuthorizationService);
  }

  static final class AlwaysDeny<U> implements ActionAuthorizationService<U> {
    @Override
    public boolean isAllowed(U subject, ActionPermission permission) {
      return false;
    }
  }

  // ── LoginAttemptPolicy ────────────────────────────────────────

  @Test
  @DisplayName("loginAttemptPolicy falls back to NoopLoginAttemptPolicy when no SPI is registered")
  void loginAttemptPolicy_defaultsToNoop() {
    assertSame(NoopLoginAttemptPolicy.INSTANCE,
        JCustosServiceResolver.loginAttemptPolicy());
  }

  @Test
  @DisplayName("findLoginAttemptPolicy returns empty when no SPI is registered")
  void findLoginAttemptPolicy_emptyByDefault() {
    assertTrue(JCustosServiceResolver.findLoginAttemptPolicy().isEmpty());
  }

  @Test
  @DisplayName("setLoginAttemptPolicy overrides the cached policy for both accessors")
  void setLoginAttemptPolicy_overrides() {
    BlockEverything blocker = new BlockEverything();
    JCustosServiceResolver.setLoginAttemptPolicy(blocker);

    assertSame(blocker, JCustosServiceResolver.loginAttemptPolicy());
    assertSame(blocker, JCustosServiceResolver.findLoginAttemptPolicy().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the login-attempt-policy cache")
  void resetAll_clearsLoginAttemptPolicy() {
    JCustosServiceResolver.setLoginAttemptPolicy(new BlockEverything());

    JCustosServiceResolver.resetAll();

    assertSame(NoopLoginAttemptPolicy.INSTANCE,
        JCustosServiceResolver.loginAttemptPolicy());
  }

  // ── ClientAddressResolver (JS-SEC-061) ─────────────────────────

  @Test
  @DisplayName("clientAddressResolver falls back to DefaultClientAddressResolver when no SPI is registered")
  void clientAddressResolver_defaultsToRemotePeer() {
    assertSame(DefaultClientAddressResolver.INSTANCE,
        JCustosServiceResolver.clientAddressResolver());
  }

  @Test
  @DisplayName("findClientAddressResolver returns empty for the default")
  void findClientAddressResolver_emptyByDefault() {
    JCustosServiceResolver.clientAddressResolver();
    assertTrue(JCustosServiceResolver.findClientAddressResolver().isEmpty());
  }

  @Test
  @DisplayName("setClientAddressResolver overrides both accessors; resetAll restores the default")
  void setClientAddressResolver_overridesAndResets() {
    ClientAddressResolver trusted = ClientAddressResolver.trustedProxies("127.0.0.1");
    JCustosServiceResolver.setClientAddressResolver(trusted);

    assertSame(trusted, JCustosServiceResolver.clientAddressResolver());
    assertSame(trusted, JCustosServiceResolver.findClientAddressResolver().orElseThrow());

    JCustosServiceResolver.resetAll();

    assertSame(DefaultClientAddressResolver.INSTANCE,
        JCustosServiceResolver.clientAddressResolver());
  }

  static final class BlockEverything implements LoginAttemptPolicy {
    @Override
    public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
      return LoginAttemptDecision.lockedOut(java.time.Duration.ofSeconds(60), 99);
    }

    @Override
    public void recordSuccess(LoginAttemptContext context) {
    }

    @Override
    public void recordFailure(LoginAttemptContext context) {
    }
  }

  // ── SessionPolicy ─────────────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-065: sessionPolicy falls back to the enforcing TimeoutSessionPolicy when no SPI is registered")
  void sessionPolicy_defaultsToTimeoutSessionPolicy() {
    SessionPolicy<String> policy = JCustosServiceResolver.sessionPolicy();
    assertTrue(policy instanceof TimeoutSessionPolicy<?>,
        "the secure default must enforce idle and absolute lifetime, not NoopSessionPolicy");
  }

  @Test
  @DisplayName("JS-SEC-065: the secure default still counts as 'not configured' for findSessionPolicy")
  void findSessionPolicy_emptyForTheSecureDefault() {
    JCustosServiceResolver.sessionPolicy();
    assertTrue(JCustosServiceResolver.findSessionPolicy().isEmpty(),
        "diagnostics must be able to tell a default from a registration");
  }

  @Test
  @DisplayName("JS-SEC-065: NoopSessionPolicy registered explicitly is the opt-out")
  void explicitNoop_isTheOptOut() {
    JCustosServiceResolver.setSessionPolicy(NoopSessionPolicy.instance());
    assertTrue(JCustosServiceResolver.sessionPolicy() instanceof NoopSessionPolicy<?>);
    assertTrue(JCustosServiceResolver.findSessionPolicy().isEmpty());
  }

  @Test
  @DisplayName("findSessionPolicy returns empty when no SPI is registered")
  void findSessionPolicy_emptyByDefault() {
    assertTrue(JCustosServiceResolver.findSessionPolicy().isEmpty());
  }

  @Test
  @DisplayName("setSessionPolicy overrides the cached policy for both accessors")
  void setSessionPolicy_overrides() {
    AlwaysInvalidate<String> custom = new AlwaysInvalidate<>();
    JCustosServiceResolver.setSessionPolicy(custom);

    assertSame(custom, JCustosServiceResolver.<String>sessionPolicy());
    assertSame(custom, JCustosServiceResolver.<String>findSessionPolicy().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the session-policy cache")
  void resetAll_clearsSessionPolicy() {
    JCustosServiceResolver.setSessionPolicy(new AlwaysInvalidate<String>());

    JCustosServiceResolver.resetAll();

    SessionPolicy<String> after = JCustosServiceResolver.sessionPolicy();
    assertTrue(after instanceof TimeoutSessionPolicy<?>, "after reset the secure default applies again");
  }

  static final class AlwaysInvalidate<U> implements SessionPolicy<U> {
    @Override
    public SessionDecision beforeNavigation(SessionContext<U> context) {
      return new SessionDecision.Invalidate("test", "/login");
    }
  }

  // ── PasswordHasher ────────────────────────────────────────────

  @Test
  @DisplayName("passwordHashingService falls back to Pbkdf2PasswordHasher when no SPI is registered")
  void passwordHashingService_defaultsToPbkdf2() {
    eu.jsentinel.jcustos.authentication.PasswordHasher hasher =
        JCustosServiceResolver.passwordHashingService();
    assertTrue(hasher instanceof eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher,
        "default fallback must be Pbkdf2PasswordHasher");
  }

  @Test
  @DisplayName("findPasswordHashingService returns empty when only the default fallback is cached")
  void findPasswordHashingService_emptyByDefault() {
    JCustosServiceResolver.passwordHashingService();
    assertTrue(JCustosServiceResolver.findPasswordHashingService().isEmpty(),
        "the default Pbkdf2 fallback must NOT be reported as an SPI registration");
  }

  @Test
  @DisplayName("setPasswordHashingService overrides the cached hasher for both accessors")
  void setPasswordHashingService_overrides() {
    RecordingHasher custom = new RecordingHasher();
    JCustosServiceResolver.setPasswordHashingService(custom);

    assertSame(custom, JCustosServiceResolver.passwordHashingService());
    assertSame(custom, JCustosServiceResolver.findPasswordHashingService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the password-hasher cache so the next call returns a fresh fallback")
  void resetAll_clearsPasswordHasher() {
    JCustosServiceResolver.setPasswordHashingService(new RecordingHasher());

    JCustosServiceResolver.resetAll();

    eu.jsentinel.jcustos.authentication.PasswordHasher after =
        JCustosServiceResolver.passwordHashingService();
    assertTrue(after instanceof eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher);
  }

  static final class RecordingHasher implements eu.jsentinel.jcustos.authentication.PasswordHasher {
    @Override public String hash(char[] rawPassword) { return "stub"; }
    @Override public boolean verify(char[] rawPassword, String storedHash) { return false; }
  }

  // ── LogoutService ─────────────────────────────────────────────

  @Test
  @DisplayName("logoutService falls back to NoopLogoutService when no SPI is registered")
  void logoutService_defaultsToNoop() {
    assertSame(NoopLogoutService.INSTANCE, JCustosServiceResolver.logoutService());
  }

  @Test
  @DisplayName("findLogoutService returns empty when only the noop fallback is cached")
  void findLogoutService_emptyByDefault() {
    JCustosServiceResolver.logoutService();
    assertTrue(JCustosServiceResolver.findLogoutService().isEmpty());
  }

  @Test
  @DisplayName("setLogoutService overrides the cached service for both accessors")
  void setLogoutService_overrides() {
    RecordingLogoutService custom = new RecordingLogoutService();
    JCustosServiceResolver.setLogoutService(custom);

    assertSame(custom, JCustosServiceResolver.logoutService());
    assertSame(custom, JCustosServiceResolver.findLogoutService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the logout-service cache")
  void resetAll_clearsLogoutService() {
    JCustosServiceResolver.setLogoutService(new RecordingLogoutService());

    JCustosServiceResolver.resetAll();

    assertSame(NoopLogoutService.INSTANCE, JCustosServiceResolver.logoutService());
  }

  static final class RecordingLogoutService implements LogoutService {
    @Override public void logout(SubjectId subjectId, LogoutScope scope) {
    }

    @Override public void addListener(LogoutListener listener) {
    }

    @Override public void removeListener(LogoutListener listener) {
    }
  }

  // ── JCustosVersionStore / SubjectIdResolver (Phase 4c-Followup) ──

  @Test
  @DisplayName("findJCustosVersionStore returns empty when no SPI is registered")
  void findJCustosVersionStore_emptyByDefault() {
    assertTrue(JCustosServiceResolver.findJCustosVersionStore().isEmpty());
  }

  @Test
  @DisplayName("setJCustosVersionStore overrides the cached store; resetAll clears it")
  void setJCustosVersionStore_overrides() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    JCustosServiceResolver.setJCustosVersionStore(store);

    Optional<JCustosVersionStore> resolved = JCustosServiceResolver.findJCustosVersionStore();
    assertSame(store, resolved.orElseThrow());

    JCustosServiceResolver.resetAll();
    assertTrue(JCustosServiceResolver.findJCustosVersionStore().isEmpty());
  }

  @Test
  @DisplayName("findSubjectIdResolver returns empty when no SPI is registered")
  void findSubjectIdResolver_emptyByDefault() {
    assertTrue(JCustosServiceResolver.<String>findSubjectIdResolver().isEmpty());
  }

  @Test
  @DisplayName("setSubjectIdResolver overrides the cached resolver and survives lookups; resetAll clears it")
  void setSubjectIdResolver_overrides() {
    SubjectIdResolver<String> resolver = new SubjectIdResolver<String>() {
      @Override public SubjectId resolve(String s) { return new SubjectId(s); }
      @Override public TenantId tenantFor(String s) { return new TenantId("acme"); }
    };
    JCustosServiceResolver.setSubjectIdResolver(resolver);

    SubjectIdResolver<String> read = JCustosServiceResolver.<String>findSubjectIdResolver()
        .orElseThrow();
    assertSame(resolver, read);
    assertEquals(new SubjectId("alice"), read.resolve("alice"));
    assertEquals(new TenantId("acme"), read.tenantFor("alice"));

    JCustosServiceResolver.resetAll();
    assertTrue(JCustosServiceResolver.<String>findSubjectIdResolver().isEmpty());
  }

  @Test
  @DisplayName("SubjectIdResolver default tenantFor returns TenantId.DEFAULT")
  void subjectIdResolver_defaultTenant() {
    SubjectIdResolver<String> resolver = s -> new SubjectId(s);
    assertSame(TenantId.DEFAULT, resolver.tenantFor("alice"));
  }
}
