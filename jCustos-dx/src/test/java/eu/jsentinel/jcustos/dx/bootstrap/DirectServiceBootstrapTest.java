/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService;
import eu.jsentinel.jcustos.authentication.ApiKeyStore;
import eu.jsentinel.jcustos.authentication.InMemoryApiKeyStore;
import eu.jsentinel.jcustos.authentication.InMemoryRefreshTokenStore;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.credential.token.TokenHasher;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.audit.CorrelationIdResolver;
import eu.jsentinel.jcustos.audit.TrustedPeerCorrelationIdResolver;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicy;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitStore;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("V00.74 direct-service builder methods")
class DirectServiceBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".logout(svc) registers via JCustosServiceResolver.setLogoutService(...)")
  void logoutWiresResolver() {
    LogoutService svc = new RecordingLogoutService();
    JCustosRuntime runtime = new TestBootstrap()
        .logout(svc)
        .install();
    assertSame(svc, JCustosServiceResolver.findLogoutService().orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> LogoutService.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".bruteForce(policy) registers via JCustosServiceResolver.setLoginAttemptPolicy(...)")
  void bruteForceWiresResolver() {
    LoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JCustosRuntime runtime = new TestBootstrap()
        .bruteForce(policy)
        .install();
    assertSame(policy, JCustosServiceResolver.findLoginAttemptPolicy().orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> LoginAttemptPolicy.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".clientAddress(resolver) registers via JCustosServiceResolver.setClientAddressResolver(...) (JS-SEC-061)")
  void clientAddressWiresResolver() {
    ClientAddressResolver resolver = ClientAddressResolver.trustedProxies("127.0.0.1");
    JCustosRuntime runtime = new TestBootstrap()
        .clientAddress(resolver)
        .install();
    assertSame(resolver, JCustosServiceResolver.findClientAddressResolver().orElseThrow());
    assertSame(resolver, JCustosServiceResolver.clientAddressResolver());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> ClientAddressResolver.class.equals(s.spi())));
  }

  @Test
  @DisplayName("without .clientAddress(...) the resolver default applies and nothing is registered")
  void clientAddressDefaultsToPeer() {
    JCustosRuntime runtime = new TestBootstrap().install();
    assertTrue(JCustosServiceResolver.findClientAddressResolver().isEmpty());
    assertFalse(runtime.services().stream()
        .anyMatch(s -> ClientAddressResolver.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".correlationIds(resolver) registers via JCustosServiceResolver.setCorrelationIdResolver(...) (R5, JS-SEC-066)")
  void correlationIdsWiresResolver() {
    CorrelationIdResolver resolver = new TrustedPeerCorrelationIdResolver(
        ClientAddressResolver.trustedProxies("127.0.0.1"), "X-Correlation-ID");
    JCustosRuntime runtime = new TestBootstrap()
        .correlationIds(resolver)
        .install();
    assertSame(resolver, JCustosServiceResolver.findCorrelationIdResolver().orElseThrow());
    assertSame(resolver, JCustosServiceResolver.correlationIdResolver());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> CorrelationIdResolver.class.equals(s.spi())));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().correlationIds(null));
  }

  @Test
  @DisplayName("without .correlationIds(...) the resolver default applies and nothing is registered")
  void correlationIdsDefaultToTrustedPeer() {
    JCustosRuntime runtime = new TestBootstrap().install();
    assertTrue(JCustosServiceResolver.findCorrelationIdResolver().isEmpty());
    assertTrue(JCustosServiceResolver.correlationIdResolver()
        instanceof TrustedPeerCorrelationIdResolver);
    assertFalse(runtime.services().stream()
        .anyMatch(s -> CorrelationIdResolver.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".rateLimit(policy) is recorded-not-wired: INFO warning, NOT a registered service (R029)")
  void rateLimitDxStateOnly() {
    RateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(),
        new NoopJCustosAuditService(),
        200, Duration.ofMinutes(1));
    JCustosRuntime runtime = new TestBootstrap()
        .rateLimit(policy)
        .install();
    // R029: must NOT masquerade as an actively-wired service.
    assertFalse(runtime.services().stream()
        .anyMatch(s -> RateLimitPolicy.class.equals(s.spi())),
        "an unwired DX feature must not appear as a registered service");
    // JS-SEC-055: raised from INFO to WARNING (loud) in non-STRICT modes.
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/rate-limit-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.WARNING),
        "an unwired DX feature must surface as an explicit WARNING");
  }

  @Test
  @DisplayName(".apiKeys(svc) is recorded-not-wired: INFO warning, NOT a registered service (R029)")
  void apiKeysDxStateOnly() {
    ApiKeyStore store = new InMemoryApiKeyStore();
    TokenHasher hasher = new Sha256TokenHasher();
    ApiKeyAuthenticationService svc = new ApiKeyAuthenticationService(
        store, hasher, new NoopJCustosAuditService());
    JCustosRuntime runtime = new TestBootstrap()
        .apiKeys(svc)
        .install();
    assertFalse(runtime.services().stream()
        .anyMatch(s -> ApiKeyAuthenticationService.class.equals(s.spi())));
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/api-keys-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.WARNING));
  }

  @Test
  @DisplayName(".refreshTokens(svc) is recorded-not-wired: INFO warning, NOT a registered service (R029)")
  void refreshTokensDxStateOnly() {
    TokenService svc = new TokenService(
        new InMemoryRefreshTokenStore(),
        new Sha256TokenHasher(),
        new NoopJCustosAuditService());
    JCustosRuntime runtime = new TestBootstrap()
        .refreshTokens(svc)
        .install();
    assertFalse(runtime.services().stream()
        .anyMatch(s -> TokenService.class.equals(s.spi())));
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/refresh-tokens-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.WARNING));
  }

  @Test
  @DisplayName("resolver-wired services register; recorded-not-wired features surface as INFO (R029)")
  void allFiveTogether() {
    LogoutService logout = new RecordingLogoutService();
    LoginAttemptPolicy bf = new InMemoryLoginAttemptPolicy();
    RateLimitPolicy rl = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoopJCustosAuditService(),
        50, Duration.ofMinutes(1));
    TokenHasher hasher = new Sha256TokenHasher();
    ApiKeyAuthenticationService ak = new ApiKeyAuthenticationService(
        new InMemoryApiKeyStore(), hasher, new NoopJCustosAuditService());
    TokenService ts = new TokenService(
        new InMemoryRefreshTokenStore(), hasher, new NoopJCustosAuditService());

    JCustosRuntime runtime = new TestBootstrap()
        .logout(logout)
        .bruteForce(bf)
        .rateLimit(rl)
        .apiKeys(ak)
        .refreshTokens(ts)
        .install();

    // Only the two genuinely resolver-wired services register.
    assertEquals(2, runtime.services().stream()
        .filter(s -> s.spi() == LogoutService.class
            || s.spi() == LoginAttemptPolicy.class)
        .count(),
        "only resolver-wired services (logout + brute-force) must register");
    assertEquals(0, runtime.services().stream()
        .filter(s -> s.spi() == RateLimitPolicy.class
            || s.spi() == ApiKeyAuthenticationService.class
            || s.spi() == TokenService.class)
        .count(),
        "recorded-not-wired features must NOT register as services");
    // The three recorded-not-wired features each surface as a WARNING (JS-SEC-055).
    assertEquals(3, runtime.warnings().stream()
        .filter(w -> w.severity() == Severity.WARNING
            && w.code().endsWith("-recorded-not-wired"))
        .count(),
        "rateLimit / apiKeys / refreshTokens must each surface as an INFO");
  }

  @Test
  @DisplayName("JS-SEC-055: in STRICT mode a recorded-not-wired .rateLimit(...) is a hard boot failure")
  void strictModeRateLimitThrows() {
    RateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoopJCustosAuditService(), 50, Duration.ofMinutes(1));
    assertThrows(JCustosBootstrapException.class,
        () -> new TestBootstrap().mode(JCustosBootstrapMode.STRICT).rateLimit(policy).install());
  }

  @Test
  @DisplayName("null arguments are rejected")
  void nullsRejected() {
    assertThrows(NullPointerException.class, () -> new TestBootstrap().logout(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().bruteForce(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().rateLimit(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().apiKeys(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().refreshTokens(null));
  }

  // ── JS-SEC-124: disabled throttling and missing logout ───────────

  private static boolean has(List<JCustosBootstrapWarning> warnings, String code, Severity severity) {
    return warnings.stream().anyMatch(w -> code.equals(w.code()) && w.severity() == severity);
  }

  private static boolean has(List<JCustosBootstrapWarning> warnings, String code) {
    return warnings.stream().anyMatch(w -> code.equals(w.code()));
  }

  @Test
  @DisplayName("JS-SEC-124: STRICT with an explicit NoopLoginAttemptPolicy refuses to boot with bruteforce/noop-policy")
  void strictWithExplicitNoopPolicyThrows() {
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class,
        () -> new TestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .logout(new RecordingLogoutService())
            .bruteForce(new NoopLoginAttemptPolicy())   // a fresh instance: type, not identity
            .install());
    assertTrue(has(ex.warnings(), "bruteforce/noop-policy", Severity.ERROR), ex.warnings().toString());
    assertFalse(has(ex.warnings(), "logout/missing-service"));
  }

  @Test
  @DisplayName("JS-SEC-124: PRODUCTION records bruteforce/noop-policy as ERROR and boots; DEVELOPMENT records a WARNING")
  void explicitNoopPolicySeverityByMode() {
    JCustosRuntime production = new TestBootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .logout(new RecordingLogoutService())
        .bruteForce(NoopLoginAttemptPolicy.INSTANCE)
        .install();
    assertTrue(has(production.warnings(), "bruteforce/noop-policy", Severity.ERROR));

    JCustosServiceResolver.resetAll();
    JCustosRuntime development = new TestBootstrap()
        .mode(JCustosBootstrapMode.DEVELOPMENT)
        .logout(new RecordingLogoutService())
        .bruteForce(NoopLoginAttemptPolicy.INSTANCE)
        .install();
    assertTrue(has(development.warnings(), "bruteforce/noop-policy", Severity.WARNING));
  }

  @Test
  @DisplayName("JS-SEC-124: a Noop registered at the resolver, outside the bootstrap, is reported as well")
  void noopRegisteredOutsideTheBootstrapIsReported() {
    JCustosServiceResolver.setLoginAttemptPolicy(new NoopLoginAttemptPolicy());
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class,
        () -> new TestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .logout(new RecordingLogoutService())
            .install());
    assertTrue(has(ex.warnings(), "bruteforce/noop-policy", Severity.ERROR));
  }

  @Test
  @DisplayName("JS-SEC-124: STRICT without any policy boots - the resolver default throttles and is no finding")
  void strictWithoutPolicyBootsOnTheThrottlingDefault() {
    JCustosRuntime runtime = new TestBootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .logout(new RecordingLogoutService())
        .install();

    assertFalse(has(runtime.warnings(), "bruteforce/noop-policy"), runtime.warnings().toString());
    assertTrue(runtime.warnings().isEmpty(), runtime.warnings().toString());
    assertTrue(JCustosServiceResolver.loginAttemptPolicy() instanceof InMemoryLoginAttemptPolicy,
        "what the application gets without configuring anything");
    assertFalse(runtime.services().stream().anyMatch(s -> LoginAttemptPolicy.class.equals(s.spi())),
        "the default is not listed as a registration");
  }

  @Test
  @DisplayName("JS-SEC-124: a throttling policy passed to .bruteForce(...) is no finding")
  void throttlingPolicyIsNoFinding() {
    JCustosRuntime runtime = new TestBootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .logout(new RecordingLogoutService())
        .bruteForce(new InMemoryLoginAttemptPolicy())
        .install();
    assertTrue(runtime.warnings().isEmpty(), runtime.warnings().toString());
  }

  @Test
  @DisplayName("JS-SEC-124: STRICT without a LogoutService refuses to boot with logout/missing-service")
  void strictWithoutLogoutThrows() {
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class,
        () -> new TestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .install());
    assertTrue(has(ex.warnings(), "logout/missing-service", Severity.ERROR), ex.warnings().toString());
    assertFalse(has(ex.warnings(), "bruteforce/noop-policy"));
  }

  @Test
  @DisplayName("JS-SEC-124: logout/missing-service is ERROR in PRODUCTION, WARNING otherwise, and silenced by a registered service")
  void missingLogoutSeverityByMode() {
    assertTrue(has(new TestBootstrap().mode(JCustosBootstrapMode.PRODUCTION).install().warnings(),
        "logout/missing-service", Severity.ERROR));
    assertTrue(has(new TestBootstrap().mode(JCustosBootstrapMode.DEVELOPMENT).install().warnings(),
        "logout/missing-service", Severity.WARNING));
    assertTrue(has(new TestBootstrap().install().warnings(),
        "logout/missing-service", Severity.WARNING), "the default mode warns");

    // a service registered outside the bootstrap counts
    JCustosServiceResolver.setLogoutService(new RecordingLogoutService());
    assertFalse(has(new TestBootstrap().mode(JCustosBootstrapMode.STRICT).install().warnings(),
        "logout/missing-service"));

    // a Noop does not - detected by type
    JCustosServiceResolver.setLogoutService(new eu.jsentinel.jcustos.logout.NoopLogoutService());
    assertTrue(has(new TestBootstrap().mode(JCustosBootstrapMode.PRODUCTION).install().warnings(),
        "logout/missing-service", Severity.ERROR));
  }

  // ── adapter test double ──────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractJCustosBootstrap<TestBootstrap> {
    @Override
    public JCustosRuntime install() {
      List<RegisteredJCustosService> services = new ArrayList<>();
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyDirectServiceConfiguration(services, warnings);
      JCustosBootstrapMode mode = state.mode();
      if (mode == JCustosBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new JCustosBootstrapException(warnings);
      }
      return new JCustosRuntime(services, warnings, mode);
    }
  }

  /** Minimal LogoutService impl for tests — no-op, just lets us register a real instance. */
  private static final class RecordingLogoutService implements LogoutService {
    @Override public void logout(eu.jsentinel.jcustos.logout.SubjectId subjectId,
                                  eu.jsentinel.jcustos.logout.LogoutScope scope) { }
    @Override public void addListener(eu.jsentinel.jcustos.logout.LogoutListener listener) { }
    @Override public void removeListener(eu.jsentinel.jcustos.logout.LogoutListener listener) { }
  }
}
