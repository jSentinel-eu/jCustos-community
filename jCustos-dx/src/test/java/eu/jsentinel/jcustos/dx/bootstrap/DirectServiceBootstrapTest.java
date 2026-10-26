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
