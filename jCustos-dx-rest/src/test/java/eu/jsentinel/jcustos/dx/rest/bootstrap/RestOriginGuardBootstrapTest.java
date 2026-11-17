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
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.rest.RestDecisionContext;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CSRF (CWE-352), DX part: {@code .originGuard(...)} installs the guard and lists it, the router
 * finds it as its outermost filter, and {@code rest/credentialed-cors-without-origin-guard}
 * reports credentialed CORS without a guard - a WARNING in PRODUCTION and STRICT, INFO
 * otherwise. Real bootstrap, real guard, the audit sink of jCustos-test.
 */
@DisplayName("RestSecurity.bootstrap().originGuard(...) and the credentialed-CORS finding (CSRF, CWE-352)")
class RestOriginGuardBootstrapTest {

  private static final String CODE = "rest/credentialed-cors-without-origin-guard";

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  @AfterEach
  void resetGlobals() {
    JCustosServiceResolver.resetAll();
    RestOriginGuard.reset();
    RestCorsContext.reset();
    RestDecisionContext.reset();
    JCustosServiceResolver.setDenyByDefault(false);
    JCustosServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JCustosServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  private static RestJCustosBootstrap bootstrap(JCustosBootstrapMode mode) {
    return RestSecurity.bootstrap()
        .mode(mode)
        .denyByDefault(true)
        .audit(a -> a.logging())
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver((RestSubjectResolver) request -> Optional.empty())
        .logout(new SubjectClearingLogoutService<>(new InMemorySubjectStore(), String.class));
  }

  // ── .originGuard(...) ──────────────────────────────────────────

  @Test
  @DisplayName(".originGuard(...) installs the guard for the process and lists it as bootstrap-origin-guard")
  void originGuard_isInstalledAndListed() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin()
        .withAllowedOrigins(Set.of("https://api.example", "https://app.example"));

    JCustosRuntime runtime = bootstrap(JCustosBootstrapMode.PRODUCTION).originGuard(guard).install();

    assertSame(guard, RestOriginGuard.installed().orElseThrow());
    assertTrue(runtime.services().stream().anyMatch(s -> s.spi() == RestOriginGuard.class
            && "bootstrap-origin-guard".equals(s.source()) && !s.defaulted()),
        runtime.services().toString());
  }

  @Test
  @DisplayName("the router's outermost filter is the installed guard: a cross-origin POST is 403 through the configured problem+json mapper and audited")
  void installedGuard_isTheRoutersOutermostFilter() {
    bootstrap(JCustosBootstrapMode.DEVELOPMENT)
        .problemJsonErrors()
        .originGuard(RestOriginGuard.sameOrigin())
        .install();
    JCustosServiceResolver.setJCustosAuditService(audit);
    Captured refused = new Captured();
    Captured passed = new Captured();

    boolean refusedPasses = routerStep(post("https://attacker.example"), refused);
    boolean ownPasses = routerStep(post("https://app.example"), passed);

    assertFalse(refusedPasses);
    assertEquals(HttpStatus.FORBIDDEN.code(), refused.status);
    assertEquals("{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403}", refused.body);
    assertEquals(RestOriginGuard.REASON_ORIGIN_MISMATCH,
        audit.single(AccessDenied.class).reason());
    assertTrue(ownPasses);
    assertEquals(0, passed.status, "nothing written for a request that passes");
  }

  @Test
  @DisplayName("without .originGuard(...) the bootstrap leaves a guard the application installed itself in place")
  void withoutOriginGuard_anInstalledGuardStays() {
    RestOriginGuard own = RestOriginGuard.sameOrigin();
    RestOriginGuard.install(own);

    JCustosRuntime runtime = bootstrap(JCustosBootstrapMode.PRODUCTION).install();

    assertSame(own, RestOriginGuard.installed().orElseThrow());
    assertFalse(runtime.services().stream().anyMatch(s -> s.spi() == RestOriginGuard.class));
  }

  @Test
  @DisplayName(".originGuard(null) is refused")
  void originGuard_null() {
    assertThrows(NullPointerException.class, () -> RestSecurity.bootstrap().originGuard(null));
  }

  // ── rest/credentialed-cors-without-origin-guard ────────────────

  @Test
  @DisplayName("credentialed CORS without a guard: WARNING in PRODUCTION")
  void credentialedCorsWithoutGuard_warnsInProduction() {
    JCustosRuntime runtime = bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
        .install();

    assertEquals(Optional.of(Severity.WARNING), finding(runtime.warnings()));
  }

  @Test
  @DisplayName("credentialed CORS without a guard: WARNING in STRICT, which still boots")
  void credentialedCorsWithoutGuard_warnsInStrict() {
    JCustosRuntime runtime = bootstrap(JCustosBootstrapMode.STRICT)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
        .install();

    assertEquals(Optional.of(Severity.WARNING), finding(runtime.warnings()));
  }

  @Test
  @DisplayName("credentialed CORS without a guard: INFO in DEVELOPMENT and COMMUNITY_DEFAULTS")
  void credentialedCorsWithoutGuard_isInfoElsewhere() {
    JCustosRuntime development = bootstrap(JCustosBootstrapMode.DEVELOPMENT)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
        .install();
    assertEquals(Optional.of(Severity.INFO), finding(development.warnings()));

    resetGlobals();
    JCustosRuntime defaults = bootstrap(JCustosBootstrapMode.COMMUNITY_DEFAULTS)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
        .install();
    assertEquals(Optional.of(Severity.INFO), finding(defaults.warnings()));
  }

  @Test
  @DisplayName("no finding with .originGuard(...), with a guard the application installed, without credentials or without CORS")
  void noFindingWhenGuardedOrNotCredentialed() {
    assertEquals(Optional.empty(), finding(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
        .originGuard(RestOriginGuard.sameOrigin().withAllowedOrigins(Set.of("https://app.example")))
        .install().warnings()), ".originGuard(...)");

    resetGlobals();
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    assertEquals(Optional.empty(), finding(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
        .install().warnings()), "installed by the application");

    resetGlobals();
    assertEquals(Optional.empty(), finding(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(false))
        .install().warnings()), "CORS without credentials");

    resetGlobals();
    assertEquals(Optional.empty(), finding(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .install().warnings()), "no CORS at all");
  }

  // ── RF30: rest/credentialed-cors-origin-not-accepted ───────────

  private static final String NOT_ACCEPTED = "rest/credentialed-cors-origin-not-accepted";

  @Test
  @DisplayName("RF30: a credentialed CORS origin a same-origin guard refuses is a WARNING in every mode, naming the origin")
  void credentialedCorsOriginTheGuardRefuses_isReported() {
    for (JCustosBootstrapMode mode : JCustosBootstrapMode.values()) {
      resetGlobals();
      JCustosRuntime runtime = bootstrap(mode)
          .cors(c -> c.allowedOrigins("https://partner.example").allowCredentials(true))
          .originGuard(RestOriginGuard.sameOrigin())
          .install();

      List<JCustosBootstrapWarning> found = runtime.warnings().stream()
          .filter(w -> NOT_ACCEPTED.equals(w.code())).toList();
      assertEquals(1, found.size(), mode + ": " + runtime.warnings());
      assertEquals(Severity.WARNING, found.getFirst().severity(), mode.toString());
      assertTrue(found.getFirst().message().contains("https://partner.example"), found.getFirst().message());
      assertEquals(Optional.empty(), finding(runtime.warnings()), "a guard is installed");
    }
  }

  @Test
  @DisplayName("RF30: only the origins the allowlist misses are named; a guard the application installed is checked too")
  void onlyTheMissingOriginsAreNamed() {
    JCustosRuntime runtime = bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://app.example", "https://partner.example", "https://other.example")
            .allowCredentials(true))
        .originGuard(RestOriginGuard.sameOrigin()
            .withAllowedOrigins(Set.of("https://api.example", "https://App.Example", "https://other.example/")))
        .install();
    JCustosBootstrapWarning warning = runtime.warnings().stream()
        .filter(w -> NOT_ACCEPTED.equals(w.code())).findFirst().orElseThrow();
    assertTrue(warning.message().contains("[https://partner.example]"), warning.message());

    resetGlobals();
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    assertTrue(bootstrap(JCustosBootstrapMode.DEVELOPMENT)
        .cors(c -> c.allowedOrigins("https://partner.example").allowCredentials(true))
        .install().warnings().stream().anyMatch(w -> NOT_ACCEPTED.equals(w.code())),
        "installed by the application");
  }

  @Test
  @DisplayName("RF30: no finding when every origin is accepted, without credentials, without a guard, or for * and null")
  void noFindingWhenAcceptedOrNotApplicable() {
    assertTrue(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://partner.example").allowCredentials(true))
        .originGuard(RestOriginGuard.sameOrigin()
            .withAllowedOrigins(Set.of("https://app.example", "https://partner.example")))
        .install().warnings().stream().noneMatch(w -> NOT_ACCEPTED.equals(w.code())), "accepted");

    resetGlobals();
    assertTrue(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://partner.example").allowCredentials(false))
        .originGuard(RestOriginGuard.sameOrigin())
        .install().warnings().stream().noneMatch(w -> NOT_ACCEPTED.equals(w.code())), "no credentials");

    resetGlobals();
    assertTrue(bootstrap(JCustosBootstrapMode.PRODUCTION)
        .cors(c -> c.allowedOrigins("https://partner.example").allowCredentials(true))
        .install().warnings().stream().noneMatch(w -> NOT_ACCEPTED.equals(w.code())),
        "no guard: rest/credentialed-cors-without-origin-guard reports it");

    resetGlobals();
    assertTrue(bootstrap(JCustosBootstrapMode.DEVELOPMENT)
        .cors(c -> c.allowedOrigins("*", "null").allowCredentials(true))
        .originGuard(RestOriginGuard.sameOrigin())
        .install().warnings().stream().noneMatch(w -> NOT_ACCEPTED.equals(w.code())),
        "cors/wildcard-with-credentials reports these");
  }

  // ── fixtures ───────────────────────────────────────────────────

  /** What the router of a cookie-session application does first, for every route. */
  private static boolean routerStep(RestRequest request, RestResponse response) {
    return RestOriginGuard.installed().map(guard -> guard.allow(request, response)).orElse(true);
  }

  private static Optional<Severity> finding(List<JCustosBootstrapWarning> warnings) {
    List<JCustosBootstrapWarning> found = warnings.stream()
        .filter(w -> CODE.equals(w.code()))
        .toList();
    assertTrue(found.size() <= 1, found.toString());
    return found.stream().map(JCustosBootstrapWarning::severity).findFirst();
  }

  private static RestRequest post(String origin) {
    return new RestRequest() {
      @Override public String method() {
        return "POST";
      }

      @Override public String path() {
        return "/api/documents";
      }

      @Override public Map<String, String> headers() {
        return Map.of("Host", "app.example", "Origin", origin, "Cookie", "APP_SESSION=1f2e");
      }

      @Override public Map<String, String> queryParameters() {
        return Map.of();
      }
    };
  }

  private static final class Captured implements RestResponse {
    int status;
    String body;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String value) {
      this.body = value;
    }
  }
}
