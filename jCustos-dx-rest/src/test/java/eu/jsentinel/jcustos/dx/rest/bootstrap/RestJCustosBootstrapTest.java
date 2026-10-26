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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestJCustosBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JCustosServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  private static final RestSubjectResolver TEST_RESOLVER = new RestSubjectResolver() {
    @Override
    public Optional<JCustosSubject> resolveSubject(RestRequest request) {
      return Optional.empty();
    }
  };

  @Test
  void defaultRegistration_listsDecisionMapperAndErrorBodiesAsDefaulted() {
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .audit(a -> a.logging()) // JS-SEC-080: without an audit trail the bootstrap now reports audit/noop-fallback
        .install();

    assertTrue(runtime.warnings().isEmpty(),
        "happy path must have no warnings, got: " + runtime.warnings());

    RegisteredJCustosService mapperEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestDecisionMapper.class)
        .findFirst().orElseThrow();
    assertTrue(mapperEntry.defaulted(), "default mapper must be flagged as defaulted=true");
    assertEquals(DefaultRestDecisionMapper.class, mapperEntry.impl());

    RegisteredJCustosService bodyEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestErrorBodyStrategy.class)
        .findFirst().orElseThrow();
    assertTrue(bodyEntry.defaulted());
  }

  @Test
  void customDecisionMapperOverridesDefault() {
    RestDecisionMapper custom = (decision, response) -> true;

    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .decisionMapper(custom)
        .install();

    RegisteredJCustosService mapperEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestDecisionMapper.class)
        .findFirst().orElseThrow();
    assertEquals(custom.getClass(), mapperEntry.impl());
    assertEquals(false, mapperEntry.defaulted());
  }

  @Test
  void strictMode_missingSubjectResolver_throws() {
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        RestSecurity.bootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-rest-subject-resolver".equals(w.code())));
  }

  @Test
  void defaultErrorBodyIsGenericString() {
    DefaultRestErrorBodyStrategy strat = new DefaultRestErrorBodyStrategy();
    assertEquals("Unauthorized",
        strat.bodyFor(new eu.jsentinel.jcustos.authorization.api.AuthorizationDecision
            .Unauthenticated("test reason")));
    assertEquals("Forbidden",
        strat.bodyFor(new eu.jsentinel.jcustos.authorization.api.AuthorizationDecision
            .Forbidden("test reason")));
  }

  @Test
  void secondInstallCallThrows() {
    RestJCustosBootstrap b = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER);

    JCustosRuntime first = b.install();
    assertSame(JCustosBootstrapMode.COMMUNITY_DEFAULTS, first.mode());
    assertThrows(IllegalStateException.class, b::install);
  }

  // ── V00.74 A2.2 problemJsonErrors / cors / openApiMetadata ─────

  @Test
  void problemJsonErrors_selectsRfc7807Strategy() {
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .problemJsonErrors()
        .install();

    RegisteredJCustosService entry = runtime.services().stream()
        .filter(s -> RestErrorBodyStrategy.class.equals(s.spi()))
        .findFirst()
        .orElseThrow();
    assertEquals(ProblemJsonErrorBodyStrategy.class, entry.impl());
    assertEquals("bootstrap-explicit", entry.source());

    String body = ProblemJsonErrorBodyStrategy.INSTANCE.bodyFor(
        new eu.jsentinel.jcustos.authorization.api.AuthorizationDecision
            .Unauthenticated("nope"));
    assertTrue(body.contains("\"title\":\"Unauthorized\""));
    assertTrue(body.contains("\"status\":401"));
  }

  @Test
  void cors_publishesConfigurationAndRuntimeEntry() {
    RestCorsContext.reset();
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c
            .allowedOrigins("https://app.example.com")
            .allowedMethods("GET", "POST")
            .allowedHeaders("Authorization", "Content-Type")
            .exposedHeaders("X-Total-Count")
            .allowCredentials(true)
            .maxAgeSeconds(3600))
        .install();

    RestCorsConfiguration cfg = RestCorsContext.configuration().orElseThrow();
    assertEquals(java.util.List.of("https://app.example.com"), cfg.allowedOrigins());
    assertEquals(java.util.List.of("GET", "POST"), cfg.allowedMethods());
    assertEquals(java.util.List.of("Authorization", "Content-Type"), cfg.allowedHeaders());
    assertEquals(java.util.List.of("X-Total-Count"), cfg.exposedHeaders());
    assertTrue(cfg.allowCredentials());
    assertEquals(3600L, cfg.maxAgeSeconds());

    assertTrue(runtime.services().stream()
        .anyMatch(s -> RestCorsContext.class.equals(s.spi())
            && RestCorsConfiguration.class.equals(s.impl())
            && "bootstrap-cors".equals(s.source())));
  }

  @Test
  void cors_wildcardWithCredentials_warnsInNonStrict() {
    RestCorsContext.reset();
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("*").allowCredentials(true))
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())),
        "wildcard origin + credentials must surface a warning, got: " + runtime.warnings());
  }

  @Test
  void cors_credentialedNullOrigin_warnsInNonStrict() {
    RestCorsContext.reset();
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("null").allowCredentials(true))
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())),
        "credentialed \"null\" origin must surface the same warning (JS-SEC-025), got: "
            + runtime.warnings());
  }

  @Test
  void cors_wildcardWithCredentials_throwsInStrict() {
    RestCorsContext.reset();
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        RestSecurity.bootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .subjectResolver(TEST_RESOLVER)
            .cors(c -> c.allowedOrigins("*").allowCredentials(true))
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())));
  }

  @Test
  void corsContext_rejectsConflictingSecondPublish() {
    // R06 (V00.76.10): the process-global holder must reject a conflicting second
    // publish loudly (the multi-app-in-one-JVM hazard) rather than silently
    // overwriting; an equal re-publish stays idempotent.
    RestCorsContext.reset();
    RestCorsConfiguration a = new RestCorsConfiguration(
        java.util.List.of("https://a.example"), java.util.List.of("GET"),
        java.util.List.of(), java.util.List.of(), false, -1L);
    RestCorsContext.publish(a);
    RestCorsContext.publish(a); // equal re-publish is idempotent
    RestCorsConfiguration b = new RestCorsConfiguration(
        java.util.List.of("https://b.example"), java.util.List.of("GET"),
        java.util.List.of(), java.util.List.of(), false, -1L);
    assertThrows(IllegalStateException.class, () -> RestCorsContext.publish(b),
        "a conflicting second publish must fail loudly, not silently overwrite");
    assertEquals(java.util.List.of("https://a.example"),
        RestCorsContext.configuration().orElseThrow().allowedOrigins(),
        "the first app's config must survive a rejected conflicting publish");
    RestCorsContext.reset();
  }

  @Test
  void cors_wildcardWithCredentials_notPublishedInProduction() {
    // R15 (V00.76.10): PRODUCTION records the ERROR warning AND refuses to
    // publish the dangerous credentialed-wildcard config live — CORS stays
    // unconfigured (the safe default), mirroring the JWKS PRODUCTION refusal.
    RestCorsContext.reset();
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("*").allowCredentials(true))
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())),
        "PRODUCTION must still surface the credentialed-wildcard warning");
    assertTrue(RestCorsContext.configuration().isEmpty(),
        "PRODUCTION must NOT publish the dangerous credentialed-wildcard config live");
  }

  @Test
  void cors_explicitOriginWithCredentials_publishedInProduction() {
    // Control: a credentialed config with explicit origins (no wildcard) is
    // valid and must still publish in PRODUCTION.
    RestCorsContext.reset();
    RestSecurity.bootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("https://app.example.com").allowCredentials(true))
        .install();

    assertTrue(RestCorsContext.configuration().isPresent(),
        "explicit-origin credentialed CORS must still publish in PRODUCTION");
  }

  @Test
  void openApiMetadata_publishesAndRuntimeEntry() {
    RestOpenApiContext.reset();
    JCustosRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .openApiMetadata(o -> o
            .title("Demo REST API")
            .version("0.74.0")
            .description("Demo endpoints secured by jCustos.")
            .servers("https://api.example.com"))
        .install();

    RestOpenApiMetadata meta = RestOpenApiContext.metadata().orElseThrow();
    assertEquals("Demo REST API", meta.title());
    assertEquals("0.74.0", meta.version());
    assertEquals("Demo endpoints secured by jCustos.", meta.description());
    assertEquals(java.util.List.of("https://api.example.com"), meta.servers());

    assertTrue(runtime.services().stream()
        .anyMatch(s -> RestOpenApiContext.class.equals(s.spi())
            && RestOpenApiMetadata.class.equals(s.impl())
            && "bootstrap-openapi-metadata".equals(s.source())));
  }

  @Test
  void openApiMetadata_blankTitleRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> RestSecurity.bootstrap().openApiMetadata(o -> o.title("   ")));
  }

  @Test
  void cors_nullConsumerRejected() {
    assertThrows(NullPointerException.class,
        () -> RestSecurity.bootstrap().cors(null));
  }
}
