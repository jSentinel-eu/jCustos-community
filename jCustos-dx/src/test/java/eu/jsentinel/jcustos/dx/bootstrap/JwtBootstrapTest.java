package eu.jsentinel.jcustos.dx.bootstrap;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.internal.JwtState;
import eu.jsentinel.jcustos.dx.internal.RecordingJwtBootstrap;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName(".jwt(...) sub-builder recording + apply wiring")
class JwtBootstrapTest {

  private static final JwtValidator NOOP_VALIDATOR = compactJwt ->
      Result.failure(new JwtValidationError.MalformedJwt("noop"));

  /** Test-only bootstrap exposing the protected apply pass. */
  static final class TestBootstrap extends AbstractJCustosBootstrap<TestBootstrap> {
    List<JCustosBootstrapWarning> applyJwt() {
      List<RegisteredJCustosService> services = new ArrayList<>();
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyJwtConfiguration(services, warnings);
      return warnings;
    }
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.setJwtValidator(null);
  }

  private static boolean hasError(List<JCustosBootstrapWarning> warnings, String code) {
    return warnings.stream().anyMatch(w ->
        w.code().equals(code) && w.severity() == Severity.ERROR);
  }

  private static boolean hasInfo(List<JCustosBootstrapWarning> warnings, String code) {
    return warnings.stream().anyMatch(w ->
        w.code().equals(code) && w.severity() == Severity.INFO);
  }

  @Test
  @DisplayName("an explicit .validator(...) is installed into the resolver")
  void explicitValidatorInstalled() {
    new TestBootstrap().jwt(j -> j.validator(NOOP_VALIDATOR)).applyJwt();
    assertSame(NOOP_VALIDATOR, JCustosServiceResolver.findJwtValidator().orElseThrow());
  }

  @Test
  @DisplayName(".validator(...) and .jwksUri(...) together raise at config time")
  void conflictingValidatorConfigRaises() {
    assertThrows(IllegalStateException.class, () ->
        new TestBootstrap().jwt(j -> j.validator(NOOP_VALIDATOR)
            .jwksUri(URI.create("https://idp.example/jwks"))));
  }

  @Test
  @DisplayName(".algorithmProfile(...) and .algorithmAllowList(...) together raise at config time")
  void conflictingAlgorithmConfigRaises() {
    JwtState state = new JwtState();
    RecordingJwtBootstrap b = new RecordingJwtBootstrap(state);
    b.algorithmProfile(AlgorithmProfile.STRICT_MODERN);
    assertThrows(IllegalStateException.class, () ->
        b.algorithmAllowList(AlgorithmProfile.STRICT_MODERN.toAllowList()));
  }

  @Test
  @DisplayName(".jwksUri(...) without a profile or allow-list is a STRICT-class error")
  void jwksUriWithoutAllowListIsError() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))).applyJwt();
    assertTrue(hasError(warnings, "jwt/no-algorithm-allow-list"));
  }

  @Test
  @DisplayName("neither .validator(...) nor .jwksUri(...) is a STRICT-class error")
  void missingJwksUriOrValidatorIsError() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.issuer("https://idp.example/")).applyJwt();
    assertTrue(hasError(warnings, "jwt/missing-jwks-uri-or-validator"));
  }

  @Test
  @DisplayName("JS-SEC-005: .jwt(...) without .audience(...) emits the claims/audience-empty INFO")
  void audienceEmptyEmitsInfo() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmAllowList(AlgorithmProfile.STRICT_MODERN.toAllowList())
            .issuer("https://idp.example/"))
        .applyJwt();
    assertTrue(hasInfo(warnings, "claims/audience-empty"));
  }

  @Test
  @DisplayName("JS-SEC-005: .jwt(...) with an .audience(...) does not emit claims/audience-empty")
  void audienceSetSuppressesInfo() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmAllowList(AlgorithmProfile.STRICT_MODERN.toAllowList())
            .issuer("https://idp.example/")
            .audience("rp-client"))
        .applyJwt();
    assertFalse(hasInfo(warnings, "claims/audience-empty"));
  }

  @Test
  @DisplayName("a non-https JWKS URI is a STRICT-class error in STRICT mode")
  void nonHttpsJwksUriIsErrorInStrict() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .jwt(j -> j.jwksUri(URI.create("http://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
        .applyJwt();
    assertTrue(hasError(warnings, "jwks/uri-not-https"));
  }

  @Test
  @DisplayName("F4: .tokenType(...) is recorded into the JWT state and flows to ClaimExpectations")
  void tokenTypeRecorded() {
    JwtState state = new JwtState();
    new RecordingJwtBootstrap(state).tokenType("at+jwt");
    assertEquals("at+jwt", state.tokenType());
    assertTrue(state.hasAnySelection(),
        "recording a tokenType must mark the .jwt(...) sub-builder as non-empty");
  }

  @Test
  @DisplayName("R11: a non-https JWKS URI is also an ERROR in PRODUCTION mode (was WARNING)")
  void nonHttpsJwksUriIsErrorInProduction() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .jwt(j -> j.jwksUri(URI.create("http://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
        .applyJwt();
    assertTrue(hasError(warnings, "jwks/uri-not-https"),
        "PRODUCTION must reject a cleartext JWKS trust root, not merely warn");
  }

  @Test
  @DisplayName("R11/ER31: loopback http is NOT an error in DEVELOPMENT when -Djcustos.dev=true is set")
  void nonHttpsJwksUriIsNotErrorInDevelopment() {
    System.setProperty("jcustos.dev", "true");
    try {
      List<JCustosBootstrapWarning> warnings = new TestBootstrap()
          .mode(JCustosBootstrapMode.DEVELOPMENT)
          .jwt(j -> j.jwksUri(URI.create("http://localhost/jwks"))
              .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
          .applyJwt();
      assertFalse(hasError(warnings, "jwks/uri-not-https"),
          "DEVELOPMENT keeps loopback http at INFO with the dev flag, as the JWKS client does");
    } finally {
      System.clearProperty("jcustos.dev");
    }
  }

  @Test
  @DisplayName("ER31: loopback http without -Djcustos.dev=true is an ERROR in DEVELOPMENT, not an exception")
  void loopbackJwksWithoutDevFlagIsErrorInDevelopment() {
    System.clearProperty("jcustos.dev");
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .mode(JCustosBootstrapMode.DEVELOPMENT)
        .jwt(j -> j.jwksUri(URI.create("http://localhost/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
        .applyJwt();
    assertTrue(hasError(warnings, "jwks/uri-not-https"),
        "the JWKS client refuses loopback http without the flag; the bootstrap must say so");
  }

  @Test
  @DisplayName("ER31: http to a non-loopback host is an ERROR in DEVELOPMENT even with the dev flag")
  void remoteHttpJwksIsErrorInDevelopment() {
    System.setProperty("jcustos.dev", "true");
    try {
      List<JCustosBootstrapWarning> warnings = new TestBootstrap()
          .mode(JCustosBootstrapMode.DEVELOPMENT)
          .jwt(j -> j.jwksUri(URI.create("http://idp.example/jwks"))
              .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
          .applyJwt();
      assertTrue(hasError(warnings, "jwks/uri-not-https"),
          "the dev flag never admits cleartext to a remote JWKS");
    } finally {
      System.clearProperty("jcustos.dev");
    }
  }

  @Test
  @DisplayName("RF28: an https JWKS URI without a host is an ERROR, not an exception out of the validator factory")
  void hostlessHttpsJwksUriIsError() {
    for (String uri : List.of("https:///jwks", "https:jwks")) {
      for (JCustosBootstrapMode mode : JCustosBootstrapMode.values()) {
        List<JCustosBootstrapWarning> warnings = new TestBootstrap()
            .mode(mode)
            .jwt(j -> j.jwksUri(URI.create(uri))
                .algorithmProfile(AlgorithmProfile.STRICT_MODERN).issuer("https://idp.example/"))
            .applyJwt();
        assertTrue(hasError(warnings, "jwks/uri-not-https"), uri + " in " + mode + ": " + warnings);
        assertFalse(warnings.stream().anyMatch(w -> w.code().equals("jwt/factory-missing")),
            "the validator must not be built for a URI the JWKS client refuses: " + warnings);
        JCustosBootstrapWarning finding = warnings.stream()
            .filter(w -> w.code().equals("jwks/uri-not-https")).findFirst().orElseThrow();
        assertTrue(finding.message().contains("the endpoint must use https://"), finding.message());
      }
    }
  }

  @Test
  @DisplayName("RF28: https to a loopback host is no finding with or without the flag")
  void httpsLoopbackJwksUriIsNoFinding() {
    System.setProperty("jcustos.dev", "true");
    try {
      List<JCustosBootstrapWarning> warnings = new TestBootstrap()
          .mode(JCustosBootstrapMode.PRODUCTION)
          .jwt(j -> j.jwksUri(URI.create("https://localhost:8443/jwks"))
              .algorithmProfile(AlgorithmProfile.STRICT_MODERN).issuer("https://idp.example/"))
          .applyJwt();
      assertFalse(warnings.stream().anyMatch(w -> w.code().equals("jwks/uri-not-https")),
          "the flag must not turn a real https endpoint into a development-only one: " + warnings);
    } finally {
      System.clearProperty("jcustos.dev");
    }
  }

  @Test
  @DisplayName("RF28: loopback http with the flag is an ERROR in PRODUCTION and an INFO in DEVELOPMENT")
  void loopbackHttpJwksUriWithFlagByMode() {
    System.setProperty("jcustos.dev", "true");
    try {
      for (JCustosBootstrapMode mode : JCustosBootstrapMode.values()) {
        List<JCustosBootstrapWarning> warnings = new TestBootstrap()
            .mode(mode)
            .jwt(j -> j.jwksUri(URI.create("http://127.0.0.1:8080/jwks"))
                .algorithmProfile(AlgorithmProfile.STRICT_MODERN).issuer("https://idp.example/"))
            .applyJwt();
        Severity expected = mode == JCustosBootstrapMode.PRODUCTION || mode == JCustosBootstrapMode.STRICT
            ? Severity.ERROR : Severity.INFO;
        assertTrue(warnings.stream().anyMatch(w -> w.code().equals("jwks/uri-not-https")
            && w.severity() == expected), mode + ": " + warnings);
      }
    } finally {
      System.clearProperty("jcustos.dev");
    }
  }

  @Test
  @DisplayName("the jwksUri path needs a JwtValidatorFactory — absent in dx itself (Nimbus-free)")
  void factoryMissingWhenJwtModuleAbsent() {
    // jCustos-dx does not depend on jCustos-jwt, so no factory is on the
    // classpath here — proving the DX layer stays JOSE-free.
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN).issuer("https://idp.example/"))
        .applyJwt();
    assertTrue(hasError(warnings, "jwt/factory-missing"));
  }

  @Test
  @DisplayName("the CUSTOM profile without an explicit allow-list fails gracefully, not by exception (RF02)")
  void customProfileFailsGracefully() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.CUSTOM))
        .applyJwt();
    assertTrue(hasError(warnings, "jwt/custom-profile-needs-allow-list"));
  }
}
