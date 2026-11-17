package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName(".oauth2(...) sub-builder recording + STRICT validation (V00.77)")
class OAuth2BootstrapTest {

  /** Test-only bootstrap exposing the protected OAuth2 apply pass. */
  static final class TestBootstrap extends AbstractJCustosBootstrap<TestBootstrap> {
    final List<RegisteredJCustosService> services = new ArrayList<>();

    List<JCustosBootstrapWarning> applyOauth2() {
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyOAuth2Configuration(services, warnings);
      return warnings;
    }
  }

  private static boolean has(List<JCustosBootstrapWarning> warnings, String code, Severity sev) {
    return warnings.stream().anyMatch(w -> w.code().equals(code) && w.severity() == sev);
  }

  @Test
  @DisplayName("an empty .oauth2(o -> {}) is silent")
  void emptyIsSilent() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap().oauth2(o -> { }).applyOauth2();
    assertTrue(warnings.isEmpty(), "empty oauth2 block must not emit findings");
  }

  @Test
  @DisplayName("a configuration without .clientId(...) is a STRICT-class error")
  void missingClientId() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.tokenEndpoint(URI.create("https://idp.example/token"))).applyOauth2();
    assertTrue(has(warnings, "oauth2/missing-client-id", Severity.ERROR));
  }

  @Test
  @DisplayName("a configuration without .tokenEndpoint(...) is a STRICT-class error")
  void missingTokenEndpoint() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp").authorizationEndpoint(URI.create("https://idp.example/authorize")))
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/missing-token-endpoint", Severity.ERROR));
  }

  @Test
  @DisplayName("a non-https, non-loopback redirect URI is a STRICT-class error")
  void redirectUriNotHttps() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("http://app.example/callback"))
            .scope("openid"))
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/redirect-uri-not-https", Severity.ERROR));
  }

  @Test
  @DisplayName("a http://localhost redirect URI is accepted (local development)")
  void loopbackRedirectUriAccepted() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("http://localhost:8080/callback"))
            .scope("openid"))
        .applyOauth2();
    assertFalse(has(warnings, "oauth2/redirect-uri-not-https", Severity.ERROR),
        "loopback http must be allowed");
  }

  @Test
  @DisplayName("loopback redirect URIs per RFC 8252: [::1] and all of 127.0.0.0/8 are accepted without -Djcustos.dev, look-alikes are not")
  void loopbackRedirectUrisFollowTheSharedLoopbackRule() {
    assertFalse(EndpointSecurity.devModeEnabled(), "the test must run without the dev flag");
    for (String accepted : List.of("http://[::1]:8080/callback", "http://127.0.0.2:8080/callback",
        "http://127.255.0.9/callback", "http://LOCALHOST:8080/callback")) {
      assertFalse(has(redirect(accepted), "oauth2/redirect-uri-not-https", Severity.ERROR),
          accepted + " is a loopback redirect URI");
    }
    for (String refused : List.of("http://127.0.0.1.example.com/callback",
        "http://[::2]/callback", "http://localhost.example/callback", "http://10.0.0.1/callback",
        "ftp://127.0.0.1/callback")) {
      assertTrue(has(redirect(refused), "oauth2/redirect-uri-not-https", Severity.ERROR),
          refused + " must be refused");
    }
  }

  private static List<JCustosBootstrapWarning> redirect(String uri) {
    return new TestBootstrap()
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create(uri))
            .scope("openid"))
        .applyOauth2();
  }

  @Test
  @DisplayName("an empty scope set is an INFO finding, not an error")
  void scopeEmptyIsInfo() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp").tokenEndpoint(URI.create("https://idp.example/token")))
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/scope-empty", Severity.INFO));
    assertFalse(warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR));
  }

  @Test
  @DisplayName("a complete configuration records an OAuth2State service with no errors")
  void completeConfigurationRegisters() {
    TestBootstrap bootstrap = new TestBootstrap();
    List<JCustosBootstrapWarning> warnings = bootstrap
        .oauth2(o -> o.clientId("rp")
            .authorizationEndpoint(URI.create("https://idp.example/authorize"))
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid", "profile"))
        .applyOauth2();
    assertFalse(warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR));
    assertTrue(bootstrap.services.stream().anyMatch(s -> "bootstrap-oauth2".equals(s.source())),
        "a complete RP config registers a bootstrap-oauth2 marker service");
  }

  @Test
  @DisplayName("JS-SEC-056: a public client with PKCE disabled is a STRICT-class error")
  void publicClientWithoutPkceIsStrictError() {
    List<JCustosBootstrapWarning> warnings = new TestBootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid")
            .pkceRequired(false)) // public client (no client auth) + PKCE off
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/public-client-without-pkce", Severity.ERROR),
        "STRICT must hard-fail a public client that opted out of PKCE");
  }
}
