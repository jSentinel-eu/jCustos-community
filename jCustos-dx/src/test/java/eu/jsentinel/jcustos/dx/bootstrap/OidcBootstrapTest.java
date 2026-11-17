package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.net.EndpointSecurity;
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

@DisplayName(".oidc(...) sub-builder recording + STRICT validation (V00.78)")
class OidcBootstrapTest {

  static final class TestBootstrap extends AbstractJCustosBootstrap<TestBootstrap> {
    final List<RegisteredJCustosService> services = new ArrayList<>();

    List<JCustosBootstrapWarning> applyOidc() {
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyOidcConfiguration(services, warnings);
      return warnings;
    }
  }

  private static boolean has(List<JCustosBootstrapWarning> w, String code, Severity sev) {
    return w.stream().anyMatch(x -> x.code().equals(code) && x.severity() == sev);
  }

  @Test
  @DisplayName("an empty .oidc(o -> {}) is silent")
  void emptyIsSilent() {
    assertTrue(new TestBootstrap().oidc(o -> { }).applyOidc().isEmpty());
  }

  @Test
  @DisplayName("loopback redirect URIs per RFC 8252: [::1] and 127.0.0.2 are accepted without -Djcustos.dev")
  void loopbackRedirectUrisFollowTheSharedLoopbackRule() {
    assertFalse(EndpointSecurity.devModeEnabled(), "the test must run without the dev flag");
    for (String accepted : List.of("http://[::1]:8080/cb", "http://127.0.0.2:8080/cb")) {
      List<JCustosBootstrapWarning> w = new TestBootstrap()
          .oidc(o -> o.issuer("https://idp").clientId("app").scope("openid")
              .redirectUri(URI.create(accepted)))
          .applyOidc();
      assertFalse(has(w, "oidc/redirect-uri-not-https", Severity.ERROR), accepted);
    }
    List<JCustosBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("openid")
            .redirectUri(URI.create("http://127.0.0.1.example.com/cb")))
        .applyOidc();
    assertTrue(has(w, "oidc/redirect-uri-not-https", Severity.ERROR));
  }

  @Test
  @DisplayName("missing issuer is a STRICT error")
  void missingIssuer() {
    List<JCustosBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.clientId("app").scope("openid")).applyOidc();
    assertTrue(has(w, "oidc/missing-issuer", Severity.ERROR));
  }

  @Test
  @DisplayName("missing client id is a STRICT error")
  void missingClientId() {
    List<JCustosBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").scope("openid")).applyOidc();
    assertTrue(has(w, "oidc/missing-client-id", Severity.ERROR));
  }

  @Test
  @DisplayName("a scope without openid is a STRICT error (spec violation)")
  void scopeWithoutOpenid() {
    List<JCustosBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("profile")).applyOidc();
    assertTrue(has(w, "oidc/scope-without-openid", Severity.ERROR));
  }

  @Test
  @DisplayName("a non-https, non-loopback redirect URI is a STRICT error")
  void redirectUriNotHttps() {
    List<JCustosBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("openid")
            .redirectUri(URI.create("http://app.example/cb"))).applyOidc();
    assertTrue(has(w, "oidc/redirect-uri-not-https", Severity.ERROR));
  }

  @Test
  @DisplayName("logoutEnabled without a post-logout redirect URI is a STRICT error")
  void logoutWithoutPostLogoutRedirect() {
    List<JCustosBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("openid")
            .logoutEnabled(true)).applyOidc();
    assertTrue(has(w, "oidc/logout-without-post-logout-redirect-uri", Severity.ERROR));
  }

  @Test
  @DisplayName("a complete configuration registers the bootstrap-oidc marker with no errors")
  void completeConfiguration() {
    TestBootstrap b = new TestBootstrap();
    List<JCustosBootstrapWarning> w = b
        .oidc(o -> o.issuer("https://idp.example/realm").clientId("app")
            .redirectUri(URI.create("https://app.example/callback"))
            .scope("openid", "profile", "email")
            .logoutEnabled(true).postLogoutRedirectUri(URI.create("https://app.example/")))
        .applyOidc();
    assertFalse(w.stream().anyMatch(x -> x.severity() == Severity.ERROR));
    assertTrue(b.services.stream().anyMatch(s -> "bootstrap-oidc".equals(s.source())));
  }
}
