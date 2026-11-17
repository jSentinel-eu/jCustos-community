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
package eu.jsentinel.jcustos.identity.oidc.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.identity.oidc.RpInitiatedLogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("OidcLogoutHandler (REST) — 302 redirect to the end_session endpoint, POST and same origin only")
class OidcLogoutHandlerTest {

  private static final URI END_SESSION = URI.create("https://idp.example/logout");
  private static final URI POST_LOGOUT = URI.create("https://app.example/");

  private final AtomicInteger hintResolved = new AtomicInteger();

  /** JS-SEC-089: the application names its post-logout target, as it has to since 00.84.00. */
  private OidcLogoutHandler handler() {
    return new OidcLogoutHandler(END_SESSION,
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(POST_LOGOUT)),
        OidcLogoutHandler.hintFrom(req -> {
          hintResolved.incrementAndGet();
          return "ID-TOKEN";
        }, POST_LOGOUT));
  }

  private static RestRequest request(String method, Map<String, String> headers) {
    return new RestRequest() {
      @Override public String method() {
        return method;
      }

      @Override public String path() {
        return "/logout";
      }

      @Override public Map<String, String> headers() {
        return headers;
      }

      @Override public Map<String, String> queryParameters() {
        return Map.of();
      }
    };
  }

  private static final class CapturingResponse implements RestResponse {
    int status;
    final Map<String, String> headers = new HashMap<>();
    String body;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String value) {
      this.body = value;
    }

    @Override public void header(String name, String value) {
      headers.put(name, value);
    }
  }

  private CapturingResponse handle(OidcLogoutHandler handler, String method, Map<String, String> headers) {
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(method, headers), response);
    return response;
  }

  @Test
  @DisplayName("POST redirects to the end_session URL with id_token_hint + post_logout_redirect_uri")
  void redirectsToEndSession() {
    CapturingResponse response = handle(handler(), "POST", Map.of());

    assertEquals(HttpStatus.FOUND.code(), response.status);
    String location = response.headers.get("Location");
    assertTrue(location.startsWith("https://idp.example/logout?"), location);
    assertTrue(location.contains("id_token_hint=ID-TOKEN"), location);
    assertTrue(location.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example%2F"), location);
  }

  @ParameterizedTest(name = "{0} is refused with 405 and Allow: POST")
  @ValueSource(strings = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "get"})
  @DisplayName("JS-SEC-147 (CWE-352): only POST logs out - a link, an image tag or a prefetch does not")
  void otherMethods_areRefused(String method) {
    CapturingResponse response = handle(handler(), method, Map.of());

    assertEquals(HttpStatus.METHOD_NOT_ALLOWED.code(), response.status);
    assertEquals("POST", response.headers.get("Allow"));
    assertNull(response.headers.get("Location"), "no redirect, and above all no id_token_hint");
    assertEquals(0, hintResolved.get(), "the id token is not even looked up");
  }

  @Test
  @DisplayName("JS-SEC-147 (CWE-352): a POST from a foreign origin is refused with 403")
  void foreignOrigin_isRefused() {
    CapturingResponse response = handle(handler(), "POST",
        Map.of("Host", "app.example", "Origin", "https://evil.example"));

    assertEquals(HttpStatus.FORBIDDEN.code(), response.status);
    assertNull(response.headers.get("Location"));
    assertEquals(0, hintResolved.get());
  }

  @Test
  @DisplayName("a POST from the application's own origin passes; header names are matched case-insensitively")
  void sameOrigin_passes() {
    assertEquals(HttpStatus.FOUND.code(),
        handle(handler(), "POST", Map.of("Host", "app.example", "Origin", "https://app.example")).status);
    assertEquals(HttpStatus.FOUND.code(),
        handle(handler(), "POST", Map.of("host", "App.Example:8443", "origin", "https://app.example:8443")).status);
    assertEquals(HttpStatus.FOUND.code(),
        handle(handler(), "POST", Map.of("Host", "app.example:443", "Origin", "https://app.example")).status);
  }

  @Test
  @DisplayName("an opaque or unparsable Origin, or an Origin without a Host to compare with, is refused")
  void opaqueOrigin_isRefused() {
    assertEquals(HttpStatus.FORBIDDEN.code(),
        handle(handler(), "POST", Map.of("Host", "app.example", "Origin", "null")).status);
    assertEquals(HttpStatus.FORBIDDEN.code(),
        handle(handler(), "POST", Map.of("Host", "app.example", "Origin", "app.example")).status);
    assertEquals(HttpStatus.FORBIDDEN.code(),
        handle(handler(), "POST", Map.of("Origin", "https://app.example")).status);
    assertEquals(HttpStatus.FORBIDDEN.code(),
        handle(handler(), "POST", Map.of("Host", "app.example", "Origin", "https://app.example:8443")).status,
        "another port is another origin");
  }

  @Test
  @DisplayName("configured origins replace the Host comparison (application behind a proxy)")
  void allowedOrigins_decide() {
    OidcLogoutHandler handler = handler().withAllowedOrigins(Set.of("https://App.Example:443"));

    assertEquals(HttpStatus.FOUND.code(),
        handle(handler, "POST", Map.of("Host", "internal:8080", "Origin", "https://app.example")).status);
    assertEquals(HttpStatus.FORBIDDEN.code(),
        handle(handler, "POST", Map.of("Host", "internal:8080", "Origin", "http://internal:8080")).status,
        "the internal host is not an origin a browser page of the application has");
    assertEquals(HttpStatus.FOUND.code(), handle(handler, "POST", Map.of()).status,
        "a client that sends no Origin is no browser page");
    assertFalse(handle(handler, "GET", Map.of("Origin", "https://app.example")).headers.containsKey("Location"));

    assertThrows(IllegalArgumentException.class, () -> handler().withAllowedOrigins(Set.of()));
    assertThrows(IllegalArgumentException.class, () -> handler().withAllowedOrigins(Set.of("app.example")));
  }

  // ── JS-SEC-089 (CWE-601): no allowlist, no post-logout redirect ──

  @Test
  @DisplayName("JS-SEC-089: the two-argument constructor no longer forwards a post_logout_redirect_uri")
  void twoArgumentConstructor_refusesTheRedirectTarget() {
    OidcLogoutHandler handler = new OidcLogoutHandler(END_SESSION, OidcLogoutHandler.hintFrom(
        req -> "ID-TOKEN", URI.create("https://attacker.example/harvest")));
    CapturingResponse response = new CapturingResponse();

    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> handler.handle(request("POST", Map.of()), response),
        "until 00.84.00 this constructor fell back to permitAll() without a word");

    assertTrue(refused.getMessage().contains("no allowlist is configured"), refused.getMessage());
    assertNull(response.headers.get("Location"), "no redirect to the provider with a foreign target");
  }

  @Test
  @DisplayName("JS-SEC-089: the two-argument constructor still logs out at the provider when no target is asked for")
  void twoArgumentConstructor_logoutWithoutTarget() {
    OidcLogoutHandler handler = new OidcLogoutHandler(END_SESSION,
        OidcLogoutHandler.hintFrom(req -> "ID-TOKEN", null));

    CapturingResponse response = handle(handler, "POST", Map.of());

    assertEquals(HttpStatus.FOUND.code(), response.status);
    assertEquals("https://idp.example/logout?id_token_hint=ID-TOKEN", response.headers.get("Location"));
  }

  @Test
  @DisplayName("JS-SEC-089: an injected allowlist forwards its own target and refuses a foreign one")
  void injectedAllowlist_refusesAForeignTarget() {
    OidcLogoutHandler handler = new OidcLogoutHandler(END_SESSION,
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(POST_LOGOUT)),
        request -> new LogoutRequest("ID-TOKEN",
            Optional.of(URI.create("https://app.example.attacker.example/")), Optional.empty()));
    CapturingResponse response = new CapturingResponse();

    assertThrows(IllegalArgumentException.class,
        () -> handler.handle(request("POST", Map.of()), response));
    assertNull(response.headers.get("Location"));
  }
}
