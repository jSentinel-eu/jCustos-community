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

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.identity.oidc.RpInitiatedLogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The handler's {@code Origin} check is {@link RestOriginGuard#originAccepted(RestRequest)}
 * since 00.84.00 (CSRF, CWE-352). The tests of {@code OidcLogoutHandlerTest} stay as they were;
 * these pin what the delegation keeps - no {@code Sec-Fetch-Site}, no body, no audit event, no
 * installed guard consulted - and the two places where the shared comparison is stricter than
 * the handler's own copy was: values that are no origin, and the allowlist's configuration.
 */
@DisplayName("OidcLogoutHandler delegates its Origin check to RestOriginGuard")
class OidcLogoutHandlerOriginGuardTest {

  private static final URI END_SESSION = URI.create("https://idp.example/logout");
  private static final URI POST_LOGOUT = URI.create("https://app.example/");

  private final List<AuditEvent> audited = new ArrayList<>();

  @AfterEach
  void reset() {
    RestOriginGuard.reset();
    JCustosServiceResolver.resetAll();
  }

  private static OidcLogoutHandler handler() {
    return new OidcLogoutHandler(END_SESSION,
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(POST_LOGOUT)),
        OidcLogoutHandler.hintFrom(request -> "ID-TOKEN", POST_LOGOUT));
  }

  @Test
  @DisplayName("Sec-Fetch-Site does not decide: a matching Origin passes, a foreign one is 403, a missing one passes")
  void secFetchSite_isNotConsulted() {
    assertEquals(HttpStatus.FOUND.code(), handle(handler(), Map.of("Host", "app.example",
        "Origin", "https://app.example", "Sec-Fetch-Site", "cross-site")).status);
    assertEquals(HttpStatus.FORBIDDEN.code(), handle(handler(), Map.of("Host", "app.example",
        "Origin", "https://attacker.example", "Sec-Fetch-Site", "same-origin")).status);
    assertEquals(HttpStatus.FOUND.code(), handle(handler(), Map.of("Host", "app.example",
        "Sec-Fetch-Site", "cross-site")).status, "no Origin, as before");
  }

  @Test
  @DisplayName("the 403 has no body and is not audited, and an installed guard is not consulted - as before")
  void refusal_isUnchanged() {
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        audited.add(event);
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return List.copyOf(audited);
      }
    });
    RestOriginGuard.install(RestOriginGuard.sameOrigin().withMissingHeaders(RestOriginGuard.MissingHeaders.REFUSE));

    Captured refused = handle(handler(), Map.of("Host", "app.example", "Origin", "https://attacker.example"));
    Captured noHeaders = handle(handler(), Map.of());

    assertEquals(HttpStatus.FORBIDDEN.code(), refused.status);
    assertNull(refused.body);
    assertNull(refused.headers.get("Location"));
    assertEquals(HttpStatus.FOUND.code(), noHeaders.status, "the installed strict guard is not the handler's");
    assertTrue(audited.isEmpty(), audited.toString());
  }

  @Test
  @DisplayName("stricter: an Origin with user information, a path or another scheme no longer passes for the own host")
  void valuesThatAreNoOrigin_areRefused() {
    for (String value : List.of("https://attacker.example@app.example", "https://app.example/x",
        "ftp://app.example")) {
      assertEquals(HttpStatus.FORBIDDEN.code(),
          handle(handler(), Map.of("Host", "app.example", "Origin", value)).status, value);
    }
  }

  @Test
  @DisplayName("stricter: the allowlist refuses a value with a path; a trailing slash is still an origin")
  void allowlistConfiguration() {
    assertThrows(IllegalArgumentException.class,
        () -> handler().withAllowedOrigins(Set.of("https://app.example/login")));
    assertEquals(HttpStatus.FOUND.code(), handle(handler().withAllowedOrigins(Set.of("https://app.example/")),
        Map.of("Host", "internal:8080", "Origin", "https://app.example")).status);
  }

  private static Captured handle(OidcLogoutHandler handler, Map<String, String> headers) {
    Captured response = new Captured();
    handler.handle(new RestRequest() {
      @Override public String method() {
        return "POST";
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
    }, response);
    return response;
  }

  private static final class Captured implements RestResponse {
    int status;
    String body;
    final Map<String, String> headers = new HashMap<>();

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
}
