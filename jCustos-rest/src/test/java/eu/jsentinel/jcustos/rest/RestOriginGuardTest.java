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
package eu.jsentinel.jcustos.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.rest.RestOriginGuard.MissingHeaders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The decision table of {@link RestOriginGuard} (CSRF, CWE-352): which state-changing requests
 * pass, which are refused, and what a refusal leaves behind - 403 through the published mapper,
 * an {@code AccessDenied} with reason {@code csrf:origin-mismatch} in the real store-backed
 * audit service, inside a correlation scope, and no handler call. Requests are hand-written
 * {@link RestRequest} records with multi-line headers.
 */
@DisplayName("RestOriginGuard (CSRF, CWE-352)")
class RestOriginGuardTest {

  private static final String APP = "app.example";
  private static final String APP_ORIGIN = "https://app.example";
  private static final String FOREIGN_ORIGIN = "https://attacker.example";
  private static final String SESSION_COOKIE = "APP_SESSION=4f1c2b9e77aa";

  private final InMemoryAuditEventStore store = new InMemoryAuditEventStore();
  private final AtomicInteger handled = new AtomicInteger();

  @BeforeEach
  void installAudit() {
    JCustosServiceResolver.setJCustosAuditService(new StoreBackedJCustosAuditService(store));
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    RestDecisionContext.reset();
    RestOriginGuard.reset();
  }

  // ── refusals ───────────────────────────────────────────────────

  @Test
  @DisplayName("a cross-origin POST with the session cookie is refused with 403, audited, and the handler does not run")
  void crossOriginPostWithCookie_isRefusedAndAudited() {
    Response response = new Response();

    RestOriginGuard.sameOrigin().guard(post(Map.of(
        "Host", List.of(APP),
        "Origin", List.of(FOREIGN_ORIGIN),
        "Sec-Fetch-Site", List.of("cross-site"),
        "Cookie", List.of(SESSION_COOKIE))), response, countingHandler());

    assertEquals(HttpStatus.FORBIDDEN.code(), response.status);
    assertEquals("Forbidden", response.body, "the default mapper's generic body");
    assertEquals(0, handled.get(), "the handler must not run");
    AuditEnvelope envelope = singleEnvelope();
    AccessDenied denied = assertInstanceOf(AccessDenied.class, envelope.event());
    assertEquals(RestOriginGuard.REASON_ORIGIN_MISMATCH, denied.reason());
    assertEquals("csrf:origin-mismatch", denied.reason());
    assertEquals("/api/documents", denied.route());
    assertNotNull(envelope.correlationId(), "the refusal is audited inside a correlation scope");
  }

  @Test
  @DisplayName("Sec-Fetch-Site: cross-site with an origin that merely starts like the own one is refused")
  void crossSiteWithMatchingLookingPrefix_isRefused() {
    for (String lookalike : List.of(
        "https://app.example.attacker.example",
        "https://app.example:443.attacker.example",
        "https://app.exampl",
        "https://evil-app.example",
        "https://app.example.")) {
      Response response = new Response();
      assertFalse(RestOriginGuard.sameOrigin().allow(post(Map.of(
          "Host", List.of(APP),
          "Origin", List.of(lookalike),
          "Sec-Fetch-Site", List.of("cross-site"))), response), lookalike);
      assertEquals(HttpStatus.FORBIDDEN.code(), response.status, lookalike);
    }
    assertEquals(5, envelopes().size(), "every refusal is audited");
  }

  @Test
  @DisplayName("the opaque origin null, values that are no origin, and several Origin or Host lines are refused")
  void malformedOrigins_areRefused() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    for (String value : List.of("null", "app.example", "https://user@app.example",
        "https://app.example/", "https://app.example/path", "https://app.example?x=1",
        "https://app.example#f", "ftp://app.example", "*")) {
      assertFalse(guard.accepts(post(Map.of("Host", List.of(APP), "Origin", List.of(value)))),
          value);
    }
    assertFalse(guard.accepts(post(Map.of("Host", List.of(APP),
        "Origin", List.of(APP_ORIGIN, FOREIGN_ORIGIN)))), "two Origin lines");
    assertFalse(guard.accepts(post(Map.of("Host", List.of(APP, "attacker.example"),
        "Origin", List.of(APP_ORIGIN)))), "two Host lines");
    assertFalse(guard.accepts(post(Map.of("Origin", List.of(APP_ORIGIN)))),
        "an Origin without a Host to compare with");
    assertFalse(guard.accepts(post(Map.of("Host", List.of("app.example/x"),
        "Origin", List.of(APP_ORIGIN)))), "a Host that is no host");
  }

  @Test
  @DisplayName("another port or another host is another origin")
  void otherPortOrHost_isRefused() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    assertFalse(guard.accepts(post(Map.of("Host", List.of(APP),
        "Origin", List.of("https://app.example:8443")))));
    assertFalse(guard.accepts(post(Map.of("Host", List.of("app.example:8443"),
        "Origin", List.of(APP_ORIGIN)))));
    assertFalse(guard.accepts(post(Map.of("Host", List.of("api.example"),
        "Origin", List.of(APP_ORIGIN)))));
  }

  @Test
  @DisplayName("Sec-Fetch-Site naming a foreign initiator without any Origin is refused - a browser sends Origin with it")
  void foreignFetchSiteWithoutOrigin_isRefused() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    for (String site : List.of("cross-site", "same-site", "unknown-value")) {
      assertFalse(guard.accepts(post(Map.of("Host", List.of(APP), "Sec-Fetch-Site", List.of(site)))),
          site);
    }
    assertFalse(guard.accepts(post(Map.of("Host", List.of(APP),
        "Sec-Fetch-Site", List.of("same-origin", "cross-site")))),
        "two lines are no vouching, and there is no Origin to fall back on");
  }

  @ParameterizedTest(name = "{0} is checked")
  @ValueSource(strings = {"POST", "PUT", "PATCH", "DELETE", "patch", "PROPFIND", ""})
  @DisplayName("every method that is not safe is checked, unknown and lower-case ones included")
  void unsafeMethods_areChecked(String method) {
    assertFalse(RestOriginGuard.sameOrigin().accepts(new HeaderRequest(method, "/api/documents",
        Map.of("Host", List.of(APP), "Origin", List.of(FOREIGN_ORIGIN)))));
  }

  @Test
  @DisplayName("a request without a method is checked")
  void nullMethod_isChecked() {
    assertFalse(RestOriginGuard.sameOrigin().accepts(new HeaderRequest(null, "/api/documents",
        Map.of("Host", List.of(APP), "Origin", List.of(FOREIGN_ORIGIN)))));
  }

  @Test
  @DisplayName("strict setting: a request without Origin and Sec-Fetch-Site is refused")
  void strictSetting_refusesMissingHeaders() {
    RestOriginGuard strict = RestOriginGuard.sameOrigin().withMissingHeaders(MissingHeaders.REFUSE);
    Response response = new Response();

    assertFalse(strict.allow(post(Map.of("Host", List.of(APP))), response));

    assertEquals(HttpStatus.FORBIDDEN.code(), response.status);
    assertEquals(RestOriginGuard.REASON_ORIGIN_MISMATCH,
        ((AccessDenied) singleEnvelope().event()).reason());
    assertEquals(MissingHeaders.REFUSE, strict.missingHeaders());
    assertTrue(strict.accepts(post(Map.of("Host", List.of(APP), "Origin", List.of(APP_ORIGIN)))),
        "the strict setting refuses only the request without either header");
  }

  // ── what passes ────────────────────────────────────────────────

  @Test
  @DisplayName("a same-origin POST passes; host and header names compare case-insensitively")
  void sameOrigin_passes() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    Response response = new Response();

    guard.guard(post(Map.of("Host", List.of(APP), "Origin", List.of(APP_ORIGIN),
        "Cookie", List.of(SESSION_COOKIE))), response, countingHandler());

    assertEquals(1, handled.get());
    assertEquals(HttpStatus.OK.code(), response.status);
    assertTrue(envelopes().isEmpty(), "a request that passes is not audited by the guard");
    assertTrue(guard.accepts(post(Map.of("host", List.of("App.Example:8443"),
        "origin", List.of("HTTPS://APP.example:8443")))));
    assertTrue(guard.accepts(post(Map.of("Host", List.of("app.example:443"),
        "Origin", List.of(APP_ORIGIN)))), "a default port in Host counts as no port");
    assertTrue(guard.accepts(post(Map.of("Host", List.of("[::1]:8080"),
        "Origin", List.of("http://[::1]:8080")))), "IPv6 literal");
  }

  @Test
  @DisplayName("Sec-Fetch-Site: same-origin or none passes without looking at Origin")
  void fetchSiteSameOriginOrNone_passes() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    assertTrue(guard.accepts(post(Map.of("Host", List.of("internal:8080"),
        "Origin", List.of(APP_ORIGIN), "Sec-Fetch-Site", List.of("same-origin")))),
        "the browser vouches, also behind a proxy that rewrote Host");
    assertTrue(guard.accepts(post(Map.of("Sec-Fetch-Site", List.of("none")))),
        "user-initiated");
    assertTrue(guard.accepts(post(Map.of("Sec-Fetch-Site", List.of(" Same-Origin ")))));
  }

  @Test
  @DisplayName("without Origin and Sec-Fetch-Site (curl, a server) the request passes by default")
  void nonBrowserClient_passesByDefault() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    assertEquals(MissingHeaders.ALLOW, guard.missingHeaders());
    assertTrue(guard.accepts(post(Map.of("Host", List.of(APP), "Authorization",
        List.of("Bearer 2f0c")))));
    assertTrue(guard.accepts(post(Map.of("Host", List.of(APP), "Origin", List.of("  ")))),
        "a blank Origin is no Origin");
  }

  @ParameterizedTest(name = "{0} is not checked")
  @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "TRACE", "get", "options"})
  @DisplayName("safe methods are untouched, even from a foreign origin and in the strict setting")
  void safeMethods_areUntouched(String method) {
    RestOriginGuard strict = RestOriginGuard.sameOrigin().withMissingHeaders(MissingHeaders.REFUSE);
    Response response = new Response();

    strict.guard(new HeaderRequest(method, "/api/documents", Map.of(
        "Host", List.of(APP), "Origin", List.of(FOREIGN_ORIGIN),
        "Sec-Fetch-Site", List.of("cross-site"))), response, countingHandler());
    strict.guard(new HeaderRequest(method, "/api/documents", Map.of()), response, countingHandler());

    assertEquals(2, handled.get());
    assertEquals(HttpStatus.OK.code(), response.status);
    assertTrue(envelopes().isEmpty());
  }

  // ── RF24: the scheme of the own origin ─────────────────────────

  @Test
  @DisplayName("RF24: an http origin for the https site's host is refused with 403 and audited as csrf:origin-mismatch")
  void httpOriginAgainstHttpsSite_isRefused() {
    Response response = new Response();

    RestOriginGuard.sameOrigin().guard(post(Map.of(
        "Host", List.of(APP),
        "Origin", List.of("http://app.example"),
        "Sec-Fetch-Site", List.of("same-site"),
        "Cookie", List.of(SESSION_COOKIE))), response, countingHandler());

    assertEquals(HttpStatus.FORBIDDEN.code(), response.status,
        "until the exit review a page served over plain http for the host passed as same-origin");
    assertEquals(0, handled.get(), "the handler must not run");
    AccessDenied denied = assertInstanceOf(AccessDenied.class, singleEnvelope().event());
    assertEquals(RestOriginGuard.REASON_ORIGIN_MISMATCH, denied.reason());

    Response own = new Response();
    RestOriginGuard.sameOrigin().guard(post(Map.of("Host", List.of(APP),
        "Origin", List.of(APP_ORIGIN), "Cookie", List.of(SESSION_COOKIE))), own, countingHandler());
    assertEquals(HttpStatus.OK.code(), own.status);
    assertEquals(1, handled.get(), "https://app.example passes");
  }

  @Test
  @DisplayName("RF24: the default expects https; http passes for a loopback host only, any port included")
  void defaultScheme_isHttpsExceptForLoopback() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    assertTrue(guard.scheme().isEmpty());
    assertFalse(guard.originAccepted(post(Map.of("Host", List.of("app.example:8080"),
        "Origin", List.of("http://app.example:8080")))), "plain http to another host");
    assertFalse(guard.originAccepted(post(Map.of("Host", List.of("10.0.0.5:8080"),
        "Origin", List.of("http://10.0.0.5:8080")))), "a private address is no loopback host");
    for (String host : List.of("localhost:8080", "127.0.0.1:8080", "[::1]:8080", "LOCALHOST:8080")) {
      String origin = "http://" + host.toLowerCase(java.util.Locale.ROOT);
      assertTrue(guard.originAccepted(post(Map.of("Host", List.of(host), "Origin", List.of(origin)))),
          origin + " - no other machine can answer for a loopback host");
    }
    assertFalse(guard.originAccepted(post(Map.of("Host", List.of("localhost.example:8080"),
        "Origin", List.of("http://localhost.example:8080")))), "a lookalike of localhost");
    assertTrue(guard.originAccepted(post(Map.of("Host", List.of("localhost:8443"),
        "Origin", List.of("https://localhost:8443")))), "https always");
    assertFalse(guard.originAccepted(post(Map.of("Host", List.of("app.example"),
        "Origin", List.of("ftp://app.example")))), "neither http nor https");
  }

  @Test
  @DisplayName("RF24: withScheme decides the scheme exactly - http for a plain-http site, https without the loopback exception")
  void withScheme_comparesExactly() {
    RestOriginGuard plain = RestOriginGuard.sameOrigin().withScheme("HTTP");
    assertEquals("http", plain.scheme().orElseThrow());
    assertTrue(plain.originAccepted(post(Map.of("Host", List.of("intranet.example:8080"),
        "Origin", List.of("http://intranet.example:8080")))));
    assertFalse(plain.originAccepted(post(Map.of("Host", List.of("intranet.example:8080"),
        "Origin", List.of("https://intranet.example:8080")))), "another scheme is another origin");

    RestOriginGuard secure = RestOriginGuard.sameOrigin().withScheme("https");
    assertFalse(secure.originAccepted(post(Map.of("Host", List.of("localhost:8080"),
        "Origin", List.of("http://localhost:8080")))), "explicit https has no loopback exception");
    assertTrue(secure.originAccepted(post(Map.of("Host", List.of(APP), "Origin", List.of(APP_ORIGIN)))));

    assertEquals(Set.of(APP_ORIGIN), plain.withAllowedOrigins(Set.of(APP_ORIGIN)).allowedOrigins());
    assertTrue(plain.withAllowedOrigins(Set.of(APP_ORIGIN)).originAccepted(post(Map.of(
        "Host", List.of("internal:8080"), "Origin", List.of(APP_ORIGIN)))),
        "an allowlist entry carries its own scheme");
    assertEquals("http", plain.withMissingHeaders(MissingHeaders.REFUSE).withAllowedOrigins(
        Set.of(APP_ORIGIN)).scheme().orElseThrow(), "settings are kept");
    for (String notAScheme : List.of("ftp", "", "https://", "ws")) {
      assertThrows(IllegalArgumentException.class, () -> plain.withScheme(notAScheme), notAScheme);
    }
    assertThrows(NullPointerException.class, () -> plain.withScheme(null));
  }

  // ── RF30: cross-origin acceptance for the DX cross-check ────────

  @Test
  @DisplayName("RF30: acceptsCrossOrigin is the allowlist membership; a Host-comparing guard accepts no other origin")
  void acceptsCrossOrigin() {
    RestOriginGuard listed = RestOriginGuard.sameOrigin()
        .withAllowedOrigins(Set.of(APP_ORIGIN, "https://partner.example"));
    assertTrue(listed.acceptsCrossOrigin("https://partner.example"));
    assertTrue(listed.acceptsCrossOrigin("HTTPS://Partner.Example:443/"), "normalised like the list");
    assertFalse(listed.acceptsCrossOrigin("http://partner.example"), "another scheme");
    assertFalse(listed.acceptsCrossOrigin("https://other.example"));
    assertFalse(listed.acceptsCrossOrigin("*"));
    assertFalse(listed.acceptsCrossOrigin(null));
    assertFalse(RestOriginGuard.sameOrigin().acceptsCrossOrigin("https://partner.example"),
        "the origin of Host is the only one a same-origin guard accepts");
  }

  // ── allowlist ──────────────────────────────────────────────────

  @Test
  @DisplayName("allowed origins are compared exactly and replace the comparison with Host")
  void allowedOrigins_replaceTheHostComparison() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin()
        .withAllowedOrigins(Set.of("https://App.Example:443", "https://spa.example/"));

    assertEquals(Set.of(APP_ORIGIN, "https://spa.example"), guard.allowedOrigins());
    assertTrue(guard.accepts(post(Map.of("Host", List.of("internal:8080"),
        "Origin", List.of(APP_ORIGIN)))));
    assertTrue(guard.accepts(post(Map.of("Host", List.of("internal:8080"),
        "Origin", List.of("https://spa.example"), "Sec-Fetch-Site", List.of("cross-site")))),
        "a listed origin passes as a cross-site request (credentialed CORS)");
    assertFalse(guard.accepts(post(Map.of("Host", List.of("internal:8080"),
        "Origin", List.of("http://internal:8080")))), "the internal host is no listed origin");
    assertFalse(guard.accepts(post(Map.of("Host", List.of(APP),
        "Origin", List.of("http://app.example")))), "another scheme is another origin");
    assertFalse(guard.accepts(post(Map.of("Origin", List.of("https://spa.example.attacker.example")))));
    assertEquals(MissingHeaders.REFUSE, guard.withMissingHeaders(MissingHeaders.REFUSE)
        .withAllowedOrigins(Set.of(APP_ORIGIN)).missingHeaders(), "settings are kept");
  }

  @Test
  @DisplayName("an allowlist must name origins: empty, null, *, paths, queries and user information are refused at configuration time")
  void allowedOrigins_areValidated() {
    RestOriginGuard guard = RestOriginGuard.sameOrigin();
    assertThrows(IllegalArgumentException.class, () -> guard.withAllowedOrigins(Set.of()));
    for (String notAnOrigin : List.of("null", "*", "app.example", "https://app.example/login",
        "https://app.example?x", "https://user@app.example", "https://app.example#x", "")) {
      assertThrows(IllegalArgumentException.class,
          () -> guard.withAllowedOrigins(Set.of(notAnOrigin)), notAnOrigin);
    }
    assertThrows(NullPointerException.class, () -> guard.withAllowedOrigins(null));
    assertThrows(NullPointerException.class, () -> guard.withMissingHeaders(null));
  }

  // ── rendering, audit failure, installation ─────────────────────

  @Test
  @DisplayName("the refusal is rendered by the published mapper")
  void refusal_usesThePublishedMapper() {
    List<AuthorizationDecision> rendered = new ArrayList<>();
    RestDecisionContext.publish((decision, response) -> {
      rendered.add(decision);
      response.status(HttpStatus.FORBIDDEN.code());
      response.body("{\"title\":\"Forbidden\"}");
      return false;
    });
    Response response = new Response();

    assertFalse(RestOriginGuard.sameOrigin().allow(post(Map.of("Host", List.of(APP),
        "Origin", List.of(FOREIGN_ORIGIN))), response));

    assertEquals(List.of(AuthorizationDecision.forbidden(RestOriginGuard.REASON_ORIGIN_MISMATCH)),
        rendered);
    assertEquals("{\"title\":\"Forbidden\"}", response.body);
  }

  @Test
  @DisplayName("the mapper renders, it does not decide: a mapper that answers true does not let the request through")
  void mapperCannotOverruleTheRefusal() {
    RestDecisionContext.publish((decision, response) -> true);
    Response response = new Response();

    RestOriginGuard.sameOrigin().guard(post(Map.of("Host", List.of(APP),
        "Origin", List.of(FOREIGN_ORIGIN))), response, countingHandler());

    assertEquals(0, handled.get());
  }

  @Test
  @DisplayName("a failing audit sink does not let a refused request through")
  void failingAuditSink_keepsTheRefusal() {
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        throw new IllegalStateException("audit store down");
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return List.of();
      }
    });
    Response response = new Response();

    RestOriginGuard.sameOrigin().guard(post(Map.of("Host", List.of(APP),
        "Origin", List.of(FOREIGN_ORIGIN))), response, countingHandler());

    assertEquals(HttpStatus.FORBIDDEN.code(), response.status);
    assertEquals(0, handled.get());
  }

  @Test
  @DisplayName("install, installed and reset hold one guard for the process")
  void installation() {
    assertTrue(RestOriginGuard.installed().isEmpty());
    RestOriginGuard first = RestOriginGuard.sameOrigin();
    RestOriginGuard second = RestOriginGuard.sameOrigin().withMissingHeaders(MissingHeaders.REFUSE);

    RestOriginGuard.install(first);
    assertSame(first, RestOriginGuard.installed().orElseThrow());
    RestOriginGuard.install(second);
    assertSame(second, RestOriginGuard.installed().orElseThrow(), "a later install replaces");
    RestOriginGuard.reset();
    assertTrue(RestOriginGuard.installed().isEmpty());
    assertThrows(NullPointerException.class, () -> RestOriginGuard.install(null));
  }

  @Test
  @DisplayName("originAccepted is the Origin comparison alone: no method, no Sec-Fetch-Site, no strict setting")
  void originAccepted_isTheOriginStepAlone() {
    RestOriginGuard strict = RestOriginGuard.sameOrigin().withMissingHeaders(MissingHeaders.REFUSE);
    assertTrue(strict.originAccepted(post(Map.of())), "no Origin is accepted");
    assertTrue(strict.originAccepted(new HeaderRequest("GET", "/", Map.of(
        "Host", List.of(APP), "Origin", List.of(APP_ORIGIN)))));
    assertFalse(strict.originAccepted(new HeaderRequest("GET", "/", Map.of(
        "Host", List.of(APP), "Origin", List.of(FOREIGN_ORIGIN)))), "the method is not looked at");
    assertFalse(strict.originAccepted(post(Map.of("Host", List.of("internal"),
        "Origin", List.of(APP_ORIGIN), "Sec-Fetch-Site", List.of("same-origin")))),
        "Sec-Fetch-Site is not looked at");
  }

  @Test
  @DisplayName("an adapter whose headerValues reports nothing cannot hide the Origin: the single-valued map is asked as well")
  void inconsistentAdapter_cannotHideTheOrigin() {
    RestRequest blindLines = new RestRequest() {
      @Override public String method() {
        return "POST";
      }

      @Override public String path() {
        return "/api/documents";
      }

      @Override public Map<String, String> headers() {
        return Map.of("Host", APP, "Origin", FOREIGN_ORIGIN);
      }

      @Override public List<String> headerValues(String name) {
        return List.of();
      }

      @Override public Map<String, String> queryParameters() {
        return Map.of();
      }
    };
    assertFalse(RestOriginGuard.sameOrigin().accepts(blindLines));
  }

  // ── fixtures ───────────────────────────────────────────────────

  private RestHandler countingHandler() {
    return (request, response) -> handled.incrementAndGet();
  }

  private List<AuditEnvelope> envelopes() {
    return store.query(TenantId.DEFAULT, AuditQuery.all());
  }

  private AuditEnvelope singleEnvelope() {
    List<AuditEnvelope> envelopes = envelopes();
    assertEquals(1, envelopes.size(), envelopes.toString());
    return envelopes.getFirst();
  }

  private static RestRequest post(Map<String, List<String>> lines) {
    return new HeaderRequest("POST", "/api/documents", lines);
  }

  /** A request with multi-line headers; names compare case-insensitively, as on the wire. */
  record HeaderRequest(String method, String path, Map<String, List<String>> lines)
      implements RestRequest {

    @Override
    public Map<String, String> headers() {
      Map<String, String> joined = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
      lines.forEach((name, values) -> joined.put(name, String.join(", ", values)));
      return joined;
    }

    @Override
    public List<String> headerValues(String name) {
      return lines.entrySet().stream()
          .filter(entry -> entry.getKey().equalsIgnoreCase(name))
          .map(Map.Entry::getValue)
          .findFirst()
          .orElse(List.of());
    }

    @Override
    public Map<String, String> queryParameters() {
      return Map.of();
    }
  }

  static final class Response implements RestResponse {
    int status = HttpStatus.OK.code();
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String value) {
      this.body = value;
    }

    @Override
    public void header(String name, String value) {
      headers.put(name, value);
    }
  }
}
