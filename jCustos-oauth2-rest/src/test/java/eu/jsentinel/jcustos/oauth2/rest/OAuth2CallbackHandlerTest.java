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
package eu.jsentinel.jcustos.oauth2.rest;

/*-
 * #%L
 * jCustos OAuth2 — REST callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oauth2.HttpAuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.HttpTokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.JdkInMemoryStateStore;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OAuth2CallbackHandler (REST) — real flow + JdkInMemoryStateStore + token stub (no mocks)")
class OAuth2CallbackHandlerTest {

  private static final Instant NOW = Instant.parse("2026-06-26T10:00:00Z");

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicInteger tokenRequests = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      tokenRequests.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      byte[] out = "{\"access_token\":\"AT-rest\",\"token_type\":\"Bearer\"}"
          .getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    tokenEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private AuthorizationCodeFlow flow(JdkInMemoryStateStore store) {
    return flow(store, config());
  }

  private OAuth2ClientConfig config() {
    return new OAuth2ClientConfig(
        new ClientAuthentication.NoneAuthentication("rp"),
        Optional.of(URI.create("https://idp.example/authorize")),
        tokenEndpoint, Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.of(URI.create("https://app.example/callback")),
        Set.of("openid"), true, true, Duration.ofMinutes(5));
  }

  private AuthorizationCodeFlow flow(JdkInMemoryStateStore store, OAuth2ClientConfig config) {
    return new HttpAuthorizationCodeFlow(config,
        new HttpTokenEndpointClient(tokenEndpoint, new ClientAuthentication.NoneAuthentication("rp"),
            HttpClient.newHttpClient(), () -> NOW),
        store, () -> NOW);
  }

  private static RestRequest request(Map<String, String> query) {
    return request(query, Map.of());
  }

  private static RestRequest request(Map<String, String> query, Map<String, String> headers) {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/oauth2/callback";
      }

      @Override public Map<String, String> headers() {
        return headers;
      }

      @Override public Map<String, String> queryParameters() {
        return query;
      }
    };
  }

  /** The {@code Cookie} request header a browser sends back for the binding cookie of {@code state}. */
  private static Map<String, String> bindingCookie(String state) {
    String setCookie = CallbackStateBinding.hostCookieHeader(state);
    return Map.of("Cookie", setCookie.substring(0, setCookie.indexOf(';')));
  }

  /** A request whose transport delivered the {@code Cookie} header on several lines. */
  private static RestRequest requestWithCookieLines(Map<String, String> query, List<String> cookieLines) {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/oauth2/callback";
      }

      @Override public Map<String, String> headers() {
        return Map.of("Cookie", cookieLines.get(0));
      }

      @Override public List<String> headerValues(String name) {
        return "Cookie".equalsIgnoreCase(name) ? cookieLines : List.of();
      }

      @Override public Map<String, String> queryParameters() {
        return query;
      }
    };
  }

  private static Map<String, String> callbackQuery(String state) {
    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    return query;
  }

  private static final class CapturingResponse implements RestResponse {
    int status;
    String body;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String value) {
      this.body = value;
    }
  }

  @Test
  @DisplayName("a valid code + state exchanges the code and hands tokens to the sink (204)")
  void validCallbackExchangesCode() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (result, req) -> captured.set(result));

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    // JS-SEC-120: the two-argument constructor binds with the __Host- cookie since 00.84.00,
    // so the valid callback is the one that carries the cookie set at startRequest(...) time.
    handler.handle(request(query, bindingCookie(state)), response);

    assertEquals(204, response.status);
    assertNull(response.body, "tokens must never be written to the response body");
    assertNotNull(captured.get());
    // JS-SEC-059: the sink receives the CallbackResult (tokens + stored nonce/resumeTarget).
    assertEquals("AT-rest", captured.get().tokens().accessToken());
  }

  @Test
  @DisplayName("a missing state parameter is a 400 without touching the flow")
  void missingStateIsBadRequest() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow(store), (t, r) -> { });
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(new HashMap<>()), response);
    assertEquals(400, response.status);
  }

  @Test
  @DisplayName("an unknown state maps to 400 (single-use / replay protection)")
  void unknownStateIsBadRequest() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow(store), (t, r) -> { });
    Map<String, String> query = new HashMap<>();
    query.put("code", "x");
    query.put("state", "never-issued");
    CapturingResponse response = new CapturingResponse();
    // JS-SEC-120: with a matching binding cookie, so that the 400 comes from the state store
    // (unknown state) and not from the binding check in front of it.
    handler.handle(request(query, bindingCookie("never-issued")), response);
    assertEquals(400, response.status);
    assertEquals("Invalid state", response.body);
  }

  // ── JS-SEC-120 (CWE-352, CWE-565): the binding is the default and cannot be weakened ──

  @Test
  @DisplayName("JS-SEC-120: default constructor — a callback without the binding cookie is a 400, the state stays unconsumed")
  void defaultConstructorRejectsUnboundCallback() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (result, req) -> captured.set(result));

    // the attacker's browser-less replay of a state that is still open: login CSRF
    CapturingResponse attackerResponse = new CapturingResponse();
    handler.handle(request(callbackQuery(state)), attackerResponse);
    assertEquals(HttpStatus.BAD_REQUEST.code(), attackerResponse.status);
    assertEquals("Invalid callback", attackerResponse.body, "generic body — no detail leak");
    assertNull(captured.get(), "the flow must not run without the binding cookie");

    // the state was not consumed: the browser that started the flow still completes it
    CapturingResponse victimResponse = new CapturingResponse();
    handler.handle(request(callbackQuery(state), bindingCookie(state)), victimResponse);
    assertEquals(HttpStatus.NO_CONTENT.code(), victimResponse.status);
    assertNotNull(captured.get());
    assertTrue(handler.isUserAgentBound(), "the short constructor must not mean 'unbound'");
  }

  @Test
  @DisplayName("JS-SEC-120: no binding only by name — withoutUserAgentBinding and an explicit unbound()")
  void unboundHandlerIsAnExplicitChoice() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler =
        OAuth2CallbackHandler.withoutUserAgentBinding(flow, (result, req) -> captured.set(result));
    assertFalse(handler.isUserAgentBound());
    assertFalse(new OAuth2CallbackHandler(flow, (t, r) -> { }, CallbackStateBinding.unbound())
        .isUserAgentBound());
    assertTrue(new OAuth2CallbackHandler(flow, (t, r) -> { }, CallbackStateBinding.hostCookie())
        .isUserAgentBound());
    assertTrue(new OAuth2CallbackHandler(flow, (t, r) -> { }, (s, r) -> true).isUserAgentBound(),
        "an application-supplied binding is a binding; only unbound() is reported as none");

    CapturingResponse response = new CapturingResponse();
    handler.handle(request(callbackQuery(state)), response);
    assertEquals(HttpStatus.NO_CONTENT.code(), response.status,
        "the explicitly unbound handler keeps the pre-00.84.00 behaviour");
    assertNotNull(captured.get());
  }

  @Test
  @DisplayName("JS-SEC-120: cookie names without the __Host- prefix are refused")
  void cookieNameWithoutHostPrefixIsRefused() {
    assertThrows(IllegalArgumentException.class, () -> CallbackStateBinding.hostCookie("OAUTH_STATE"));
    assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("OAUTH_STATE", "state-123"));
    assertThrows(IllegalArgumentException.class, () -> CallbackStateBinding.hostCookie("__Secure-State"));
    assertThrows(IllegalArgumentException.class, () -> CallbackStateBinding.hostCookie("__host-State"),
        "the prefix is compared as written");
    assertThrows(IllegalArgumentException.class, () -> CallbackStateBinding.hostCookie("__Host-"),
        "the prefix alone is no name");
    assertThrows(IllegalArgumentException.class, () -> CallbackStateBinding.hostCookie("__Host-a=b"));
    assertThrows(IllegalArgumentException.class, () -> CallbackStateBinding.hostCookie(" "));
    assertThrows(NullPointerException.class, () -> CallbackStateBinding.hostCookie(null));

    assertEquals("__Host-MyState=state-123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300",
        CallbackStateBinding.hostCookieHeader("__Host-MyState", "state-123"));
    assertTrue(CallbackStateBinding.hostCookie("__Host-MyState").matches("state-123",
        request(Map.of(), Map.of("Cookie", "__Host-MyState=state-123"))));
    assertTrue(CallbackStateBinding.DEFAULT_COOKIE_NAME.startsWith(CallbackStateBinding.HOST_COOKIE_PREFIX));
  }

  @Test
  @DisplayName("JS-SEC-120: two state cookies in the Cookie header are no match, whichever comes first")
  void twoStateCookiesDoNotMatch() {
    String name = CallbackStateBinding.DEFAULT_COOKIE_NAME;
    CallbackStateBinding binding = CallbackStateBinding.hostCookie();

    assertFalse(binding.matches("state-123", request(Map.of(),
        Map.of("Cookie", name + "=state-123; " + name + "=planted"))));
    assertFalse(binding.matches("state-123", request(Map.of(),
        Map.of("Cookie", name + "=planted; other=1; " + name + "=state-123"))));
    assertFalse(binding.matches("state-123", request(Map.of(),
        Map.of("Cookie", name + "=state-123; " + name + "=state-123"))),
        "two cookies of the name are ambiguous even when they agree");
    assertTrue(binding.matches("state-123", request(Map.of(),
        Map.of("Cookie", "other=1; " + name + "=state-123"))), "exactly one is the match");
  }

  @Test
  @DisplayName("JS-SEC-120: two state cookies — the handler answers 400 and leaves the state unconsumed")
  void twoStateCookiesAreRejectedByTheHandler() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (result, req) -> captured.set(result));
    String name = CallbackStateBinding.DEFAULT_COOKIE_NAME;

    CapturingResponse response = new CapturingResponse();
    handler.handle(request(callbackQuery(state),
        Map.of("Cookie", name + "=" + state + "; " + name + "=victims-own-state")), response);
    assertEquals(HttpStatus.BAD_REQUEST.code(), response.status);
    assertNull(captured.get());

    CapturingResponse retry = new CapturingResponse();
    handler.handle(request(callbackQuery(state), bindingCookie(state)), retry);
    assertEquals(HttpStatus.NO_CONTENT.code(), retry.status, "the rejected callback did not burn the state");
  }

  @Test
  @DisplayName("JS-SEC-120: several Cookie header lines are no match")
  void severalCookieHeaderLinesDoNotMatch() {
    String name = CallbackStateBinding.DEFAULT_COOKIE_NAME;
    CallbackStateBinding binding = CallbackStateBinding.hostCookie();

    assertFalse(binding.matches("state-123", requestWithCookieLines(Map.of(),
        List.of(name + "=state-123", name + "=planted"))));
    assertFalse(binding.matches("state-123", requestWithCookieLines(Map.of(),
        List.of(name + "=state-123", "other=1"))));
    assertTrue(binding.matches("state-123", requestWithCookieLines(Map.of(),
        List.of("other=1; " + name + "=state-123"))));
  }

  @Test
  @DisplayName("BL01: host-cookie binding — matching __Host- cookie completes the flow (204)")
  void boundCallbackWithMatchingCookieSucceeds() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (result, req) -> captured.set(result), CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query,
        Map.of("Cookie", CallbackStateBinding.DEFAULT_COOKIE_NAME + "=" + state)), response);

    assertEquals(204, response.status);
    assertNotNull(captured.get(), "sink must receive the bound callback");
  }

  @Test
  @DisplayName("BL01: a callback without the binding cookie is rejected 400 and the state stays unconsumed")
  void unboundCallbackIsRejectedWithoutConsumingState() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (result, req) -> captured.set(result), CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);

    // attacker presents the (stolen) state without the victim's cookie
    CapturingResponse attackerResponse = new CapturingResponse();
    handler.handle(request(query), attackerResponse);
    assertEquals(400, attackerResponse.status);
    assertEquals("Invalid callback", attackerResponse.body, "generic body — no detail leak");
    assertNull(captured.get(), "the flow must not run for an unbound callback");

    // the legitimate browser (with cookie) still completes — state was NOT consumed
    CapturingResponse victimResponse = new CapturingResponse();
    handler.handle(request(query,
        Map.of("Cookie", CallbackStateBinding.DEFAULT_COOKIE_NAME + "=" + state)), victimResponse);
    assertEquals(204, victimResponse.status, "rejected binding must not burn the single-use state");
    assertNotNull(captured.get());
  }

  @Test
  @DisplayName("BL01: a wrong cookie value is rejected 400 (constant-time compare, fail-closed)")
  void wrongCookieValueIsRejected() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (t, r) -> { }, CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "x");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query,
        Map.of("Cookie", CallbackStateBinding.DEFAULT_COOKIE_NAME + "=not-the-state")), response);
    assertEquals(400, response.status);
  }

  @Test
  @DisplayName("BL01: the Cookie header is matched case-insensitively and among other cookies")
  void cookieHeaderLookupIsRobust() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (t, r) -> { }, CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query, Map.of("cookie",
        "other=1; " + CallbackStateBinding.DEFAULT_COOKIE_NAME + "=" + state + "; more=2")), response);
    assertEquals(204, response.status);
  }

  @Test
  @DisplayName("BL01: hostCookieHeader pins the __Host- attributes and rejects control characters")
  void hostCookieHeaderIsPinned() {
    String header = CallbackStateBinding.hostCookieHeader("state-123");
    assertEquals("__Host-JCustosOAuth2State=state-123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300",
        header);
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("evil\r\nSet-Cookie: x=y"));
    // RF-a: the cookie NAME side gets the same header-injection guard
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("evil\r\nX", "state-123"));
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("name=trick", "state-123"));
  }

  @Test
  @DisplayName("an error callback (access_denied) maps to 403 and never echoes error_description")
  void errorCallbackIsForbidden() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow(store), (t, r) -> { });
    Map<String, String> query = new HashMap<>();
    query.put("error", "access_denied");
    query.put("error_description", "internal node 10.0.0.5 refused");
    query.put("state", "some-state");
    CapturingResponse response = new CapturingResponse();
    // JS-SEC-120: the error callback, too, passes the binding check first.
    handler.handle(request(query, bindingCookie("some-state")), response);
    assertEquals(403, response.status);
    assertTrue(response.body != null && !response.body.contains("10.0.0.5"),
        "error_description must not leak");
    assertFalse(response.body.contains("access_denied"), "raw oauth error must not leak verbatim");
  }

  // ── JS-SEC-150 (CWE-346, RFC 9207): the handler passes the response issuer to the flow ──

  @Test
  @DisplayName("JS-SEC-150: a callback naming a foreign issuer is rejected before the code exchange")
  void foreignIssuerIsRejectedBeforeTheCodeExchange() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store, config().withExpectedIssuer("https://idp.example", true));
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (result, req) -> captured.set(result));

    Map<String, String> mixedUp = callbackQuery(state);
    mixedUp.put("iss", "https://attacker.example");
    CapturingResponse rejected = new CapturingResponse();
    handler.handle(request(mixedUp, bindingCookie(state)), rejected);

    assertEquals(400, rejected.status);
    assertEquals("Invalid state", rejected.body);
    assertNull(captured.get(), "the sink must not see a mixed-up response");
    assertEquals(0, tokenRequests.get(), "the code must not reach the token endpoint");

    // The state was not consumed: the response of the expected issuer still completes.
    Map<String, String> honest = callbackQuery(state);
    honest.put("iss", "https://idp.example");
    CapturingResponse accepted = new CapturingResponse();
    handler.handle(request(honest, bindingCookie(state)), accepted);

    assertEquals(204, accepted.status);
    assertNotNull(captured.get());
    assertEquals(1, tokenRequests.get());
  }

  @Test
  @DisplayName("JS-SEC-150: a callback without iss is rejected when the issuer announces the parameter")
  void missingIssuerIsRejectedWhenRequired() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store, config().withExpectedIssuer("https://idp.example", true));
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (t, r) -> { });

    CapturingResponse response = new CapturingResponse();
    handler.handle(request(callbackQuery(state), bindingCookie(state)), response);

    assertEquals(400, response.status);
    assertEquals(0, tokenRequests.get());
  }

  // ── JS-SEC-098 (RFC 6749 §3.1): each response parameter at most once ──

  /** A request whose transport reports every value of every query parameter. */
  private static RestRequest multiValuedRequest(Map<String, List<String>> query, Map<String, String> headers) {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/oauth2/callback";
      }

      @Override public Map<String, String> headers() {
        return headers;
      }

      @Override public Map<String, String> queryParameters() {
        // what a lossy adapter would keep: the first value
        Map<String, String> first = new HashMap<>();
        query.forEach((name, values) -> first.put(name, values.get(0)));
        return first;
      }

      @Override public Map<String, List<String>> queryParameterValues() {
        return query;
      }
    };
  }

  private void assertRepeatedParameterRefused(String name, String first, String second, boolean withIssuer) {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = withIssuer
        ? flow(store, config().withExpectedIssuer("https://idp.example", false))
        : flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (result, req) -> captured.set(result));

    Map<String, List<String>> query = new HashMap<>();
    query.put("code", List.of("auth-code-xyz"));
    query.put("state", List.of(state));
    query.put(name, List.of(first.replace("<state>", state), second.replace("<state>", state)));
    CapturingResponse refused = new CapturingResponse();
    handler.handle(multiValuedRequest(query, bindingCookie(state)), refused);

    assertEquals(400, refused.status, name);
    assertEquals("Invalid callback", refused.body, "generic body — the parameter is not named");
    assertNull(captured.get(), "the flow must not run for a polluted callback");
    assertEquals(0, tokenRequests.get(), "no code may reach the token endpoint");

    // The state was not consumed: the well-formed callback still completes.
    Map<String, List<String>> clean = new HashMap<>();
    clean.put("code", List.of("auth-code-xyz"));
    clean.put("state", List.of(state));
    CapturingResponse accepted = new CapturingResponse();
    handler.handle(multiValuedRequest(clean, bindingCookie(state)), accepted);
    assertEquals(204, accepted.status, name);
    assertNotNull(captured.get());
  }

  @Test
  @DisplayName("JS-SEC-098: a repeated state is refused with 400 before the flow runs; the state stays usable")
  void repeatedStateRefused() {
    assertRepeatedParameterRefused("state", "<state>", "attacker-state", false);
  }

  @Test
  @DisplayName("JS-SEC-098: a repeated code is refused with 400 before the code exchange")
  void repeatedCodeRefused() {
    assertRepeatedParameterRefused("code", "auth-code-xyz", "attacker-code", false);
  }

  @Test
  @DisplayName("JS-SEC-098: a repeated iss is refused with 400, even when the first one is the expected issuer")
  void repeatedIssuerRefused() {
    assertRepeatedParameterRefused("iss", "https://idp.example", "https://attacker.example", true);
  }

  @Test
  @DisplayName("JS-SEC-098: an adapter that keeps the lossy default still completes a well-formed callback")
  void lossyDefaultStillWorks() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (t, r) -> { });
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(callbackQuery(state), bindingCookie(state)), response);
    assertEquals(204, response.status);
  }
}
