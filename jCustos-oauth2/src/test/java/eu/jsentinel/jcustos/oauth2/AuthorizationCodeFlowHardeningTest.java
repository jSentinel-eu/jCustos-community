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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow.CallbackParams;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.StateEntry;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * JS-SEC-150 (CWE-346, CWE-770): the authorisation-code flow binds the response to its issuer
 * (RFC 9207) before it consumes the state or contacts a token endpoint, and the in-memory state
 * store stays available when it is full. No mocks: the real flow, the real
 * {@link JdkInMemoryStateStore}, the real {@link HttpTokenEndpointClient} against a JDK
 * {@link HttpServer} on loopback that counts the token requests it receives.
 */
@DisplayName("Authorisation-code flow — issuer binding and a state store that stays available (JS-SEC-150)")
class AuthorizationCodeFlowHardeningTest {

  private static final Instant NOW = Instant.parse("2026-11-10T12:00:00Z");
  private static final String HONEST = "https://honest-idp.example";
  private static final String ATTACKER = "https://attacker-idp.example";

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicInteger tokenRequests = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      tokenRequests.incrementAndGet();
      exchange.getRequestBody().readAllBytes();
      byte[] body = "{\"access_token\":\"AT-flow\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
          .getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
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

  private OAuth2ClientConfig unboundConfig() {
    return new OAuth2ClientConfig(
        new ClientAuthentication.NoneAuthentication("rp"),
        Optional.of(URI.create("https://idp.example/authorize")),
        tokenEndpoint,
        Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.of(URI.create("https://app.example/oauth2/callback")),
        Set.of("openid"), true, true, Duration.ofMinutes(10));
  }

  private HttpAuthorizationCodeFlow flow(OAuth2ClientConfig config, JdkInMemoryStateStore store) {
    return new HttpAuthorizationCodeFlow(config,
        new HttpTokenEndpointClient(tokenEndpoint, new ClientAuthentication.NoneAuthentication("rp"),
            HttpClient.newHttpClient(), () -> NOW),
        store, () -> NOW);
  }

  private static CallbackParams callback(String state, String iss) {
    return new CallbackParams(Optional.of("auth-code"), state, Optional.empty(), Optional.empty(),
        Optional.ofNullable(iss));
  }

  private static String stateInvalidDetail(Result<CallbackResult, OAuth2Error> result) {
    OAuth2Error error = result.fold(ok -> null, e -> e);
    return assertInstanceOf(OAuth2Error.StateInvalid.class, error).detail();
  }

  // ── issuer binding (RFC 9207) ───────────────────────────────────────────────────

  @Test
  @DisplayName("mix-up: a callback naming a FOREIGN issuer is rejected — no token request, the state stays unconsumed")
  void foreignIssuerRejectedBeforeStateAndCodeExchange() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(unboundConfig().withExpectedIssuer(HONEST, true), store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    Result<CallbackResult, OAuth2Error> mixedUp = flow.handleCallback(callback(state, ATTACKER));

    assertTrue(stateInvalidDetail(mixedUp).startsWith("oauth2/issuer-mismatch"));
    assertEquals(0, tokenRequests.get(), "the code must not reach the token endpoint");
    assertEquals(1, store.size(), "the state must stay unconsumed");

    // the legitimate response of the honest issuer still completes the login
    Result<CallbackResult, OAuth2Error> honest = flow.handleCallback(callback(state, HONEST));
    assertTrue(honest.isSuccess(), "expected success, got " + honest);
    assertEquals(1, tokenRequests.get());
    assertEquals(0, store.size());
  }

  @Test
  @DisplayName("an issuer that announces the iss parameter: a callback WITHOUT iss is rejected, state unconsumed")
  void missingIssuerRejectedWhenRequired() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(unboundConfig().withExpectedIssuer(HONEST, true), store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    // the pre-00.84.00 four-argument shape an adapter that was not updated still produces
    Result<CallbackResult, OAuth2Error> result = flow.handleCallback(
        new CallbackParams(Optional.of("auth-code"), state, Optional.empty(), Optional.empty()));

    assertTrue(stateInvalidDetail(result).startsWith("oauth2/issuer-missing"));
    assertEquals(0, tokenRequests.get());
    assertEquals(1, store.size());
  }

  @Test
  @DisplayName("an issuer that does NOT announce the parameter: a callback without iss is accepted, a foreign iss is not")
  void optionalIssuerParameter() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(unboundConfig().withExpectedIssuer(HONEST, false), store);

    String first = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    assertTrue(flow.handleCallback(callback(first, null)).isSuccess());

    String second = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    assertTrue(stateInvalidDetail(flow.handleCallback(callback(second, ATTACKER)))
        .startsWith("oauth2/issuer-mismatch"));
    assertEquals(1, tokenRequests.get(), "only the first callback reached the token endpoint");
  }

  @Test
  @DisplayName("an ERROR response naming a foreign issuer is not attributed to the configured server")
  void errorResponseFromForeignIssuerIsNotAuthorizationDenied() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(unboundConfig().withExpectedIssuer(HONEST, true), store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    Result<CallbackResult, OAuth2Error> result = flow.handleCallback(new CallbackParams(
        Optional.empty(), state, Optional.of("access_denied"), Optional.empty(), Optional.of(ATTACKER)));
    assertTrue(stateInvalidDetail(result).startsWith("oauth2/issuer-mismatch"));

    // the same error from the configured issuer is the ordinary denial
    Result<CallbackResult, OAuth2Error> denied = flow.handleCallback(new CallbackParams(
        Optional.empty(), state, Optional.of("access_denied"), Optional.empty(), Optional.of(HONEST)));
    assertInstanceOf(OAuth2Error.AuthorizationDenied.class, denied.fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("a state bound to issuer A is not exchanged by the flow of issuer H (shared redirect URI and store)")
  void stateBoundToAnotherIssuerIsNotExchanged() {
    JdkInMemoryStateStore sharedStore = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow attackerFlow = flow(unboundConfig().withExpectedIssuer(ATTACKER, false), sharedStore);
    HttpAuthorizationCodeFlow honestFlow = flow(unboundConfig().withExpectedIssuer(HONEST, false), sharedStore);

    // the victim starts the login at issuer A; the browser comes back with a code of issuer H and
    // the adapter hands the callback to H's flow
    String state = attackerFlow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    Result<CallbackResult, OAuth2Error> result = honestFlow.handleCallback(callback(state, HONEST));

    assertTrue(stateInvalidDetail(result).startsWith("oauth2/issuer-mismatch"));
    assertEquals(0, tokenRequests.get(), "no code exchange for a state of another issuer");
  }

  @Test
  @DisplayName("the request is bound: the state entry records the issuer it was sent to")
  void stateEntryRecordsIssuer() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    String state = flow(unboundConfig().withExpectedIssuer(HONEST, true), store)
        .startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    assertEquals(Optional.of(HONEST), store.consume(state).orElseThrow().expectedIssuer());
  }

  @Test
  @DisplayName("compatibility: a configuration without an expected issuer behaves as before, iss or not")
  void unboundConfigurationIsUnchanged() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(unboundConfig(), store);

    String first = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    assertTrue(flow.handleCallback(callback(first, null)).isSuccess());
    String second = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    assertTrue(flow.handleCallback(callback(second, "https://whatever.example")).isSuccess());
    assertEquals(2, tokenRequests.get());
  }

  // ── a state store that stays available ──────────────────────────────────────────

  @Test
  @DisplayName("state store: at the bound a further bind succeeds, the newest state is consumable, the size stays at the bound")
  void fullStateStoreEvictsInsteadOfThrowing() {
    int capacity = 50;
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(capacity, () -> NOW);
    for (int i = 0; i < capacity; i++) {
      store.bind("flood-" + i, entry(), Duration.ofMinutes(10));
    }
    assertEquals(capacity, store.size());

    // up to 00.83.x: IllegalStateException("oauth2/state-store-capacity-exceeded")
    assertDoesNotThrow(() -> store.bind("victim", entry(), Duration.ofMinutes(10)));

    assertEquals(capacity, store.size(), "the size stays at the bound");
    assertTrue(store.consume("victim").isPresent(), "the newest state is consumable");
    assertTrue(store.consume("flood-0").isEmpty(), "the earliest-expiring entry made room");
    assertTrue(store.consume("flood-1").isPresent(), "the others are untouched");
  }

  @Test
  @DisplayName("state store: a login that starts while the store is flooded completes")
  void loginCompletesWhileStoreIsFlooded() {
    int capacity = 50;
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(capacity, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(unboundConfig(), store);
    for (int i = 0; i < 5 * capacity; i++) {
      flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty());
    }
    String victim = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();
    assertEquals(capacity, store.size());
    assertTrue(flow.handleCallback(callback(victim, null)).isSuccess());
  }

  @Test
  @DisplayName("state store: the state closest to its expiry is evicted first")
  void earliestExpiryIsEvictedFirst() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(2, () -> NOW);
    store.bind("long", entry(), Duration.ofMinutes(10));
    store.bind("short", entry(), Duration.ofMinutes(1));
    store.bind("new", entry(), Duration.ofMinutes(5));
    assertTrue(store.consume("short").isEmpty());
    assertTrue(store.consume("long").isPresent());
    assertTrue(store.consume("new").isPresent());
  }

  private static StateEntry entry() {
    return new StateEntry("verifier-1234567890123456789012345678901234567890123",
        Optional.empty(), Optional.empty(), Map.of(), NOW);
  }
}
