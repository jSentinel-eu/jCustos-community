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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R5 (JS-SEC-066, CWE-778): a proxy-supplied {@code X-Request-ID} reaches the audit trail only
 * from a trusted proxy, and only as one well-formed line. Every other request gets a server-side
 * UUID. The end-to-end tests drive the real resolver, scope, store-backed service, store and
 * logging sink.
 */
@DisplayName("TrustedPeerCorrelationIdResolver (R5, JS-SEC-066)")
class TrustedPeerCorrelationIdResolverTest {

  private static final String PROXY = "127.0.0.1";
  private static final String CLIENT = "203.0.113.5";
  private static final String PROXY_ID = "caddy-4f1c2b9e-77aa-4c3e-9d0b-6a1f0c2d3e4f";
  private static final String FORGED_ID = "attacker-chosen-id";

  private final ClientAddressResolver loopbackProxy = ClientAddressResolver.trustedProxies(PROXY);
  private final TrustedPeerCorrelationIdResolver resolver =
      new TrustedPeerCorrelationIdResolver(loopbackProxy);

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  private static ClientRequestView request(String peer, Map<String, List<String>> headers) {
    return ClientRequestView.of(peer, name -> headers.entrySet().stream()
        .filter(entry -> entry.getKey().equalsIgnoreCase(name))
        .map(Map.Entry::getValue)
        .findFirst()
        .orElse(List.of()));
  }

  private static void assertServerGenerated(String id, String notThis) {
    assertNotEquals(notThis, id, "the header value must not be taken over");
    assertEquals(36, id.length(), "a server-side UUID: " + id);
    assertTrue(AuditEnvelope.isValidCorrelationId(id));
  }

  @Test
  @DisplayName("untrusted peer with X-Request-ID: the header is ignored, the id is a server-side UUID")
  void untrustedPeerGetsAUuid() {
    String id = resolver.resolve(request(CLIENT, Map.of("X-Request-ID", List.of(FORGED_ID))));
    assertServerGenerated(id, FORGED_ID);
  }

  @Test
  @DisplayName("trusted proxy with one well-formed X-Request-ID: its id is taken, any spelling of the name")
  void trustedProxyIdIsTaken() {
    assertEquals(PROXY_ID,
        resolver.resolve(request(PROXY, Map.of("X-Request-ID", List.of(PROXY_ID)))));
    assertEquals(PROXY_ID,
        resolver.resolve(request(PROXY, Map.of("x-request-id", List.of(PROXY_ID)))));
  }

  @Test
  @DisplayName("trusted proxy: two header lines, an over-long or a malformed id yield a UUID")
  void trustedProxyMalformedValuesGetAUuid() {
    assertServerGenerated(resolver.resolve(request(PROXY,
        Map.of("X-Request-ID", List.of(PROXY_ID, FORGED_ID)))), PROXY_ID);
    String overLong = "a".repeat(AuditEnvelope.MAX_CORRELATION_ID_LENGTH + 1);
    assertServerGenerated(resolver.resolve(request(PROXY,
        Map.of("X-Request-ID", List.of(overLong)))), overLong);
    for (String malformed : List.of("", "id with space", "id\r\nAUDIT type=Forged",
        "a,b", "café", "id x")) {
      assertServerGenerated(resolver.resolve(request(PROXY,
          Map.of("X-Request-ID", List.of(malformed)))), malformed);
    }
  }

  @Test
  @DisplayName("the longest allowed id is taken from a trusted proxy")
  void longestAllowedIdIsTaken() {
    String longest = "a".repeat(AuditEnvelope.MAX_CORRELATION_ID_LENGTH);
    assertEquals(longest,
        resolver.resolve(request(PROXY, Map.of("X-Request-ID", List.of(longest)))));
  }

  @Test
  @DisplayName("trusted proxy without the header: a UUID")
  void trustedProxyWithoutHeaderGetsAUuid() {
    assertServerGenerated(resolver.resolve(request(PROXY, Map.of())), null);
  }

  @Test
  @DisplayName("the default client-address resolver trusts no peer: even loopback gets a UUID")
  void defaultClientAddressResolverTrustsNobody() {
    TrustedPeerCorrelationIdResolver withDefault =
        new TrustedPeerCorrelationIdResolver(ClientAddressResolver.remoteAddress());
    assertServerGenerated(withDefault.resolve(request(PROXY,
        Map.of("X-Request-ID", List.of(PROXY_ID)))), PROXY_ID);
  }

  @Test
  @DisplayName("a configured header name replaces X-Request-ID")
  void configuredHeaderName() {
    TrustedPeerCorrelationIdResolver custom =
        new TrustedPeerCorrelationIdResolver(loopbackProxy, "X-Correlation-ID");
    assertEquals("X-Correlation-ID", custom.headerName());
    assertEquals(PROXY_ID, custom.resolve(request(PROXY,
        Map.of("X-Correlation-ID", List.of(PROXY_ID)))));
    assertServerGenerated(custom.resolve(request(PROXY,
        Map.of("X-Request-ID", List.of(PROXY_ID)))), PROXY_ID);
    assertThrows(IllegalArgumentException.class,
        () -> new TrustedPeerCorrelationIdResolver(loopbackProxy, " "));
  }

  @Test
  @DisplayName("a client-address resolver that throws counts as untrusted")
  void throwingTrustDecisionFailsClosed() {
    ClientAddressResolver broken = new ClientAddressResolver() {
      @Override
      public Optional<String> resolve(ClientRequestView request) {
        return Optional.empty();
      }

      @Override
      public boolean trustsPeer(ClientRequestView request) {
        throw new IllegalStateException("broken");
      }
    };
    assertServerGenerated(new TrustedPeerCorrelationIdResolver(broken).resolve(
        request(PROXY, Map.of("X-Request-ID", List.of(PROXY_ID)))), PROXY_ID);
  }

  @Test
  @DisplayName("the resolver default follows the client-address resolver registered later")
  void contextDefaultFollowsTheClientAddressResolver() {
    CorrelationIdResolver defaulted = JCustosServiceResolver.correlationIdResolver();
    assertInstanceOf(TrustedPeerCorrelationIdResolver.class, defaulted);
    ClientRequestView fromProxy = request(PROXY, Map.of("X-Request-ID", List.of(PROXY_ID)));
    assertServerGenerated(defaulted.resolve(fromProxy), PROXY_ID);

    JCustosServiceResolver.setClientAddressResolver(loopbackProxy);

    assertEquals(PROXY_ID, defaulted.resolve(fromProxy));
    assertEquals(PROXY_ID, new TrustedPeerCorrelationIdResolver().resolve(fromProxy),
        "the no-argument constructor reads the registered resolver too");
  }

  // ── end to end: resolver -> scope -> store and audit line ──────

  @Test
  @DisplayName("trusted proxy: its id is in the audit line and in the stored envelope")
  void trustedProxyIdReachesLineAndStore() {
    JCustosServiceResolver.setClientAddressResolver(loopbackProxy);
    Recorded recorded = publishWithin(request(PROXY, Map.of("X-Request-ID", List.of(PROXY_ID))));

    assertEquals(PROXY_ID, recorded.envelope().correlationId());
    assertTrue(recorded.line().endsWith(" corr=" + PROXY_ID), recorded.line());
  }

  @Test
  @DisplayName("untrusted peer: the forged id reaches neither line nor store; both carry the same UUID")
  void forgedIdReachesNeitherLineNorStore() {
    JCustosServiceResolver.setClientAddressResolver(loopbackProxy);
    Recorded recorded = publishWithin(request(CLIENT, Map.of("X-Request-ID", List.of(FORGED_ID))));

    String stored = recorded.envelope().correlationId();
    assertServerGenerated(stored, FORGED_ID);
    assertTrue(recorded.line().endsWith(" corr=" + stored), recorded.line());
    assertTrue(!recorded.line().contains(FORGED_ID), recorded.line());
  }

  @Test
  @DisplayName("outside a request the store keeps no id and the line has no corr= field")
  void outsideARequestNothingIsInvented() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    AuditEvent event = new LoginFailed(Instant.parse("2026-11-17T10:00:00Z"), "alice", CLIENT,
        "bad-credentials");
    new StoreBackedJCustosAuditService(store).publish(event);
    new LoggingAuditSink(logger).accept(event);

    assertNull(store.query(TenantId.DEFAULT, AuditQuery.all()).getFirst().correlationId());
    assertTrue(!logger.firstMessage().contains("corr="), logger.firstMessage());
  }

  private record Recorded(AuditEnvelope envelope, String line) {
  }

  private static Recorded publishWithin(ClientRequestView request) {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    JCustosAuditService service = new CompositeAuditService(
        new RingBufferAuditSink(), new LoggingAuditSink(logger));
    StoreBackedJCustosAuditService stored = new StoreBackedJCustosAuditService(store);
    AuditEvent event = new LoginFailed(Instant.parse("2026-11-17T10:00:00Z"), "alice", CLIENT,
        "bad-credentials");
    try (AuditCorrelation.Scope ignored = AuditCorrelation.openFor(request)) {
      service.publish(event);
      stored.publish(event);
    }
    assertTrue(AuditCorrelation.current().isEmpty());
    List<AuditEnvelope> envelopes = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, envelopes.size());
    return new Recorded(envelopes.getFirst(), logger.firstMessage());
  }
}
