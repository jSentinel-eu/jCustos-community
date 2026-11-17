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

import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R5 follow-up (JS-SEC-066, CWE-778): {@link RestJCustosVersionFilter} audits its
 * {@code SessionStale} and {@code SessionInvalidated} events inside the request's correlation
 * scope, through the new {@link RestAuditCorrelation#call(RestRequest, java.util.function.Supplier)}.
 * Real filter, enforcer, version store, session store and store-backed audit service.
 */
@DisplayName("RestJCustosVersionFilter and RestAuditCorrelation.call (R5, JS-SEC-066)")
class RestVersionFilterCorrelationTest {

  private static final String PROXY = "127.0.0.1";
  private static final String PROXY_ID = "caddy-7c1e0f42-0d3b-4f7e-9a55-1b2c3d4e5f60";
  private static final String TOKEN = "demo-token-0123456789abcdef";
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY = new JCustosVersionKey(TenantId.DEFAULT, ALICE);

  private final InMemoryAuditEventStore auditStore = new InMemoryAuditEventStore();
  private final StoreBackedJCustosAuditService audit = new StoreBackedJCustosAuditService(auditStore);
  private final InMemoryJCustosVersionStore versions = new InMemoryJCustosVersionStore();

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    RestSessionRevocation.reset();
    RestDecisionContext.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void tearDown() {
    RestSessionRevocation.reset();
    RestDecisionContext.reset();
    JCustosServiceResolver.resetAll();
    assertTrue(AuditCorrelation.current().isEmpty(), "a scope leaked out of the test");
  }

  // ── the version filter ─────────────────────────────────────────

  @Test
  @DisplayName("SessionStale carries a server-side correlation id; the scope is closed afterwards")
  void sessionStale_carriesACorrelationId() {
    versions.increment(ALICE_KEY);

    assertFalse(filter().allow(request(PeerRequest.CLIENT, Map.of()), new RestOriginGuardTest.Response()));

    AuditEnvelope envelope = single();
    assertInstanceOf(SessionStale.class, envelope.event());
    assertNotNull(envelope.correlationId(), "SessionStale was audited outside a correlation scope");
    assertEquals(36, envelope.correlationId().length(), "a server-side UUID: " + envelope.correlationId());
  }

  @Test
  @DisplayName("SessionStale from a trusted proxy carries the proxy's X-Request-ID")
  void sessionStale_carriesTheTrustedProxyId() {
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(PROXY));
    versions.increment(ALICE_KEY);

    assertFalse(filter().allow(request(PROXY, Map.of("X-Request-ID", List.of(PROXY_ID))),
        new RestOriginGuardTest.Response()));

    assertEquals(PROXY_ID, single().correlationId());
  }

  @Test
  @DisplayName("SessionInvalidated of a revoked session carries a correlation id")
  void revokedSession_carriesACorrelationId() {
    InMemorySessionStore sessions = new InMemorySessionStore();
    Instant login = Instant.now().minusSeconds(60);
    sessions.save(new SessionRecord(SessionId.of(TOKEN), ALICE, TenantId.DEFAULT, login, login,
        JCustosVersion.INITIAL, SessionStatus.REVOKED));
    RestSessionRevocation.useSessionStore(sessions);

    assertFalse(filter().allow(request(PeerRequest.CLIENT, Map.of()), new RestOriginGuardTest.Response()));

    AuditEnvelope envelope = single();
    assertInstanceOf(SessionInvalidated.class, envelope.event());
    assertNotNull(envelope.correlationId());
  }

  @Test
  @DisplayName("inside a scope the application opened, the filter uses that scope's id and leaves it open")
  void insideAnOpenScope_theFilterUsesItsId() {
    versions.increment(ALICE_KEY);
    try (AuditCorrelation.Scope outer = AuditCorrelation.open("router-scope-1")) {
      assertFalse(filter().allow(request(PeerRequest.CLIENT, Map.of()), new RestOriginGuardTest.Response()));
      assertEquals(Optional.of("router-scope-1"), AuditCorrelation.current());
    }
    assertEquals("router-scope-1", single().correlationId());
  }

  @Test
  @DisplayName("a request that passes is unchanged: true, nothing audited, no scope left open")
  void passingRequest_isUnchanged() {
    assertTrue(filter().allow(request(PeerRequest.CLIENT, Map.of()), new RestOriginGuardTest.Response()));
    assertTrue(auditStore.query(TenantId.DEFAULT, AuditQuery.all()).isEmpty());
  }

  // ── RestAuditCorrelation.call ──────────────────────────────────

  @Test
  @DisplayName("call returns the action's result inside a scope and closes it")
  void call_returnsInsideAScope() {
    List<Optional<String>> seen = new ArrayList<>();

    String result = RestAuditCorrelation.call(request(PeerRequest.CLIENT, Map.of()), () -> {
      seen.add(AuditCorrelation.current());
      return "decided";
    });

    assertEquals("decided", result);
    assertTrue(seen.getFirst().isPresent());
    assertTrue(AuditCorrelation.current().isEmpty());
  }

  @Test
  @DisplayName("call closes the scope when the action throws, reuses an open scope, and runs a null request without one")
  void call_scopeRules() {
    assertThrows(IllegalStateException.class,
        () -> RestAuditCorrelation.call(request(PeerRequest.CLIENT, Map.of()), () -> {
          throw new IllegalStateException("filter failed");
        }));
    assertTrue(AuditCorrelation.current().isEmpty(), "the scope must not survive the exception");

    try (AuditCorrelation.Scope outer = AuditCorrelation.open("outer-id")) {
      assertEquals(Optional.of("outer-id"), RestAuditCorrelation.call(
          request(PeerRequest.CLIENT, Map.of()), AuditCorrelation::current));
      assertEquals(Optional.of("outer-id"), AuditCorrelation.current(), "call must not close it");
    }

    assertEquals(Optional.empty(), RestAuditCorrelation.call(null, AuditCorrelation::current));
    assertThrows(NullPointerException.class,
        () -> RestAuditCorrelation.call(request(PeerRequest.CLIENT, Map.of()), null));
  }

  // ── fixtures ───────────────────────────────────────────────────

  private AuditEnvelope single() {
    List<AuditEnvelope> envelopes = auditStore.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, envelopes.size(), envelopes.toString());
    return envelopes.getFirst();
  }

  /** The session carries the initial snapshot; incrementing the store drifts it. */
  private RestJCustosVersionFilter filter() {
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override
      public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.of(new JCustosSubject("alice", "Alice", Set.of(), Set.of()));
      }

      @Override
      public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, TOKEN));
      }

      @Override
      public Optional<SessionId> resolveSessionId(RestRequest request) {
        return Optional.of(SessionId.of(TOKEN));
      }
    };
    return new RestJCustosVersionFilter(resolver,
        new JCustosVersionEnforcer(versions, JCustosServiceResolver.securityAuditService()));
  }

  private static RestRequest request(String peer, Map<String, List<String>> lines) {
    return new PeerRequest("GET", "/api/documents", peer, lines);
  }

  /** A request with a peer address and multi-line headers. */
  private record PeerRequest(String method, String path, String remoteAddress,
                             Map<String, List<String>> lines) implements RestRequest {

    static final String CLIENT = "203.0.113.5";

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
}
