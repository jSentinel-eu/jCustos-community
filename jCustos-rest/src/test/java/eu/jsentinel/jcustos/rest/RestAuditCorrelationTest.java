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

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoggingAuditSink;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;
import org.slf4j.helpers.MessageFormatter;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R5 (JS-SEC-066, CWE-778): the REST filters run inside the correlation scope of the request.
 * The scope is opened once per request, closed in a {@code finally} block, reused by nested
 * filters, and its id reaches the audit store and the audit line - the proxy's
 * {@code X-Request-ID} only from a trusted proxy. Real filters, resolver, store and sink; the
 * request and the audit logger are hand-written test doubles.
 */
@DisplayName("RestAuditCorrelation (R5, JS-SEC-066)")
class RestAuditCorrelationTest {

  private static final String PROXY = "127.0.0.1";
  private static final String CLIENT = "203.0.113.5";
  private static final String PROXY_ID = "caddy-4f1c2b9e-77aa-4c3e-9d0b-6a1f0c2d3e4f";
  private static final String FORGED_ID = "attacker-chosen-id";

  private final StoreAndLog audit = new StoreAndLog();

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    assertTrue(AuditCorrelation.current().isEmpty(), "a scope leaked out of the test");
  }

  // ── RestAuditCorrelation.run ───────────────────────────────────

  @Test
  @DisplayName("run opens a scope for the action and closes it afterwards")
  void runOpensAndCloses() {
    List<Optional<String>> seen = new ArrayList<>();
    RestAuditCorrelation.run(request(CLIENT, Map.of()), () -> seen.add(AuditCorrelation.current()));

    assertEquals(1, seen.size());
    assertTrue(seen.getFirst().isPresent(), "the action runs inside a scope");
    assertTrue(AuditCorrelation.current().isEmpty());
  }

  @Test
  @DisplayName("run closes the scope in finally when the action throws")
  void runClosesWhenTheActionThrows() {
    IllegalStateException thrown = assertThrows(IllegalStateException.class,
        () -> RestAuditCorrelation.run(request(CLIENT, Map.of()), () -> {
          assertTrue(AuditCorrelation.current().isPresent());
          throw new IllegalStateException("handler failed");
        }));
    assertEquals("handler failed", thrown.getMessage());
    assertTrue(AuditCorrelation.current().isEmpty(), "the scope must not survive the exception");
  }

  @Test
  @DisplayName("inside an open scope run keeps that id and leaves it open; a nested scope restores it")
  void runReusesAnOpenScope() {
    try (AuditCorrelation.Scope outer = AuditCorrelation.open("outer-id")) {
      RestAuditCorrelation.run(request(CLIENT, Map.of()), () -> {
        assertEquals(Optional.of("outer-id"), AuditCorrelation.current());
        try (AuditCorrelation.Scope nested = AuditCorrelation.open("nested-id")) {
          assertEquals(Optional.of("nested-id"), AuditCorrelation.current());
        }
        assertEquals(Optional.of("outer-id"), AuditCorrelation.current(),
            "closing the nested scope restores the request's id");
      });
      assertEquals(Optional.of("outer-id"), AuditCorrelation.current(),
          "run must not close a scope it did not open");
    }
  }

  @Test
  @DisplayName("a null request runs the action without a scope")
  void nullRequestRunsWithoutScope() {
    List<Optional<String>> seen = new ArrayList<>();
    RestAuditCorrelation.run(null, () -> seen.add(AuditCorrelation.current()));
    assertEquals(List.of(Optional.empty()), seen);
  }

  // ── through the filters ────────────────────────────────────────

  @Test
  @DisplayName("authentication filter, untrusted peer with X-Request-ID: header ignored, a UUID in store, line and handler")
  void authenticationFilterIgnoresAForgedId() {
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(PROXY));
    List<Optional<String>> inHandler = new ArrayList<>();

    new RestAuthenticationFilter(request -> Optional.empty())
        .requireAuthenticated(request(CLIENT, Map.of("X-Request-ID", List.of(FORGED_ID))),
            new RecordingResponse(), (request, response) -> inHandler.add(Optional.empty()));

    AuditEnvelope denied = audit.single();
    assertInstanceOf(AccessDenied.class, denied.event());
    String id = denied.correlationId();
    assertNotEquals(FORGED_ID, id);
    assertEquals(36, id.length(), "a server-side UUID: " + id);
    assertTrue(audit.lines.getFirst().endsWith(" corr=" + id), audit.lines.getFirst());
    assertTrue(inHandler.isEmpty(), "the refused request never reaches the handler");
    assertTrue(AuditCorrelation.current().isEmpty());
  }

  @Test
  @DisplayName("nested filters from a trusted proxy: one scope, the proxy's id on every event and in the handler")
  void nestedFiltersShareTheProxyId() throws NoSuchMethodException {
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(PROXY));
    RestSubjectResolver subjects = request -> Optional.of(new JCustosSubject("u1", "User",
        Set.of(), Set.of(new PermissionName("document:delete"))));
    RestAuthorizationFilter authorization = new RestAuthorizationFilter(subjects);
    Method secured = Secured.class.getDeclaredMethod("delete");
    List<Optional<String>> inHandler = new ArrayList<>();
    RestRequest request = request(PROXY, Map.of("X-Request-ID", List.of(PROXY_ID)));

    new RestAuthenticationFilter(subjects).requireAuthenticated(request, new RecordingResponse(),
        (outerRequest, outerResponse) -> authorization.authorizeAndHandle(outerRequest,
            outerResponse, (innerRequest, innerResponse) -> {
              inHandler.add(AuditCorrelation.current());
              JCustosServiceResolver.securityAuditService().publish(
                  new AccessDenied(java.time.Instant.now(), "u1", "/handler", "handler-audit"));
            }, secured));

    assertEquals(List.of(Optional.of(PROXY_ID)), inHandler);
    List<AuditEnvelope> envelopes = audit.store.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(2, envelopes.size(), "AccessGranted of the filter and the handler's own event");
    assertInstanceOf(AccessGranted.class, envelopes.get(0).event());
    envelopes.forEach(envelope -> assertEquals(PROXY_ID, envelope.correlationId()));
    audit.lines.forEach(line -> assertTrue(line.endsWith(" corr=" + PROXY_ID), line));
    assertTrue(AuditCorrelation.current().isEmpty(), "closed when the outer filter returned");
  }

  @Test
  @DisplayName("authorization filter alone opens the scope, also on an unannotated handler")
  void authorizationFilterOpensTheScope() throws NoSuchMethodException {
    List<Optional<String>> inHandler = new ArrayList<>();
    new RestAuthorizationFilter(request -> Optional.empty()).authorizeAndHandle(
        request(CLIENT, Map.of()), new RecordingResponse(),
        (request, response) -> inHandler.add(AuditCorrelation.current()),
        Secured.class.getDeclaredMethod("open"));

    assertEquals(1, inHandler.size());
    assertTrue(inHandler.getFirst().isPresent());
    assertTrue(AuditCorrelation.current().isEmpty());
  }

  // ── fixtures ───────────────────────────────────────────────────

  static final class Secured {
    @RequiresPermission("document:delete")
    void delete() {
    }

    void open() {
    }
  }

  private static RestRequest request(String peer, Map<String, List<String>> lines) {
    return new PeerRequest("DELETE", "/api/documents/42", peer, lines);
  }

  /** A request with a peer address and multi-line headers. */
  private record PeerRequest(String method, String path, String peer,
                             Map<String, List<String>> lines) implements RestRequest {

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

    @Override
    public Optional<String> remoteAddress() {
      return Optional.ofNullable(peer);
    }
  }

  /** Persists through the real store-backed service and writes the real audit line. */
  private static final class StoreAndLog implements JCustosAuditService {
    final InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    final List<String> lines = new ArrayList<>();
    private final StoreBackedJCustosAuditService stored = new StoreBackedJCustosAuditService(store);
    private final LoggingAuditSink sink = new LoggingAuditSink(new LineRecorder(lines));

    @Override
    public void publish(AuditEvent event) {
      stored.publish(event);
      sink.accept(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return stored.query(query);
    }

    AuditEnvelope single() {
      List<AuditEnvelope> envelopes = store.query(TenantId.DEFAULT, AuditQuery.all());
      assertEquals(1, envelopes.size(), envelopes.toString());
      return envelopes.getFirst();
    }
  }

  /** SLF4J logger that keeps the formatted messages. */
  private static final class LineRecorder extends AbstractLogger {
    private final List<String> lines;

    LineRecorder(List<String> lines) {
      this.lines = lines;
      this.name = "recording";
    }

    @Override
    protected String getFullyQualifiedCallerName() {
      return LineRecorder.class.getName();
    }

    @Override
    protected void handleNormalizedLoggingCall(Level level, Marker marker, String messagePattern,
                                               Object[] arguments, Throwable throwable) {
      lines.add(arguments == null || arguments.length == 0
          ? messagePattern
          : MessageFormatter.basicArrayFormat(messagePattern, arguments));
    }

    @Override public boolean isTraceEnabled() { return true; }
    @Override public boolean isTraceEnabled(Marker marker) { return true; }
    @Override public boolean isDebugEnabled() { return true; }
    @Override public boolean isDebugEnabled(Marker marker) { return true; }
    @Override public boolean isInfoEnabled() { return true; }
    @Override public boolean isInfoEnabled(Marker marker) { return true; }
    @Override public boolean isWarnEnabled() { return true; }
    @Override public boolean isWarnEnabled(Marker marker) { return true; }
    @Override public boolean isErrorEnabled() { return true; }
    @Override public boolean isErrorEnabled(Marker marker) { return true; }
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      // not inspected here
    }
  }
}
