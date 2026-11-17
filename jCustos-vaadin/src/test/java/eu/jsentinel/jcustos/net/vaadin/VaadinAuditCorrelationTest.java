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
package eu.jsentinel.jcustos.net.vaadin;

import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.mocks.MockRequest;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinRequestInterceptor;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinSession;
import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoggingAuditSink;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimeListener;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;
import org.slf4j.helpers.MessageFormatter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R5 (JS-SEC-066, CWE-778), browserless: the interceptor that the jCustos-vaadin service-init
 * file registers opens the correlation scope at {@code requestStart} and closes it at
 * {@code requestEnd}; audit events recorded in between carry the id - a proxy's
 * {@code X-Request-ID} only from a trusted proxy. The service, the request and the interceptor
 * are the real ones Vaadin's service loader set up; only the audit logger is a test double.
 */
@DisplayName("VaadinAuditCorrelation (R5, JS-SEC-066)")
class VaadinAuditCorrelationTest extends BrowserlessTest {

  private static final String PROXY_ID = "caddy-4f1c2b9e-77aa-4c3e-9d0b-6a1f0c2d3e4f";
  private static final String FORGED_ID = "attacker-chosen-id";

  @Route("audit-correlation-fixture")
  public static class Fixture extends Div {
  }

  private final InMemoryAuditEventStore store = new InMemoryAuditEventStore();
  private final List<String> lines = new ArrayList<>();

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    assertTrue(AuditCorrelation.current().isEmpty(), "a scope leaked out of the test");
  }

  @Test
  @DisplayName("the service loader registers the interceptor, ahead of the session checks")
  void registeredAheadOfTheSessionChecks() {
    navigate(Fixture.class);
    List<VaadinRequestInterceptor> interceptors = new ArrayList<>();
    VaadinService.getCurrent().getVaadinRequestInterceptors().forEach(interceptors::add);

    int correlation = indexOf(interceptors, VaadinAuditCorrelation.class);
    int sessionChecks = indexOf(interceptors, SessionLifetimeListener.class);
    assertTrue(correlation >= 0, "VaadinAuditCorrelation is not registered: " + interceptors);
    assertTrue(sessionChecks >= 0, "SessionLifetimeListener is not registered: " + interceptors);
    assertTrue(correlation < sessionChecks,
        "the scope must be open before SessionLifetimeListener audits: " + interceptors);
  }

  @Test
  @DisplayName("untrusted peer with X-Request-ID: the header is ignored; store and line carry a UUID")
  void untrustedPeerGetsAUuid() {
    MockRequest mock = currentMockRequest();
    JCustosServiceResolver.setClientAddressResolver(
        ClientAddressResolver.trustedProxies("192.0.2.1"));
    mock.getHeaders().put("X-Request-ID", List.of(FORGED_ID));

    AuditEnvelope envelope = auditWithinRequest();

    String id = envelope.correlationId();
    assertNotEquals(FORGED_ID, id);
    assertEquals(36, id.length(), "a server-side UUID: " + id);
    assertTrue(lines.getFirst().endsWith(" corr=" + id), lines.getFirst());
  }

  @Test
  @DisplayName("trusted proxy: its X-Request-ID is in the store and in the audit line")
  void trustedProxyIdIsTaken() {
    MockRequest mock = currentMockRequest();
    String peer = mock.getRemoteAddr();
    assertNotNull(peer, "the mock request must report a peer address");
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(peer));
    mock.getHeaders().put("X-Request-ID", List.of(PROXY_ID));

    AuditEnvelope envelope = auditWithinRequest();

    assertEquals(PROXY_ID, envelope.correlationId());
    assertTrue(lines.getFirst().endsWith(" corr=" + PROXY_ID), lines.getFirst());
  }

  @Test
  @DisplayName("trusted proxy with two X-Request-ID lines: a UUID")
  void twoHeaderLinesGetAUuid() {
    MockRequest mock = currentMockRequest();
    JCustosServiceResolver.setClientAddressResolver(
        ClientAddressResolver.trustedProxies(mock.getRemoteAddr()));
    mock.getHeaders().put("X-Request-ID", List.of(PROXY_ID, FORGED_ID));

    String id = auditWithinRequest().correlationId();

    assertNotEquals(PROXY_ID, id);
    assertNotEquals(FORGED_ID, id);
    assertEquals(36, id.length(), "a server-side UUID: " + id);
  }

  @Test
  @DisplayName("a second instance leaves the request's scope alone; the scope is closed once")
  void secondInstanceDoesNotOpenASecondScope() {
    currentMockRequest();
    VaadinRequest request = VaadinRequest.getCurrent();
    VaadinResponse response = VaadinResponse.getCurrent();
    VaadinAuditCorrelation first = registered();
    VaadinAuditCorrelation second = new VaadinAuditCorrelation();

    first.requestStart(request, response);
    Optional<String> opened = AuditCorrelation.current();
    second.requestStart(request, response);
    assertTrue(opened.isPresent());
    assertEquals(opened, AuditCorrelation.current());

    first.requestEnd(request, response, VaadinSession.getCurrent());
    second.requestEnd(request, response, VaadinSession.getCurrent());
    assertTrue(AuditCorrelation.current().isEmpty());
  }

  @Test
  @DisplayName("outside a request - no requestStart - an audit event carries no id")
  void outsideARequestNoId() {
    navigate(Fixture.class);
    useStoreAndLog();
    JCustosServiceResolver.securityAuditService().publish(loginFailed());
    assertEquals(null, single().correlationId());
    assertTrue(!lines.getFirst().contains("corr="), lines.getFirst());
  }

  // ── helpers ────────────────────────────────────────────────────

  /** requestStart, an audit event, requestEnd - as Vaadin brackets every request. */
  private AuditEnvelope auditWithinRequest() {
    useStoreAndLog();
    VaadinAuditCorrelation interceptor = registered();
    VaadinRequest request = VaadinRequest.getCurrent();
    VaadinResponse response = VaadinResponse.getCurrent();
    interceptor.requestStart(request, response);
    try {
      JCustosServiceResolver.securityAuditService().publish(loginFailed());
    } finally {
      interceptor.requestEnd(request, response, VaadinSession.getCurrent());
    }
    assertTrue(AuditCorrelation.current().isEmpty(), "requestEnd closes the scope");
    return single();
  }

  private void useStoreAndLog() {
    StoreBackedJCustosAuditService stored = new StoreBackedJCustosAuditService(store);
    LoggingAuditSink sink = new LoggingAuditSink(new LineRecorder(lines));
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        stored.publish(event);
        sink.accept(event);
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return stored.query(query);
      }
    });
  }

  private AuditEnvelope single() {
    List<AuditEnvelope> envelopes = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, envelopes.size(), envelopes.toString());
    assertEquals(1, lines.size(), lines.toString());
    return envelopes.getFirst();
  }

  private static LoginFailed loginFailed() {
    return new LoginFailed(Instant.parse("2026-11-17T10:00:00Z"), "alice", "203.0.113.5",
        "bad-credentials");
  }

  private static VaadinAuditCorrelation registered() {
    for (VaadinRequestInterceptor interceptor
        : VaadinService.getCurrent().getVaadinRequestInterceptors()) {
      if (interceptor instanceof VaadinAuditCorrelation correlation) {
        return correlation;
      }
    }
    throw new AssertionError("VaadinAuditCorrelation is not registered with the service");
  }

  private static int indexOf(List<VaadinRequestInterceptor> interceptors, Class<?> type) {
    for (int i = 0; i < interceptors.size(); i++) {
      if (type.isInstance(interceptors.get(i))) {
        return i;
      }
    }
    return -1;
  }

  private MockRequest currentMockRequest() {
    navigate(Fixture.class);
    VaadinRequest current = VaadinRequest.getCurrent();
    assertNotNull(current, "Browserless must bind a current VaadinRequest");
    ServletRequest unwrapped = (VaadinServletRequest) current;
    while (unwrapped instanceof HttpServletRequestWrapper wrapper) {
      unwrapped = wrapper.getRequest();
    }
    assertSame(MockRequest.class, unwrapped.getClass());
    return (MockRequest) unwrapped;
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
}
