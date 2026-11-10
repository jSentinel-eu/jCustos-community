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
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RestAuthenticationFilter")
class RestAuthenticationFilterTest {

  private static final RestRequest REQUEST = new RestRequest() {
    @Override public String method() { return "GET"; }
    @Override public String path() { return "/x"; }
    @Override public Map<String, String> headers() { return Map.of(); }
    @Override public Map<String, String> queryParameters() { return Map.of(); }
  };

  @Test
  @DisplayName("returns 401 with body 'Unauthorized' when no subject is resolved")
  void unauthenticated() {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean called = new AtomicBoolean();
    new RestAuthenticationFilter(req -> Optional.empty())
        .requireAuthenticated(REQUEST, response, (r, w) -> called.set(true));
    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertFalse(called.get());
  }

  @Test
  @DisplayName("delegates to the handler when a subject is present")
  void authenticated() {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean called = new AtomicBoolean();
    JCustosSubject subject = new JCustosSubject("u", "User", Set.of(), Set.of());
    new RestAuthenticationFilter(req -> Optional.of(subject))
        .requireAuthenticated(REQUEST, response, (r, w) -> {
          called.set(true);
          w.status(204);
        });
    assertEquals(204, response.status);
    assertTrue(called.get());
  }

  // ── JS-SEC-086: mapper, body strategy, challenge and audit ──────

  /** What a problem+json body strategy renders for a 401 (RFC 7807). */
  private static final String PROBLEM_JSON_UNAUTHORIZED =
      "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401}";

  @AfterEach
  void resetPublished() {
    RestDecisionContext.reset();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("JS-SEC-086: an anonymous request renders through the published mapper and leaves an AccessDenied")
  void unauthenticated_usesPublishedMapperAndAudits() {
    RestDecisionContext.publish(new HttpStatusDecisionMapper(decision -> PROBLEM_JSON_UNAUTHORIZED));
    RecordingAudit audit = new RecordingAudit();
    JCustosServiceResolver.setJCustosAuditService(audit);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean called = new AtomicBoolean();

    new RestAuthenticationFilter(req -> Optional.empty())
        .requireAuthenticated(REQUEST, response, (r, w) -> called.set(true));

    assertFalse(called.get(), "the handler must not run for an anonymous request");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, response.body,
        "the body strategy of the published mapper must apply to this filter too");
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE, response.headers.get(RestHeaders.WWW_AUTHENTICATE),
        "a 401 carries a challenge (RFC 7235)");
    assertEquals(1, audit.events.size());
    AccessDenied denied = (AccessDenied) audit.events.get(0);
    assertEquals("Unauthenticated:no-subject", denied.reason());
    assertEquals("/x", denied.route());
    assertNull(denied.subjectId());
  }

  @Test
  @DisplayName("JS-SEC-086: without a published mapper the default renders the generic body plus challenge")
  void unauthenticated_defaultMapperCarriesChallenge() {
    RecordingResponse response = new RecordingResponse();

    new RestAuthenticationFilter(req -> Optional.empty())
        .requireAuthenticated(REQUEST, response, (r, w) -> { });

    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE, response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @DisplayName("JS-SEC-086: an expired session renders through the published mapper and leaves a SessionExpired")
  void expiredSession_usesPublishedMapperAndAudits() {
    RestDecisionContext.publish(new HttpStatusDecisionMapper(decision -> PROBLEM_JSON_UNAUTHORIZED));
    RecordingAudit audit = new RecordingAudit();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setSessionPolicy(new IdleTimeoutPolicy<>());
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean called = new AtomicBoolean();
    JCustosSubject subject = new JCustosSubject("u1", "User", Set.of(), Set.of());
    Instant loggedInAt = Instant.parse("2026-05-08T10:00:00Z");
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.of(subject);
      }
      @Override public Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
        return Optional.of(new SessionMetadata("u1", loggedInAt, loggedInAt));
      }
    };

    new RestAuthenticationFilter(resolver)
        .requireAuthenticated(REQUEST, response, (r, w) -> called.set(true));

    assertFalse(called.get(), "the handler must not run for an expired session");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, response.body,
        "the second denial path of this filter must share the body strategy");
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE, response.headers.get(RestHeaders.WWW_AUTHENTICATE));
    assertEquals(1, audit.events.size());
    SessionExpired expired = (SessionExpired) audit.events.get(0);
    assertEquals("u1", expired.subjectId());
    assertEquals(SessionExpired.REASON_IDLE_TIMEOUT, expired.reason());
  }

  @Test
  @DisplayName("JS-SEC-086: a published mapper that would let the request pass cannot admit an anonymous request")
  void unauthenticated_staysRefusedWhateverTheMapperReturns() {
    RestDecisionContext.publish((decision, target) -> true);
    AtomicBoolean called = new AtomicBoolean();

    new RestAuthenticationFilter(req -> Optional.empty())
        .requireAuthenticated(REQUEST, new RecordingResponse(), (r, w) -> called.set(true));

    assertFalse(called.get(), "the mapper renders the refusal, it does not decide it");
  }

  /** Session policy that reports every session as idle-timed-out. */
  static final class IdleTimeoutPolicy<U> implements SessionPolicy<U> {
    @Override public SessionDecision beforeNavigation(SessionContext<U> context) {
      return SessionDecision.Continue.INSTANCE;
    }
    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return SessionPolicyDecision.idleTimeout();
    }
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;
    final Map<String, String> headers = new HashMap<>();
    @Override public void status(int code) { status = code; }
    @Override public void body(String body) { this.body = body; }
    @Override public void header(String name, String value) { headers.put(name, value); }
  }

  static final class RecordingAudit implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void publish(AuditEvent event) { events.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(events); }
  }
}
