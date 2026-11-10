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
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.DefaultCompositeAuditService;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoggingAuditSink;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RestJCustosVersionFilter")
class RestJCustosVersionFilterTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY =
      new JCustosVersionKey(TenantId.DEFAULT, ALICE);

  @Test
  @DisplayName("resolver without a version-context → filter is a pass-through")
  void noContextIsPassThrough() {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = r -> Optional.empty();

    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertTrue(filter.allow(new StubRequest("/api/things"), response));
    assertEquals(200, response.status);
    assertTrue(response.headers.isEmpty());
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("matching version → filter returns true, response untouched")
  void matchingVersionAllows() {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-1"));
      }
    };

    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertTrue(filter.allow(new StubRequest("/api/things"), response));
    assertEquals(200, response.status);
    assertTrue(response.headers.isEmpty());
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("drifted version → 401 + WWW-Authenticate: SessionStale + audit emitted")
  void driftedVersionRefuses() {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(ALICE_KEY); // current → 1
    versionStore.increment(ALICE_KEY); // current → 2

    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-7"));
      }
    };

    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertFalse(filter.allow(new StubRequest("/admin/secret"), response, "/admin/secret"));

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals(RestJCustosVersionFilter.SESSION_STALE_CHALLENGE,
        response.headers.get("WWW-Authenticate"));

    assertEquals(1, audit.published.size());
    SessionStale event = (SessionStale) audit.published.get(0);
    assertEquals("alice", event.subjectId());
    // JS-SEC-117: the event carries the reference, never the identifier the resolver supplied.
    assertEquals(RestJCustosVersionFilter.sessionReference("sid-7"), event.sessionId());
    assertEquals("/admin/secret", event.route());
    assertEquals(0L, event.snapshotVersion());
    assertEquals(2L, event.currentVersion());
  }

  // ── JS-SEC-086: mapper and body strategy ─────────────────────

  @AfterEach
  void resetPublishedMapper() {
    RestDecisionContext.reset();
  }

  @Test
  @DisplayName("JS-SEC-086: drift renders through the published mapper, the SessionStale challenge stays")
  void driftedVersion_usesPublishedMapperAndKeepsChallenge() {
    String problemJson = "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401}";
    RestDecisionContext.publish(new HttpStatusDecisionMapper(decision -> problemJson));
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(ALICE_KEY); // current → 1, the session still carries the initial snapshot

    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-9"));
      }
    };

    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    assertFalse(filter.allow(new StubRequest("/admin/secret"), response));

    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(problemJson, response.body,
        "the body strategy of the published mapper must apply to the version filter too");
    assertEquals(RestJCustosVersionFilter.SESSION_STALE_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE),
        "the specific challenge must replace the mapper's generic Bearer challenge");
    assertEquals(1, audit.published.size());
    // JS-SEC-117: the reference, not the identifier itself.
    assertEquals(RestJCustosVersionFilter.sessionReference("sid-9"), ((SessionStale) audit.published.get(0)).sessionId());
  }

  @Test
  @DisplayName("JS-SEC-086: a published mapper that would let the request pass cannot reopen a drifted session")
  void driftedVersion_staysRefusedWhateverTheMapperReturns() {
    RestDecisionContext.publish((decision, target) -> true);
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(ALICE_KEY);

    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-9"));
      }
    };
    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, new CollectingAuditService()));

    RecordingResponse response = new RecordingResponse();
    assertFalse(filter.allow(new StubRequest("/admin/secret"), response),
        "the drift verdict belongs to the enforcer, the mapper only renders it");
    assertEquals(RestJCustosVersionFilter.SESSION_STALE_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @DisplayName("default route is derived from request.path() when not supplied")
  void defaultRouteIsRequestPath() {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(ALICE_KEY); // current → 1

    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid"));
      }
    };

    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, audit));

    RecordingResponse response = new RecordingResponse();
    filter.allow(new StubRequest("/api/x"), response);
    assertEquals("/api/x", ((SessionStale) audit.published.get(0)).route());
  }

  // ── JS-SEC-117 (CWE-532, CWE-522): no token in the audit trail ──

  private static final String BEARER_TOKEN = "eyJhbGciOiJub25lIn0.demo-bearer-token.0123456789abcdef";

  /**
   * The integration the Javadoc used to recommend and the reference resolver
   * implements: the "session id" of a REST request is its bearer token.
   */
  private static RestSubjectResolver tokenAsSessionIdResolver() {
    return new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return new BearerTokenExtractor().extract(request)
            .map(token -> new RestJCustosVersionContext(
                ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, token));
      }
    };
  }

  private static RestRequest bearerRequest(String token) {
    return new RestAuthorizationFilterTest.SimpleRestRequest(
        "GET", "/api/things", Map.of("Authorization", "Bearer " + token), Map.of());
  }

  @Test
  @DisplayName("JS-SEC-117: after drift no field of SessionStale contains the token; the same token gives the same reference")
  void driftedSession_tokenNeverReachesTheAuditTrail() throws ReflectiveOperationException {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(ALICE_KEY); // the role change: current → 1, the token still carries 0
    // the real audit service: logging sink plus the ring buffer an audit view reads
    DefaultCompositeAuditService audit = new DefaultCompositeAuditService();
    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        tokenAsSessionIdResolver(), new JCustosVersionEnforcer(versionStore, audit));

    // the client keeps sending its old token; a second token belongs to another session
    assertFalse(filter.allow(bearerRequest(BEARER_TOKEN), new RecordingResponse()));
    assertFalse(filter.allow(bearerRequest(BEARER_TOKEN), new RecordingResponse()));
    assertFalse(filter.allow(bearerRequest(BEARER_TOKEN + "-other"), new RecordingResponse()));

    List<AuditEvent> events = audit.query(AuditQuery.ofType(SessionStale.class));
    assertEquals(3, events.size());
    for (AuditEvent event : events) {
      for (RecordComponent component : SessionStale.class.getRecordComponents()) {
        Object value = component.getAccessor().invoke(event);
        assertFalse(String.valueOf(value).contains(BEARER_TOKEN),
            "SessionStale." + component.getName() + " must not carry the bearer token");
      }
      assertFalse(event.toString().contains(BEARER_TOKEN));
    }
    // the trail itself puts the newest event first or last - compare by reference, not by position
    List<String> references = events.stream().map(e -> ((SessionStale) e).sessionId()).toList();
    String expected = LoggingAuditSink.sessionRef(BEARER_TOKEN);
    assertEquals(2, references.stream().filter(expected::equals).count(),
        "two events of the same token carry the same reference: " + references);
    assertEquals(1, references.stream()
            .filter(LoggingAuditSink.sessionRef(BEARER_TOKEN + "-other")::equals).count(),
        "another token gives another reference: " + references);
  }

  @Test
  @DisplayName("JS-SEC-117: sessionReference is stable, 16 hex characters, distinct per value and null-safe")
  void sessionReferenceContract() {
    String reference = RestJCustosVersionFilter.sessionReference(BEARER_TOKEN);

    assertEquals(reference, RestJCustosVersionFilter.sessionReference(BEARER_TOKEN));
    assertTrue(reference.matches("[0-9a-f]{16}"), reference);
    assertNotEquals(reference, RestJCustosVersionFilter.sessionReference(BEARER_TOKEN + "x"));
    assertNull(RestJCustosVersionFilter.sessionReference(null));
  }

  @Test
  @DisplayName("JS-SEC-117: a context without a session id still yields a SessionStale without one")
  void driftedSession_withoutSessionIdStaysNull() {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(ALICE_KEY);
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = new RestSubjectResolver() {
      @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
      @Override public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
        return Optional.of(new RestJCustosVersionContext(
            ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, null));
      }
    };
    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(
        resolver, new JCustosVersionEnforcer(versionStore, audit));

    assertFalse(filter.allow(new StubRequest("/api/x"), new RecordingResponse()));

    assertNull(((SessionStale) audit.published.get(0)).sessionId());
  }

  @Test
  @DisplayName("constructor + allow reject null arguments")
  void rejectNulls() {
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    RestSubjectResolver resolver = r -> Optional.empty();
    JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(versionStore, audit);

    assertThrows(NullPointerException.class,
        () -> new RestJCustosVersionFilter(null, enforcer));
    assertThrows(NullPointerException.class,
        () -> new RestJCustosVersionFilter(resolver, null));

    RestJCustosVersionFilter filter = new RestJCustosVersionFilter(resolver, enforcer);
    assertThrows(NullPointerException.class,
        () -> filter.allow(null, new RecordingResponse()));
    assertThrows(NullPointerException.class,
        () -> filter.allow(new StubRequest("/x"), null));
  }

  private static final class StubRequest implements RestRequest {
    private final String path;
    StubRequest(String path) { this.path = path; }
    @Override public String method() { return "GET"; }
    @Override public String path() { return path; }
    @Override public Map<String, String> headers() { return Map.of(); }
    @Override public Map<String, String> queryParameters() { return Map.of(); }
  }

  private static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override public void status(int statusCode) { this.status = statusCode; }
    @Override public void body(String body) { this.body = body; }
    @Override public void header(String name, String value) { headers.put(name, value); }
  }

  private static final class CollectingAuditService implements JCustosAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
