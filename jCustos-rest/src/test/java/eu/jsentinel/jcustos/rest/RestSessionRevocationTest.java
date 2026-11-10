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
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613), REST part: a revoked session must stop working over REST. Real
 * filters, the real {@link InMemorySessionStore}, a resolver as an application writes it:
 * the bearer token names the session, the record is stored under the reference of the
 * token.
 */
@DisplayName("REST session revocation (JS-SEC-131)")
class RestSessionRevocationTest {

  private static final String TOKEN = "synthetic-token-alice-0123456789";
  private static final SessionId SESSION = SessionId.of(SessionRef.of(TOKEN));
  private static final String ROUTE = "/api/documents/42";

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final InMemorySessionStore store = new InMemorySessionStore();
  private final TokenResolver resolver = new TokenResolver();

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    RestDecisionContext.reset();
    RestSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void tearDown() {
    RestSessionRevocation.reset();
    RestDecisionContext.reset();
    JCustosServiceResolver.resetAll();
  }

  // ── the finding: REVOKED is read on the request path ──

  @Test
  @DisplayName("authentication filter: a REVOKED record ends the session - 401 with challenge, handler not run, one SessionInvalidated")
  void authenticationFilter_revokedRecord_isRefused() {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.ACTIVE));
    assertTrue(throughAuthentication(TOKEN).handlerRan, "the session works while its record is ACTIVE");
    audit.clear();

    store.save(record(SESSION, SessionStatus.REVOKED)); // the administrator revokes
    Outcome outcome = throughAuthentication(TOKEN);

    assertFalse(outcome.handlerRan, "the handler must not run for a revoked session");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), outcome.response.status);
    assertEquals("Unauthorized", outcome.response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        outcome.response.headers.get(RestHeaders.WWW_AUTHENTICATE));
    assertEquals(1, audit.events().size(), "audited once: " + audit.events());
    SessionInvalidated event = audit.single(SessionInvalidated.class);
    assertEquals("alice", event.subjectId());
    assertEquals(RestSessionRevocation.REASON_REVOKED, event.reason());
    assertEquals(SessionRef.of(TOKEN), event.sessionId());
    assertFalse(event.toString().contains(TOKEN), "the token must not reach the audit event");
  }

  @Test
  @DisplayName("authorisation filter: a REVOKED record ends the session although the subject holds the permission - one event, no AccessDenied, no AccessGranted")
  void authorizationFilter_revokedRecord_isRefused() throws NoSuchMethodException {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.ACTIVE));
    assertTrue(throughAuthorization(TOKEN).handlerRan);
    assertEquals(1, audit.all(AccessGranted.class).size());
    audit.clear();

    store.save(record(SESSION, SessionStatus.REVOKED));
    Outcome outcome = throughAuthorization(TOKEN);

    assertFalse(outcome.handlerRan, "the handler must not run for a revoked session");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), outcome.response.status);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        outcome.response.headers.get(RestHeaders.WWW_AUTHENTICATE));
    assertEquals(1, audit.events().size(), "audited once: " + audit.events());
    assertEquals(RestSessionRevocation.REASON_REVOKED, audit.single(SessionInvalidated.class).reason());
    assertTrue(audit.all(AccessDenied.class).isEmpty());
    assertTrue(audit.all(AccessGranted.class).isEmpty());
  }

  @Test
  @DisplayName("a record that was seen and is gone ends the session (revocation by delete)")
  void seenAndGone_isRefused() throws NoSuchMethodException {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.ACTIVE));
    assertTrue(throughAuthentication(TOKEN).handlerRan);
    audit.clear();

    assertTrue(store.delete(SESSION)); // the default revoke of the session management

    assertFalse(throughAuthentication(TOKEN).handlerRan);
    assertFalse(throughAuthorization(TOKEN).handlerRan);
    List<SessionInvalidated> events = audit.all(SessionInvalidated.class);
    assertEquals(2, events.size(), "one event per refused request: " + audit.events());
    assertEquals("alice", events.get(0).subjectId());
    assertEquals(SessionRef.of(TOKEN), events.get(0).sessionId());
  }

  @Test
  @DisplayName("only the revoked session is refused; another session of the same subject keeps working")
  void otherSession_keepsWorking() {
    String otherToken = "synthetic-token-alice-second-device";
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.REVOKED));
    store.save(record(SessionId.of(SessionRef.of(otherToken)), SessionStatus.ACTIVE));

    assertFalse(throughAuthentication(TOKEN).handlerRan);
    assertTrue(throughAuthentication(otherToken).handlerRan);
  }

  // ── the decisions mirrored from the Vaadin part ──

  @Test
  @DisplayName("EXPIRED alone does not end a session: the lifetime policy is the authority")
  void expiredRecord_isNotARevocation() throws NoSuchMethodException {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.EXPIRED));

    assertTrue(throughAuthentication(TOKEN).handlerRan);
    assertTrue(throughAuthorization(TOKEN).handlerRan);
    assertTrue(audit.all(SessionInvalidated.class).isEmpty());
  }

  @Test
  @DisplayName("a session the application never recorded is not affected")
  void neverRecorded_isNotAffected() {
    RestSessionRevocation.useSessionStore(store);

    assertTrue(throughAuthentication(TOKEN).handlerRan);
    assertTrue(throughAuthentication(TOKEN).handlerRan, "a second request without a record still passes");
    assertTrue(audit.all(SessionInvalidated.class).isEmpty());
  }

  @Test
  @DisplayName("a store failure is survived: the request proceeds to the other checks")
  void storeFailure_requestProceeds() throws NoSuchMethodException {
    RestSessionRevocation.useSessionStore(new CountingStore(store) {
      @Override public Optional<SessionRecord> findById(SessionId sessionId) {
        throw new IllegalStateException("store unreachable");
      }
    });

    assertTrue(throughAuthentication(TOKEN).handlerRan);
    assertTrue(throughAuthorization(TOKEN).handlerRan);
    assertTrue(audit.all(SessionInvalidated.class).isEmpty());
  }

  @Test
  @DisplayName("the check never writes the store")
  void checkNeverWrites() throws NoSuchMethodException {
    store.save(record(SESSION, SessionStatus.ACTIVE));
    CountingStore counting = new CountingStore(store);
    RestSessionRevocation.useSessionStore(counting);

    throughAuthentication(TOKEN);
    throughAuthorization(TOKEN);
    store.save(record(SESSION, SessionStatus.REVOKED));
    throughAuthentication(TOKEN);
    store.delete(SESSION);
    throughAuthorization(TOKEN);

    assertEquals(4, counting.reads.get(), "one lookup per request");
    assertEquals(0, counting.writes.get(), "no save, delete or rekey from the request path");
  }

  // ── opt-in ──

  @Test
  @DisplayName("without a registered store nothing changes: the resolver is not asked for a session id, the request is served")
  void noStore_noBehaviourChange() throws NoSuchMethodException {
    store.save(record(SESSION, SessionStatus.REVOKED)); // a store exists, but nobody registered it

    assertTrue(throughAuthentication(TOKEN).handlerRan);
    assertTrue(throughAuthorization(TOKEN).handlerRan);
    assertTrue(RestSessionRevocation.allow(resolver, request(TOKEN), new RecordingResponse()));
    assertEquals(0, resolver.sessionIdLookups.get(), "resolveSessionId must not be called");
    assertTrue(audit.all(SessionInvalidated.class).isEmpty());
  }

  @Test
  @DisplayName("a resolver that reports no session id passes every request, store or not")
  void resolverWithoutSessionId_passes() {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.REVOKED));
    RestSubjectResolver plain = request -> Optional.of(alice());

    Outcome outcome = new Outcome();
    new RestAuthenticationFilter(plain).requireAuthenticated(
        request(TOKEN), outcome.response, (rq, rs) -> outcome.handlerRan = true);

    assertTrue(outcome.handlerRan);
  }

  @Test
  @DisplayName("requireRecord(true): a session id without a record is refused without any memory")
  void requireRecord_refusesUnknownSessions() {
    RestSessionRevocation.useSessionStore(store);
    RestSessionRevocation.requireRecord(true);

    Outcome unknown = throughAuthentication(TOKEN);
    assertFalse(unknown.handlerRan);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), unknown.response.status);
    assertEquals("alice", audit.single(SessionInvalidated.class).subjectId());

    store.save(record(SESSION, SessionStatus.ACTIVE));
    assertTrue(throughAuthentication(TOKEN).handlerRan, "with its record the session is served");
  }

  @Test
  @DisplayName("a public handler is served without a session lookup")
  void publicHandler_isNotChecked() throws NoSuchMethodException {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.REVOKED));
    Outcome outcome = new Outcome();

    new RestAuthorizationFilter(resolver).authorizeAndHandle(
        request(TOKEN), outcome.response, (rq, rs) -> outcome.handlerRan = true,
        Handlers.class.getDeclaredMethod("open"));

    assertTrue(outcome.handlerRan);
    assertEquals(0, resolver.sessionIdLookups.get());
  }

  // ── rendering, audit robustness, the stand-alone check ──

  @Test
  @DisplayName("the refusal is rendered by the published mapper; a mapper that answers 'granted' still does not start the handler")
  void refusal_goesThroughThePublishedMapper() throws NoSuchMethodException {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.REVOKED));
    RestDecisionContext.publish((decision, response) -> {
      AuthorizationDecision.Unauthenticated unauthenticated =
          (AuthorizationDecision.Unauthenticated) decision;
      response.status(HttpStatus.UNAUTHORIZED.code());
      response.body("{\"title\":\"" + unauthenticated.reason() + "\"}");
      return true; // a mapper that gets its return value wrong
    });

    Outcome authentication = throughAuthentication(TOKEN);
    Outcome authorization = throughAuthorization(TOKEN);

    assertEquals("{\"title\":\"session-revoked\"}", authentication.response.body);
    assertEquals("{\"title\":\"session-revoked\"}", authorization.response.body);
    assertFalse(authentication.handlerRan);
    assertFalse(authorization.handlerRan);
  }

  @Test
  @DisplayName("a failing audit service does not let the revoked session through")
  void auditFailure_stillRefuses() {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.REVOKED));
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override public void publish(AuditEvent event) {
        throw new IllegalStateException("audit down");
      }

      @Override public List<AuditEvent> query(AuditQuery query) {
        return List.of();
      }
    });

    Outcome outcome = throughAuthentication(TOKEN);

    assertFalse(outcome.handlerRan);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), outcome.response.status);
  }

  @Test
  @DisplayName("allow(...) is the same check for request paths without the two filters")
  void standAloneCheck() {
    RestSessionRevocation.useSessionStore(store);
    store.save(record(SESSION, SessionStatus.ACTIVE));
    RecordingResponse served = new RecordingResponse();
    assertTrue(RestSessionRevocation.allow(resolver, request(TOKEN), served));
    assertEquals(HttpStatus.OK.code(), served.status, "a passing request is not touched");

    store.save(record(SESSION, SessionStatus.REVOKED));
    RecordingResponse refused = new RecordingResponse();
    assertFalse(RestSessionRevocation.allow(resolver, request(TOKEN), refused));

    assertEquals(HttpStatus.UNAUTHORIZED.code(), refused.status);
    SessionInvalidated event = audit.single(SessionInvalidated.class);
    assertEquals("alice", event.subjectId());
    assertEquals(SessionRef.of(TOKEN), event.sessionId());
  }

  @Test
  @DisplayName("the holder: a new store forgets the records seen in the old one; null switches the check off")
  void holderSemantics() {
    RestSessionRevocation.useSessionStore(store);
    assertSame(store, RestSessionRevocation.findSessionStore().orElseThrow());
    store.save(record(SESSION, SessionStatus.ACTIVE));
    assertTrue(throughAuthentication(TOKEN).handlerRan); // seen in the first store

    RestSessionRevocation.useSessionStore(new InMemorySessionStore()); // a redeploy with a fresh store
    assertTrue(throughAuthentication(TOKEN).handlerRan,
        "'seen in another store' must not read as 'removed from this one'");

    RestSessionRevocation.useSessionStore(null);
    assertTrue(RestSessionRevocation.findSessionStore().isEmpty());
    assertFalse(RestSessionRevocation.isRecordRequired());
  }

  @Test
  @DisplayName("the memory of seen records is bounded: beyond SEEN_CAPACITY the least recently seen session is forgotten")
  void seenMemory_isBounded() {
    RestSessionRevocation.useSessionStore(store);
    String first = "synthetic-token-0";
    for (int i = 0; i <= RestSessionRevocation.SEEN_CAPACITY; i++) {
      String token = "synthetic-token-" + i;
      SessionId id = SessionId.of(SessionRef.of(token));
      store.save(record(id, SessionStatus.ACTIVE));
      assertTrue(RestSessionRevocation.allow(resolver, request(token), new RecordingResponse()));
      store.delete(id);
    }
    String last = "synthetic-token-" + RestSessionRevocation.SEEN_CAPACITY;

    assertFalse(RestSessionRevocation.allow(resolver, request(last), new RecordingResponse()),
        "a session within the bound is recognised as revoked once its record is gone");
    assertTrue(RestSessionRevocation.allow(resolver, request(first), new RecordingResponse()),
        "the documented limit: the session pushed out of the memory reads as never recorded");
  }

  // ── helpers ──

  private Outcome throughAuthentication(String token) {
    Outcome outcome = new Outcome();
    new RestAuthenticationFilter(resolver).requireAuthenticated(
        request(token), outcome.response, (rq, rs) -> outcome.handlerRan = true);
    return outcome;
  }

  private Outcome throughAuthorization(String token) throws NoSuchMethodException {
    Outcome outcome = new Outcome();
    Method secured = Handlers.class.getDeclaredMethod("delete");
    new RestAuthorizationFilter(resolver).authorizeAndHandle(
        request(token), outcome.response, (rq, rs) -> outcome.handlerRan = true, secured, Handlers.class);
    return outcome;
  }

  private static RestRequest request(String token) {
    return new RestAuthorizationFilterTest.SimpleRestRequest(
        "DELETE", ROUTE, Map.of("Authorization", "Bearer " + token), Map.of());
  }

  private static SessionRecord record(SessionId id, SessionStatus status) {
    Instant login = Instant.now().minusSeconds(60);
    return new SessionRecord(id, new SubjectId("alice"), TenantId.DEFAULT,
        login, login, JCustosVersion.INITIAL, status);
  }

  private static JCustosSubject alice() {
    return new JCustosSubject("alice", "Alice", Set.of(), Set.of(new PermissionName("document:delete")));
  }

  /**
   * The resolver of an application with bearer tokens: every token authenticates alice,
   * the session record lives under the reference of the token, the session is young.
   */
  private static final class TokenResolver implements RestSubjectResolver {
    private final AtomicInteger sessionIdLookups = new AtomicInteger();
    private final BearerTokenExtractor extractor = new BearerTokenExtractor();

    @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
      return extractor.extract(request).map(token -> alice());
    }

    @Override public Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
      Instant now = Instant.now();
      return Optional.of(new SessionMetadata("alice", now.minusSeconds(60), now));
    }

    @Override public Optional<SessionId> resolveSessionId(RestRequest request) {
      sessionIdLookups.incrementAndGet();
      return extractor.extract(request).map(token -> SessionId.of(SessionRef.of(token)));
    }
  }

  /** A real store behind a counter - shows what the request path reads and writes. */
  private static class CountingStore implements SessionStore {
    private final SessionStore delegate;
    final AtomicInteger reads = new AtomicInteger();
    final AtomicInteger writes = new AtomicInteger();

    CountingStore(SessionStore delegate) {
      this.delegate = delegate;
    }

    @Override public void save(SessionRecord session) {
      writes.incrementAndGet();
      delegate.save(session);
    }

    @Override public Optional<SessionRecord> findById(SessionId sessionId) {
      reads.incrementAndGet();
      return delegate.findById(sessionId);
    }

    @Override public List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId) {
      reads.incrementAndGet();
      return delegate.findBySubject(tenant, subjectId);
    }

    @Override public boolean delete(SessionId sessionId) {
      writes.incrementAndGet();
      return delegate.delete(sessionId);
    }

    @Override public boolean rekey(SessionId from, SessionId to) {
      writes.incrementAndGet();
      return delegate.rekey(from, to);
    }

    @Override public List<SessionRecord> findAll() {
      reads.incrementAndGet();
      return delegate.findAll();
    }
  }

  private static final class Outcome {
    final RecordingResponse response = new RecordingResponse();
    boolean handlerRan;
  }

  private static final class RecordingResponse implements RestResponse {
    int status = HttpStatus.OK.code();
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String body) {
      this.body = body;
    }

    @Override public void header(String name, String value) {
      headers.put(name, value);
    }
  }

  static final class Handlers {
    @RequiresPermission("document:delete")
    void delete() {
    }

    void open() {
    }
  }
}
