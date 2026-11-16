/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.rest.HttpStatusDecisionMapper;
import eu.jsentinel.jcustos.rest.RestAuthenticationFilter;
import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;
import eu.jsentinel.jcustos.rest.RestDecisionContext;
import eu.jsentinel.jcustos.rest.RestHeaders;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.rest.RestSessionRevocation;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613), REST part, through the real bootstrap: the store configured with
 * {@code .sessions(s -> s.storeBacked(...))} reaches the REST filters, and a revoked
 * session is answered with the configured problem+json body.
 */
@DisplayName("JS-SEC-131 - the REST bootstrap hands the SessionStore to the filters")
class RestSessionRevocationBootstrapTest {

  private static final String PROBLEM_JSON_UNAUTHORIZED =
      "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401}";

  private static final String SESSION_KEY = "session-row-4711";

  private final RecordingAuditSink recording = new RecordingAuditSink();
  private final InMemorySessionStore store = new InMemorySessionStore();
  private final RestSubjectResolver resolver = new RecordedSessionResolver();

  @BeforeEach
  @AfterEach
  void resetGlobals() {
    RestDecisionContext.reset();
    RestSessionRevocation.reset();
    JCustosServiceResolver.resetAll();
  }

  private RestJCustosBootstrap bootstrap() {
    return RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(resolver)
        .logout(new SubjectClearingLogoutService<>(new InMemorySubjectStore(), String.class))
        .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)
        .audit(a -> a.securityAuditService(recording));
  }

  @Test
  @DisplayName(".storeBacked(store) registers the store with the filters and is no longer reported as unused")
  void storeBacked_isPublished() {
    JCustosRuntime runtime = bootstrap()
        .sessions(s -> s.storeBacked(store).timeout(Duration.ofMinutes(15)))
        .install();

    assertSame(store, RestSessionRevocation.findSessionStore().orElseThrow());
    assertFalse(runtime.warnings().stream().anyMatch(w -> "rest/session-store-unused".equals(w.code())),
        "REST reads the store now, got: " + runtime.warnings());
    assertTrue(runtime.services().stream().anyMatch(s -> s.spi() == SessionStore.class),
        "the store is listed among the registered services, got: " + runtime.services());
    assertEquals(1, runtime.services().stream().filter(s -> s.spi() == SessionStore.class).count(),
        "listed once, by the shared base: " + runtime.services());
    assertTrue(runtime.services().stream().anyMatch(s -> s.spi() == RestSessionRevocation.class
            && "bootstrap-session-revocation".equals(s.source())),
        "the revocation wiring is listed as in the Vaadin bootstrap, got: " + runtime.services());
  }

  @Test
  @DisplayName("a bootstrap without a store leaves a store the application registered itself in place")
  void noStoreConfigured_holderUntouched() {
    RestSessionRevocation.useSessionStore(store);

    bootstrap().install();

    assertSame(store, RestSessionRevocation.findSessionStore().orElseThrow());
  }

  @Test
  @DisplayName("revoked session: both filters answer 401 problem+json with a challenge, the handler does not run, SessionInvalidated is audited")
  void revokedSession_isRefusedWithProblemJson() throws NoSuchMethodException {
    bootstrap().sessions(s -> s.storeBacked(store).timeout(Duration.ofMinutes(15))).install();
    store.save(record(SessionStatus.ACTIVE));
    assertTrue(authenticated().handlerRan.get(), "the session works while its record is ACTIVE");
    assertTrue(authorized().handlerRan.get());

    store.save(record(SessionStatus.REVOKED)); // the administrator revokes
    recording.clear();
    Outcome authentication = authenticated();
    Outcome authorization = authorized();

    for (Outcome outcome : new Outcome[] {authentication, authorization}) {
      assertFalse(outcome.handlerRan.get(), "the handler must not run for a revoked session");
      assertEquals(HttpStatus.UNAUTHORIZED.code(), outcome.response.status);
      assertEquals(PROBLEM_JSON_UNAUTHORIZED, outcome.response.body,
          "the bootstrapped body strategy renders the refusal");
      assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
          outcome.response.headers.get(RestHeaders.WWW_AUTHENTICATE));
    }
    assertEquals(2, recording.events().size(), "one event per refused request: " + recording.events());
    for (SessionInvalidated event : recording.all(SessionInvalidated.class)) {
      assertEquals("alice", event.subjectId());
      assertEquals(RestSessionRevocation.REASON_REVOKED, event.reason());
      assertEquals(SessionRef.of(SESSION_KEY), event.sessionId());
    }
    assertEquals(2, recording.all(SessionInvalidated.class).size());
  }

  private Outcome authenticated() {
    Outcome outcome = new Outcome();
    new RestAuthenticationFilter(resolver).requireAuthenticated(
        request(), outcome.response, (rq, rs) -> outcome.handlerRan.set(true));
    return outcome;
  }

  private Outcome authorized() throws NoSuchMethodException {
    Outcome outcome = new Outcome();
    new RestAuthorizationFilter(resolver).authorizeAndHandle(
        request(), outcome.response, (rq, rs) -> outcome.handlerRan.set(true),
        Handlers.class.getDeclaredMethod("userOnly"), Handlers.class);
    return outcome;
  }

  private static SessionRecord record(SessionStatus status) {
    Instant login = Instant.now().minusSeconds(60);
    return new SessionRecord(SessionId.of(SESSION_KEY), new SubjectId("alice"), TenantId.DEFAULT,
        login, login, JCustosVersion.INITIAL, status);
  }

  private static RestRequest request() {
    return new ProblemJsonAllFiltersTest.SimpleRestRequest("GET", "/api/documents/42", Map.of(), Map.of());
  }

  /** Alice is authenticated; her session is recorded under a non-secret row id. */
  private static final class RecordedSessionResolver implements RestSubjectResolver {
    @Override public Optional<JCustosSubject> resolveSubject(RestRequest request) {
      return Optional.of(new JCustosSubject("alice", "Alice", Set.of(new RoleName("USER")), Set.of()));
    }

    @Override public Optional<SessionId> resolveSessionId(RestRequest request) {
      return Optional.of(SessionId.of(SESSION_KEY));
    }
  }

  private static final class Outcome {
    final Recording response = new Recording();
    final AtomicBoolean handlerRan = new AtomicBoolean();
  }

  private static final class Recording implements RestResponse {
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
    @RequiresRole("USER")
    void userOnly() {
    }
  }
}
