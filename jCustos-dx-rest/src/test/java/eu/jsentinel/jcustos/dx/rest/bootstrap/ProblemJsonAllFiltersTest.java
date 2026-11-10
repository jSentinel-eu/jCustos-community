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
import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.rest.HttpStatusDecisionMapper;
import eu.jsentinel.jcustos.rest.RestAuthenticationFilter;
import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;
import eu.jsentinel.jcustos.rest.RestDecisionContext;
import eu.jsentinel.jcustos.rest.RestHeaders;
import eu.jsentinel.jcustos.rest.RestJCustosVersionContext;
import eu.jsentinel.jcustos.rest.RestJCustosVersionFilter;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-086 (CWE-778): acceptance test for the one seam every REST denial
 * renders through.
 *
 * <p>Until V00.84 a bootstrap configured with
 * {@code .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)} changed the
 * body of {@code RestAuthorizationFilter} only. {@code RestAuthenticationFilter}
 * and {@code RestJCustosVersionFilter} wrote status and body themselves, so an
 * API promising problem+json answered two of its three filters with the plain
 * text {@code Unauthorized}, without a challenge, and an anonymous request
 * stopped by the authentication filter left no audit event at all.
 *
 * <p>The tests drive the real bootstrap and the three real filters and assert
 * what goes on the wire, not what {@code runtime.services()} lists. No mocking
 * framework: the response is a recording implementation of the real interface,
 * the audit sink is {@link RecordingAuditSink}.
 *
 * <p>Known limit, deliberately not covered here: the mapper renders the
 * problem+json <em>body</em>; it does not set a {@code Content-Type} header.
 */
@DisplayName("JS-SEC-086 — all three REST filters render a 401 through the bootstrapped body strategy")
class ProblemJsonAllFiltersTest {

  /** What {@link ProblemJsonErrorBodyStrategy} renders for an unauthenticated request. */
  private static final String PROBLEM_JSON_UNAUTHORIZED =
      "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401}";

  private static final String ROUTE = "/api/documents/42";

  private static final SubjectId ALICE = new SubjectId("alice");

  private final RecordingAuditSink recording = new RecordingAuditSink();

  @BeforeEach
  @AfterEach
  void resetGlobals() {
    RestDecisionContext.reset();
    JCustosServiceResolver.resetAll();
  }

  private void installProblemJsonBootstrap(RestSubjectResolver resolver) {
    RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(resolver)
        .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)
        .audit(a -> a.securityAuditService(recording))
        .install();
  }

  @Test
  @DisplayName("authentication filter: no subject → 401 problem+json, Bearer challenge, AccessDenied audited")
  void authenticationFilter_rendersProblemJsonAndAudits() {
    RestSubjectResolver anonymous = request -> Optional.empty();
    installProblemJsonBootstrap(anonymous);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean handlerRan = new AtomicBoolean();

    new RestAuthenticationFilter(anonymous)
        .requireAuthenticated(request(), response, (rq, rs) -> handlerRan.set(true));

    assertFalse(handlerRan.get(), "the handler must not run for an anonymous request");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, response.body,
        "the bootstrapped body strategy must reach the authentication filter");
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE),
        "a 401 carries a challenge (RFC 7235)");

    AccessDenied denied = recording.single(AccessDenied.class);
    assertEquals("Unauthenticated:no-subject", denied.reason());
    assertEquals(ROUTE, denied.route());
    assertNull(denied.subjectId(), "an anonymous request has no subject to name");
  }

  @Test
  @DisplayName("authorisation filter: @RequiresRole without subject → 401 problem+json, Bearer challenge")
  void authorizationFilter_rendersProblemJson() throws NoSuchMethodException {
    RestSubjectResolver anonymous = request -> Optional.empty();
    installProblemJsonBootstrap(anonymous);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean handlerRan = new AtomicBoolean();
    Method secured = HandlerFixture.class.getDeclaredMethod("adminOnly");

    new RestAuthorizationFilter(anonymous)
        .authorizeAndHandle(request(), response, (rq, rs) -> handlerRan.set(true), secured);

    assertFalse(handlerRan.get(), "the handler must not run for an anonymous request");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE),
        "a 401 carries a challenge (RFC 7235)");
    assertTrue(recording.single(AccessDenied.class).reason().startsWith("Unauthenticated:"),
        "the authorisation filter audits its own denial, got: " + recording.events());
  }

  @Test
  @DisplayName("version filter: drifted session → 401 problem+json, SessionStale challenge, SessionStale audited")
  void versionFilter_rendersProblemJsonAndKeepsItsChallenge() {
    RestSubjectResolver drifted = new DriftedSessionResolver();
    installProblemJsonBootstrap(drifted);
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE)); // roles changed after login
    RecordingResponse response = new RecordingResponse();

    boolean allowed = new RestJCustosVersionFilter(
        drifted, new JCustosVersionEnforcer(versionStore, recording))
        .allow(request(), response);

    assertFalse(allowed, "a drifted session must be refused");
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, response.body,
        "the bootstrapped body strategy must reach the version filter");
    assertEquals(RestJCustosVersionFilter.SESSION_STALE_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE),
        "the specific challenge replaces the mapper's generic Bearer challenge");

    SessionStale stale = recording.single(SessionStale.class);
    assertEquals(ALICE.value(), stale.subjectId());
    assertEquals(ROUTE, stale.route());
  }

  @Test
  @DisplayName("one request refused by each filter: three identical bodies, every refusal in the audit trail")
  void allThreeFilters_shareOneBodyAndOneAuditTrail() throws NoSuchMethodException {
    RestSubjectResolver resolver = new DriftedSessionResolver() {
      @Override
      public Optional<JCustosSubject> resolveSubject(RestRequest request) {
        return Optional.empty();
      }
    };
    installProblemJsonBootstrap(resolver);
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE));

    RecordingResponse authentication = new RecordingResponse();
    new RestAuthenticationFilter(resolver)
        .requireAuthenticated(request(), authentication, (rq, rs) -> { });
    RecordingResponse authorization = new RecordingResponse();
    new RestAuthorizationFilter(resolver).authorizeAndHandle(
        request(), authorization, (rq, rs) -> { }, HandlerFixture.class.getDeclaredMethod("adminOnly"));
    RecordingResponse version = new RecordingResponse();
    new RestJCustosVersionFilter(resolver, new JCustosVersionEnforcer(versionStore, recording))
        .allow(request(), version);

    assertEquals(PROBLEM_JSON_UNAUTHORIZED, authentication.body);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, authorization.body);
    assertEquals(PROBLEM_JSON_UNAUTHORIZED, version.body);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), authentication.status);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), authorization.status);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), version.status);

    assertTrue(recording.all(AccessDenied.class).stream()
            .anyMatch(event -> "Unauthenticated:no-subject".equals(event.reason())),
        "the authentication filter's refusal must be in the audit trail, got: " + recording.events());
    assertEquals(2, recording.all(AccessDenied.class).size(),
        "authentication and authorisation filter each audit their denial, got: " + recording.events());
    assertEquals(1, recording.all(SessionStale.class).size());
  }

  private static RestRequest request() {
    return new SimpleRestRequest("GET", ROUTE, Map.of(), Map.of());
  }

  static final class HandlerFixture {
    @RequiresRole("ADMIN")
    void adminOnly() {
    }
  }

  /**
   * Resolver of a token store that recorded the security version at login:
   * alice is authenticated, her session still carries the initial snapshot.
   */
  static class DriftedSessionResolver implements RestSubjectResolver {
    @Override
    public Optional<JCustosSubject> resolveSubject(RestRequest request) {
      return Optional.of(new JCustosSubject(
          ALICE.value(), "Alice", Set.of(new RoleName("USER")), Set.of()));
    }

    @Override
    public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
      return Optional.of(new RestJCustosVersionContext(
          ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-1"));
    }
  }

  record SimpleRestRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters
  ) implements RestRequest {
  }

  static final class RecordingResponse implements RestResponse {
    int status = HttpStatus.OK.code();
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body;
    }

    @Override
    public void header(String name, String value) {
      headers.put(name, value);
    }
  }
}
