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
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CSRF (CWE-352): the three jCustos REST filters run an installed {@link RestOriginGuard}
 * before their own checks - the subject is not even resolved for a refused request - and leave
 * everything unchanged while no guard is installed. Real filters, real store-backed audit.
 */
@DisplayName("The jCustos REST filters run the installed RestOriginGuard first (CSRF, CWE-352)")
class RestOriginGuardFilterChainTest {

  private final InMemoryAuditEventStore store = new InMemoryAuditEventStore();
  private final AtomicInteger resolved = new AtomicInteger();
  private final AtomicInteger handled = new AtomicInteger();
  private final RestSubjectResolver subjects = request -> {
    resolved.incrementAndGet();
    return Optional.of(new JCustosSubject("alice", "Alice", Set.of(),
        Set.of(new PermissionName("document:delete"))));
  };

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(new StoreBackedJCustosAuditService(store));
  }

  @AfterEach
  void tearDown() {
    RestOriginGuard.reset();
    RestDecisionContext.reset();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("authentication filter: a cross-origin POST is 403 and audited once; no subject is resolved, the handler does not run")
  void authenticationFilter() {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    RestOriginGuardTest.Response response = new RestOriginGuardTest.Response();

    new RestAuthenticationFilter(subjects).requireAuthenticated(crossOrigin(), response, counting());

    assertRefused(response);
    assertEquals(0, resolved.get(), "the guard runs before the subject is resolved");
  }

  @Test
  @DisplayName("authorisation filter: a cross-origin POST to a restricted and to a public handler is 403, through the filter's own mapper")
  void authorizationFilter() throws NoSuchMethodException {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    RestOriginGuardTest.Response restricted = new RestOriginGuardTest.Response();
    RestOriginGuardTest.Response open = new RestOriginGuardTest.Response();
    AtomicInteger mapped = new AtomicInteger();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(subjects, (decision, response) -> {
      mapped.incrementAndGet();
      return new HttpStatusDecisionMapper().apply(decision, response);
    });

    filter.authorizeAndHandle(crossOrigin(), restricted, counting(),
        Handlers.class.getDeclaredMethod("delete"), Handlers.class);
    filter.authorizeAndHandle(crossOrigin(), open, counting(),
        Handlers.class.getDeclaredMethod("login"), Handlers.class);

    assertEquals(HttpStatus.FORBIDDEN.code(), restricted.status);
    assertEquals(HttpStatus.FORBIDDEN.code(), open.status);
    assertEquals(2, mapped.get(), "the filter's explicit mapper renders the guard's refusal");
    assertEquals(0, handled.get());
    assertEquals(0, resolved.get());
    assertEquals(2, envelopes().size(), "one AccessDenied per refused request, no AccessGranted");
  }

  @Test
  @DisplayName("version filter: a cross-origin POST is refused before the drift check")
  void versionFilter() {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    RestOriginGuardTest.Response response = new RestOriginGuardTest.Response();

    boolean allowed = new RestJCustosVersionFilter(subjects, new JCustosVersionEnforcer(
        new InMemoryJCustosVersionStore(), JCustosServiceResolver.securityAuditService()))
        .allow(crossOrigin(), response);

    assertFalse(allowed);
    assertRefused(response);
  }

  @Test
  @DisplayName("same origin passes every filter; without an installed guard a cross-origin POST is served as before")
  void sameOriginAndNoGuard_areUnchanged() throws NoSuchMethodException {
    RestOriginGuard.install(RestOriginGuard.sameOrigin());
    RestRequest own = new RestOriginGuardTest.HeaderRequest("POST", "/api/documents/42", Map.of(
        "Host", List.of("app.example"), "Origin", List.of("https://app.example")));
    new RestAuthenticationFilter(subjects).requireAuthenticated(own,
        new RestOriginGuardTest.Response(), counting());
    new RestAuthorizationFilter(subjects).authorizeAndHandle(own, new RestOriginGuardTest.Response(),
        counting(), Handlers.class.getDeclaredMethod("delete"), Handlers.class);
    assertEquals(2, handled.get());

    RestOriginGuard.reset();
    new RestAuthenticationFilter(subjects).requireAuthenticated(crossOrigin(),
        new RestOriginGuardTest.Response(), counting());
    assertEquals(3, handled.get(), "no guard installed: nothing changes");
  }

  private void assertRefused(RestOriginGuardTest.Response response) {
    assertEquals(HttpStatus.FORBIDDEN.code(), response.status);
    assertEquals(0, handled.get());
    List<AuditEnvelope> envelopes = envelopes();
    assertEquals(1, envelopes.size(), envelopes.toString());
    AccessDenied denied = assertInstanceOf(AccessDenied.class, envelopes.getFirst().event());
    assertEquals(RestOriginGuard.REASON_ORIGIN_MISMATCH, denied.reason());
    assertNotNull(envelopes.getFirst().correlationId());
    assertTrue(denied.subjectId() == null);
  }

  private List<AuditEnvelope> envelopes() {
    return store.query(TenantId.DEFAULT, AuditQuery.all());
  }

  private RestHandler counting() {
    return (request, response) -> handled.incrementAndGet();
  }

  private static RestRequest crossOrigin() {
    return new RestOriginGuardTest.HeaderRequest("POST", "/api/documents/42", Map.of(
        "Host", List.of("app.example"), "Origin", List.of("https://attacker.example"),
        "Sec-Fetch-Site", List.of("cross-site"), "Cookie", List.of("APP_SESSION=1f2e")));
  }

  static final class Handlers {
    @RequiresPermission("document:delete")
    void delete() {
    }

    @PublicRoute
    void login() {
    }
  }
}
