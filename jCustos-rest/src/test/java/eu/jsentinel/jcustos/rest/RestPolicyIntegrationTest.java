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

import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.policy.api.JCustosPolicies;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.api.SubjectPredicates;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@code @RequiresPolicy} flows through the existing
 * {@link RestAuthorizationFilter} without any filter changes — the
 * annotation, evaluator, registry, and bridge are wired up entirely in
 * {@code security-core}.
 */
@DisplayName("RestAuthorizationFilter with @RequiresPolicy")
class RestPolicyIntegrationTest {

  private InMemoryPolicyRegistry registry;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    registry = new InMemoryPolicyRegistry();
    registry.register(Policy.named("test.policy")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());
    registry.register(Policy.named("test.step-up")
        .stepUpRequiredIf(c -> true, PolicyDecision.StepUpMethod.MFA, "needs mfa")
        .build());
    JCustosServiceResolver.setPolicyRegistry(registry);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("admin subject is granted, handler runs")
  void adminGranted() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new RoleName("ADMIN")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (req, res) -> {
          executed.set(true);
          res.status(204);
        },
        securedMethod());

    assertTrue(executed.get(), "ADMIN must reach the handler");
    assertEquals(204, response.status);
  }

  @Test
  @DisplayName("non-admin subject is forbidden (403)")
  void nonAdminForbidden() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new RoleName("USER")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (req, res) -> executed.set(true),
        securedMethod());

    assertEquals(403, response.status);
    assertEquals("Forbidden", response.body);
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("JS-SEC-157: anonymous request is unauthenticated (401 + Bearer challenge), the policy is not consulted")
  void anonymousUnauthenticated() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(
        request(),
        response,
        (req, res) -> executed.set(true),
        securedMethod());

    // Subject resolves to empty → filter skips session check, AccessContext
    // carries Optional.empty() subject → RequiresPolicyEvaluator answers
    // Unauthenticated before the policy runs → 401. Up to 00.83.00 the policy ran
    // with an empty subject and this was a 403.
    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("JS-SEC-157: a subject-free policy (ipAllowList) does not open the route to an anonymous request")
  void anonymousSubjectFreePolicyUnauthenticated() throws NoSuchMethodException {
    registry.register(JCustosPolicies.ipAllowList(
        "test.policy", RestAccessContextFactory.CLIENT_ADDRESS_ATTRIBUTE, "10.0.0.0/8"));
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(
        requestFrom("10.1.2.3"),
        response,
        (req, res) -> executed.set(true),
        securedMethod());

    assertEquals(401, response.status);
    assertFalse(executed.get(), "an address inside the allow-list is not an authentication");
  }

  @Test
  @DisplayName("JS-SEC-157: the same policy, opted in with JCustosPolicies.anonymous, admits the anonymous request")
  void anonymousOptInPolicyGranted() throws NoSuchMethodException {
    registry.register(JCustosPolicies.anonymous(JCustosPolicies.ipAllowList(
        "test.policy", RestAccessContextFactory.CLIENT_ADDRESS_ATTRIBUTE, "10.0.0.0/8")));
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(
        requestFrom("10.1.2.3"),
        response,
        (req, res) -> {
          executed.set(true);
          res.status(204);
        },
        securedMethod());

    assertTrue(executed.get(), "the explicit opt-in keeps anonymous policies possible");
    assertEquals(204, response.status);
  }

  @Test
  @DisplayName("missing policy registration is forbidden (no throw)")
  void missingPolicyRegistrationForbidden() throws NoSuchMethodException {
    JCustosServiceResolver.setPolicyRegistry(new InMemoryPolicyRegistry());
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new RoleName("ADMIN")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (req, res) -> executed.set(true),
        securedMethod());

    assertEquals(403, response.status);
    assertEquals("Forbidden", response.body);
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("StepUpRequired policy yields 401 + RFC-7235 challenge, handler does not run")
  void stepUpReturns401WithChallenge() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new RoleName("USER")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (req, res) -> executed.set(true),
        stepUpSecuredMethod());

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals("StepUp method=\"MFA\"",
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
    assertFalse(executed.get(), "handler must not run when step-up is required");
  }

  private static Method securedMethod() throws NoSuchMethodException {
    return HandlerFixture.class.getDeclaredMethod("delete");
  }

  private static Method stepUpSecuredMethod() throws NoSuchMethodException {
    return HandlerFixture.class.getDeclaredMethod("sensitive");
  }

  private static RestRequest request() {
    return new RestAuthorizationFilterTest.SimpleRestRequest(
        "DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  /** A request whose transport reports {@code peer} as the connection peer (default resolver). */
  private static RestRequest requestFrom(String peer) {
    return new RestRequest() {
      @Override
      public String method() {
        return "DELETE";
      }

      @Override
      public String path() {
        return "/api/documents/42";
      }

      @Override
      public Map<String, String> headers() {
        return Map.of();
      }

      @Override
      public Map<String, String> queryParameters() {
        return Map.of();
      }

      @Override
      public Optional<String> remoteAddress() {
        return Optional.ofNullable(peer);
      }
    };
  }

  private static JCustosSubject subject(Set<RoleName> roles) {
    return new JCustosSubject("u1", "User", roles, Set.of());
  }

  static final class HandlerFixture {
    @RequiresPolicy("test.policy")
    void delete() {
    }

    @RequiresPolicy("test.step-up")
    void sensitive() {
    }
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;
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
