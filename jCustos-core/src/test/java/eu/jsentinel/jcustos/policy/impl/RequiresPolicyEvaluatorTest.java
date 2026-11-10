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
package eu.jsentinel.jcustos.policy.impl;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.PolicyEvaluated;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.policy.api.JCustosPolicies;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.api.PolicyDecisions;
import eu.jsentinel.jcustos.policy.api.SubjectPredicates;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequiresPolicyEvaluatorTest {

  private InMemoryPolicyRegistry registry;
  private RecordingAuditSink auditSink;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    registry = new InMemoryPolicyRegistry();
    JCustosServiceResolver.setPolicyRegistry(registry);
    auditSink = new RecordingAuditSink();
    JCustosServiceResolver.setJCustosAuditService(auditSink);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  private static AccessContext ctxWithSubject(JCustosSubject subject) {
    return new AccessContext(
        Optional.of(subject), "rest-endpoint", "/documents", "read", Map.of());
  }

  private static AccessContext anonymousCtx() {
    return new AccessContext(
        Optional.empty(), "rest-endpoint", "/documents", "read", Map.of());
  }

  private static RequiresPolicy annotationFor(String policyName) {
    return new RequiresPolicy() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresPolicy.class;
      }

      @Override
      public String value() {
        return policyName;
      }
    };
  }

  @Test
  @DisplayName("Allowed → Granted and emits PolicyEvaluated(Allowed)")
  void allowedDecisionGrantsAndAuditsAllowed() {
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    JCustosSubject admin = new JCustosSubject(
        "u-admin", "admin", Set.of(new RoleName("ADMIN")), Set.of());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(admin), annotationFor("p"));

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("u-admin", audit.subjectId());
    assertEquals("p", audit.policyName());
    assertEquals("Allowed", audit.decision());
  }

  @Test
  @DisplayName("Denied → Forbidden(reason) and emits PolicyEvaluated(Denied)")
  void deniedDecisionForbidsAndAuditsDenied() {
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    JCustosSubject user = new JCustosSubject(
        "u-user", "user", Set.of(new RoleName("USER")), Set.of());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(user), annotationFor("p"));

    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals("must be ADMIN", forbidden.reason());

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("u-user", audit.subjectId());
    assertEquals("Denied", audit.decision());
    assertEquals("must be ADMIN", audit.reason());
  }

  @Test
  @DisplayName("JS-SEC-157: anonymous subject → Unauthenticated(no-subject), audited with empty subjectId")
  void anonymousSubjectAudited() {
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("p"));

    // Up to 00.83.00 this was Forbidden: the policy ran with an empty subject. A missing
    // subject is a missing authentication, whatever the policy would have said.
    AuthorizationDecision.Unauthenticated unauthenticated =
        assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
    assertEquals(RequiresPolicyEvaluator.REASON_NO_SUBJECT, unauthenticated.reason());

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    // JCustosSubject is absent, subjectId reflects that.
    assertNull(audit.subjectId());
    assertEquals("p", audit.policyName());
    assertEquals("Denied", audit.decision());
    assertEquals(RequiresPolicyEvaluator.REASON_NO_SUBJECT, audit.reason());
  }

  // ── JS-SEC-157 (CWE-306, CWE-684): policy paths require authentication ──

  /** 12:00 UTC, inside the window of {@link #businessHours()}. */
  private static final Clock NOON = Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC);

  private static Policy businessHours() {
    return JCustosPolicies.timeWindow(
        "business-hours", LocalTime.of(9, 0), LocalTime.of(17, 0), ZoneOffset.UTC, NOON);
  }

  private static AccessContext ctxFromAddress(Optional<JCustosSubject> subject, String address) {
    return new AccessContext(
        subject, "rest-endpoint", "/reports", "read", Map.of("clientAddress", address));
  }

  @Test
  @DisplayName("JS-SEC-157: timeWindow inside the window grants no anonymous request")
  void timeWindowDoesNotGrantAnonymously() {
    registry.register(businessHours());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("business-hours"));

    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("JS-SEC-157: ipAllowList with a matching address grants no anonymous request")
  void ipAllowListDoesNotGrantAnonymously() {
    registry.register(JCustosPolicies.ipAllowList("office", "clientAddress", "10.0.0.0/8"));

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxFromAddress(Optional.empty(), "10.66.66.66"), annotationFor("office"));

    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("JS-SEC-157: without a subject the policy is not consulted at all")
  void anonymousRequestDoesNotEvaluateThePolicy() {
    AtomicInteger evaluations = new AtomicInteger();
    registry.register(Policy.named("p")
        .allowIf(c -> {
          evaluations.incrementAndGet();
          return true;
        })
        .build());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("p"));

    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
    assertEquals(0, evaluations.get(), "an anonymous request must not reach the predicates");
  }

  @Test
  @DisplayName("JS-SEC-157: with a subject the subject-free policies decide as before")
  void subjectFreePoliciesUnchangedWithSubject() {
    registry.register(businessHours());
    registry.register(JCustosPolicies.ipAllowList("office", "clientAddress", "10.0.0.0/8"));
    JCustosSubject user = new JCustosSubject("u-1", "user", Set.of(), Set.of());

    assertInstanceOf(AuthorizationDecision.Granted.class, new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(user), annotationFor("business-hours")));
    assertInstanceOf(AuthorizationDecision.Granted.class, new RequiresPolicyEvaluator()
        .evaluate(ctxFromAddress(Optional.of(user), "10.1.2.3"), annotationFor("office")));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, new RequiresPolicyEvaluator()
        .evaluate(ctxFromAddress(Optional.of(user), "203.0.113.50"), annotationFor("office")));
  }

  @Test
  @DisplayName("JS-SEC-157: a policy that opted in through JCustosPolicies.anonymous grants anonymously")
  void optInThroughWrapperGrantsAnonymously() {
    registry.register(JCustosPolicies.anonymous(businessHours()));
    registry.register(JCustosPolicies.anonymous(
        JCustosPolicies.ipAllowList("office", "clientAddress", "10.0.0.0/8")));

    assertInstanceOf(AuthorizationDecision.Granted.class, new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("business-hours")));
    assertInstanceOf(AuthorizationDecision.Granted.class, new RequiresPolicyEvaluator()
        .evaluate(ctxFromAddress(Optional.empty(), "10.1.2.3"), annotationFor("office")));
    // opted in means "evaluated", not "granted": outside the allow-list the policy still denies
    assertInstanceOf(AuthorizationDecision.Forbidden.class, new RequiresPolicyEvaluator()
        .evaluate(ctxFromAddress(Optional.empty(), "203.0.113.50"), annotationFor("office")));
  }

  @Test
  @DisplayName("JS-SEC-157: a policy that opted in through PolicyBuilder.allowAnonymous grants anonymously")
  void optInThroughBuilderGrantsAnonymously() {
    registry.register(Policy.named("status.public").allowIf(c -> true).allowAnonymous().build());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("status.public"));

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
    assertEquals("Allowed", auditSink.singlePolicyEvent().decision());
  }

  @Test
  @DisplayName("JS-SEC-157: the opt-in is explicit — default false, the wrapper copies and leaves the original closed")
  void optInIsExplicit() {
    Policy closed = businessHours();
    Policy open = JCustosPolicies.anonymous(closed);

    assertFalse(closed.allowsAnonymous(), "a shipped subject-free policy is not anonymous by default");
    assertTrue(open.allowsAnonymous());
    assertEquals(closed.name(), open.name());
    assertFalse(Policy.named("p").allowIf(c -> true).build().allowsAnonymous());
    assertFalse(registry.allowsAnonymous("not-registered"), "an unknown policy never allows anonymous");
  }

  @Test
  @DisplayName("JS-SEC-157: an unknown policy answers an anonymous request with Unauthenticated")
  void unknownPolicyAnonymousIsUnauthenticated() {
    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("missing"));

    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("unknown policy → Forbidden(\"unknown policy: ...\") and emits PolicyEvaluated(Denied)")
  void unknownPolicyDeniesGracefully() {
    // JS-SEC-157: evaluated with a subject - an anonymous request no longer reaches the lookup.
    JCustosSubject user = new JCustosSubject("u-user", "user", Set.of(), Set.of());
    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(user), annotationFor("missing"));

    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals("unknown policy: missing", forbidden.reason());

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("missing", audit.policyName());
    assertEquals("Denied", audit.decision());
    assertEquals("unknown policy: missing", audit.reason());
  }

  @Test
  @DisplayName("StepUpRequired is bridged to AuthorizationDecision.StepUpRequired with method + reason")
  void stepUpBridgedToTypedStepUp() {
    registry.register(Policy.named("p")
        .stepUpRequiredIf(c -> true, PolicyDecision.StepUpMethod.MFA, "needs mfa")
        .build());
    JCustosSubject user = new JCustosSubject(
        "u-1", "u-1", Set.of(), Set.of(new PermissionName("any")));

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(user), annotationFor("p"));

    AuthorizationDecision.StepUpRequired stepUp = assertInstanceOf(
        AuthorizationDecision.StepUpRequired.class, decision);
    assertEquals("needs mfa", stepUp.reason());
    assertEquals("MFA", stepUp.method());

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("StepUpRequired", audit.decision());
    assertTrue(audit.reason().startsWith("MFA"));
  }

  @Test
  @DisplayName("ResourceRef from AccessContext.attributes is promoted into PolicyContext")
  void resourceRefIsPromoted() {
    eu.jsentinel.jcustos.policy.api.ResourceRef expectedRef =
        new eu.jsentinel.jcustos.policy.api.ResourceRef("document", "42");
    AccessContext ctx = new AccessContext(
        Optional.of(new JCustosSubject("u-1", "u-1", Set.of(), Set.of())),
        "rest-endpoint",
        "/documents/42",
        "read",
        Map.of(
            eu.jsentinel.jcustos.policy.api.ResourceRef.ATTRIBUTE_KEY,
            expectedRef));

    java.util.concurrent.atomic.AtomicReference<
        eu.jsentinel.jcustos.policy.api.PolicyContext> captured =
        new java.util.concurrent.atomic.AtomicReference<>();
    registry.register(eu.jsentinel.jcustos.policy.api.Policy.named("p")
        .allowIf(policyCtx -> {
          captured.set(policyCtx);
          return true;
        })
        .build());

    new RequiresPolicyEvaluator().evaluate(ctx, annotationFor("p"));

    eu.jsentinel.jcustos.policy.api.PolicyContext seen = captured.get();
    assertEquals(expectedRef, seen.resourceRef().orElseThrow());
  }

  @Test
  @DisplayName("non-ResourceRef attribute value is ignored, resourceRef stays empty")
  void nonResourceRefAttributeIgnored() {
    // JS-SEC-157: needs a subject, otherwise the capturing predicate is never reached.
    AccessContext ctx = new AccessContext(
        Optional.of(new JCustosSubject("u-1", "u-1", Set.of(), Set.of())),
        "rest-endpoint",
        "/x",
        "read",
        Map.of(
            eu.jsentinel.jcustos.policy.api.ResourceRef.ATTRIBUTE_KEY,
            "not-a-ref"));

    java.util.concurrent.atomic.AtomicReference<
        eu.jsentinel.jcustos.policy.api.PolicyContext> captured =
        new java.util.concurrent.atomic.AtomicReference<>();
    registry.register(eu.jsentinel.jcustos.policy.api.Policy.named("p")
        .allowIf(policyCtx -> {
          captured.set(policyCtx);
          return true;
        })
        .build());

    new RequiresPolicyEvaluator().evaluate(ctx, annotationFor("p"));

    assertTrue(captured.get().resourceRef().isEmpty());
  }

  @Test
  @DisplayName("audit sink that throws does not break the evaluator")
  void auditFailureIsSwallowed() {
    JCustosServiceResolver.setJCustosAuditService(new ThrowingAuditSink());
    registry.register(Policy.named("p").allowIf(c -> true).build());

    JCustosSubject anyone = new JCustosSubject(
        "u-1", "u-1", Set.of(), Set.of());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(anyone), annotationFor("p"));

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  private static final class RecordingAuditSink implements JCustosAuditService {
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return Collections.unmodifiableList(events);
    }

    PolicyEvaluated singlePolicyEvent() {
      var policyEvents = events.stream()
          .filter(PolicyEvaluated.class::isInstance)
          .map(PolicyEvaluated.class::cast)
          .toList();
      if (policyEvents.size() != 1) {
        throw new AssertionError(
            "expected exactly one PolicyEvaluated event, got " + policyEvents.size());
      }
      return policyEvents.getFirst();
    }
  }

  private static final class ThrowingAuditSink implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
      throw new RuntimeException("boom");
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }
}
