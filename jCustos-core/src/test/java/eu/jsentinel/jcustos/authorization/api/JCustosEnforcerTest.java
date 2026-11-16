/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.annotations.RequiresAllPermissions;
import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.policy.api.JCustosPolicies;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyContext;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosEnforcerTest {

  static final class TestUser {
    final String name;
    final Set<String> roles;
    final Set<String> perms;

    TestUser(String name, Set<String> roles, Set<String> perms) {
      this.name = name;
      this.roles = roles;
      this.perms = perms;
    }

    @Override public String toString() { return name; }
  }

  static final class TestAuthn implements AuthenticationService<String, TestUser> {
    @Override public boolean checkCredentials(String creds) { return false; }
    @Override public TestUser loadSubject(String creds) { return null; }
    @Override public Class<TestUser> subjectType() { return TestUser.class; }
  }

  static final class TestAuthz implements AuthorizationService<TestUser> {
    @Override public HasRoles rolesFor(TestUser u) {
      return () -> u.roles.stream().map(RoleName::new).toList();
    }
    @Override public HasPermissions permissionsFor(TestUser u) {
      return () -> u.perms.stream().map(PermissionName::new).toList();
    }
  }

  /** In-memory SubjectStore that ignores hard ThreadLocal vs Vaadin choice. */
  static final class HeapSubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> store = new HashMap<>();
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      Object v = store.get(subjectType);
      return Optional.ofNullable(subjectType.cast(v));
    }
    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      store.put(subjectType, subject);
    }
    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      store.remove(subjectType);
    }
  }

  /** Registry that maps a fixed name to a fixed decision. */
  static final class FixedRegistry implements PolicyRegistry {
    private final Map<String, PolicyDecision> map = new HashMap<>();
    void bind(String name, PolicyDecision decision) { map.put(name, decision); }
    @Override public Optional<Policy> find(String name) { return Optional.empty(); }
    @Override public void register(Policy policy) { /* unused in this test */ }
    @Override public PolicyDecision evaluate(String name, PolicyContext ctx) {
      PolicyDecision d = map.get(name);
      if (d == null) {
        throw new IllegalStateException("unknown policy: " + name);
      }
      return d;
    }
  }

  private HeapSubjectStore store;
  private FixedRegistry policies;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setAuthenticationService(new TestAuthn());
    JCustosServiceResolver.setAuthorizationService(new TestAuthz());
    store = new HeapSubjectStore();
    SubjectStores.setSubjectStore(store);
    policies = new FixedRegistry();
    JCustosServiceResolver.setPolicyRegistry(policies);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  private void bind(TestUser user) {
    store.setCurrentSubject(user, TestUser.class);
  }

  // ── requirePermission / requireAllPermissions ─────────────────────

  @Test
  @DisplayName("requirePermission passes when subject holds it")
  void requirePermissionHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    assertDoesNotThrow(() -> JCustosEnforcer.requirePermission("doc:read"));
  }

  @Test
  @DisplayName("requirePermission throws when subject misses it")
  void requirePermissionMissing() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requirePermission("doc:delete"));
    assertTrue(ex.getMessage().contains("doc:delete"));
  }

  @Test
  @DisplayName("requirePermission throws when no subject is bound")
  void requirePermissionNoSubject() {
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requirePermission("doc:read"));
    assertTrue(ex.getMessage().contains("No authenticated subject"));
  }

  @Test
  @DisplayName("requireAllPermissions passes when subject holds every one")
  void requireAllPermissionsHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read", "doc:write")));
    assertDoesNotThrow(() -> JCustosEnforcer.requireAllPermissions("doc:read", "doc:write"));
  }

  @Test
  @DisplayName("requireAllPermissions throws when one is missing")
  void requireAllPermissionsOneMissing() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requireAllPermissions("doc:read", "doc:write"));
    assertTrue(ex.getMessage().contains("doc:read"));
    assertTrue(ex.getMessage().contains("doc:write"));
  }

  @Test
  @DisplayName("requireAllPermissions rejects empty/null input with IAE")
  void requireAllPermissionsEmpty() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    assertThrows(IllegalArgumentException.class,
        () -> JCustosEnforcer.requireAllPermissions());
    assertThrows(IllegalArgumentException.class,
        () -> JCustosEnforcer.requireAllPermissions((String[]) null));
  }

  // ── requireAnyPermission ──────────────────────────────────────────

  @Test
  @DisplayName("requireAnyPermission passes when any candidate held")
  void requireAnyPermissionOneHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    assertDoesNotThrow(() -> JCustosEnforcer.requireAnyPermission("doc:write", "doc:read"));
  }

  @Test
  @DisplayName("requireAnyPermission throws when none held")
  void requireAnyPermissionNoneHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requireAnyPermission("doc:delete", "doc:purge"));
    assertTrue(ex.getMessage().contains("doc:delete"));
    assertTrue(ex.getMessage().contains("doc:purge"));
  }

  @Test
  @DisplayName("requireAnyPermission rejects empty input")
  void requireAnyPermissionEmpty() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    assertThrows(IllegalArgumentException.class,
        () -> JCustosEnforcer.requireAnyPermission());
    assertThrows(IllegalArgumentException.class,
        () -> JCustosEnforcer.requireAnyPermission((String[]) null));
  }

  // ── requireRole / requireAnyRole ──────────────────────────────────

  @Test
  @DisplayName("requireRole passes when subject holds it")
  void requireRoleHeld() {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    assertDoesNotThrow(() -> JCustosEnforcer.requireRole("ADMIN"));
  }

  @Test
  @DisplayName("requireRole throws when subject misses it")
  void requireRoleMissing() {
    bind(new TestUser("alice", Set.of("VIEWER"), Set.of()));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requireRole("ADMIN"));
    assertTrue(ex.getMessage().contains("ADMIN"));
  }

  @Test
  @DisplayName("requireAnyRole honours role hierarchy")
  void requireAnyRoleHonoursHierarchy() {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    JCustosServiceResolver.setRoleHierarchy(new RoleHierarchy() {
      @Override public Set<RoleName> impliedRoles(RoleName role) {
        if ("ADMIN".equals(role.value())) {
          return Set.of(new RoleName("ADMIN"), new RoleName("VIEWER"));
        }
        return Set.of(role);
      }
    });
    // VIEWER is implied by ADMIN — must pass
    assertDoesNotThrow(() -> JCustosEnforcer.requireRole("VIEWER"));
  }

  @Test
  @DisplayName("requireAnyRole rejects empty input")
  void requireAnyRoleEmpty() {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    assertThrows(IllegalArgumentException.class,
        () -> JCustosEnforcer.requireAnyRole());
    assertThrows(IllegalArgumentException.class,
        () -> JCustosEnforcer.requireAnyRole((String[]) null));
  }

  // ── requirePolicy ─────────────────────────────────────────────────

  @Test
  @DisplayName("requirePolicy with Allowed decision falls through")
  void requirePolicyAllowed() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("any-policy", PolicyDecision.allowed("ok"));
    assertDoesNotThrow(() -> JCustosEnforcer.requirePolicy("any-policy"));
  }

  @Test
  @DisplayName("requirePolicy with Denied throws with the policy reason")
  void requirePolicyDenied() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("doc-owner", PolicyDecision.denied("not the owner"));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requirePolicy("doc-owner"));
    assertTrue(ex.getMessage().contains("doc-owner"));
    assertTrue(ex.getMessage().contains("not the owner"));
  }

  @Test
  @DisplayName("requirePolicy with StepUpRequired throws with method + reason")
  void requirePolicyStepUp() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("doc-sensitive",
        PolicyDecision.stepUpRequired("high-value operation",
            PolicyDecision.StepUpMethod.MFA));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requirePolicy("doc-sensitive"));
    assertTrue(ex.getMessage().contains("step-up"));
    assertTrue(ex.getMessage().contains("MFA"));
    assertTrue(ex.getMessage().contains("high-value operation"));
  }

  @Test
  @DisplayName("requirePolicy 4-arg overload propagates resource/operation into the context")
  void requirePolicyWithContext() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    final AccessContext[] captured = new AccessContext[1];
    PolicyRegistry capturing = new PolicyRegistry() {
      @Override public Optional<Policy> find(String name) { return Optional.empty(); }
      @Override public void register(Policy policy) { /* unused */ }
      @Override public PolicyDecision evaluate(String n, PolicyContext c) {
        captured[0] = c.accessContext();
        return PolicyDecision.allowed("ok");
      }
    };
    JCustosServiceResolver.setPolicyRegistry(capturing);
    JCustosEnforcer.requirePolicy("doc.read", "document", "doc-42", "read");
    assertEquals("document", captured[0].resourceType());
    assertEquals("doc-42", captured[0].resourceName());
    assertEquals("read", captured[0].operation());
  }

  // ── JS-SEC-157 (CWE-306, CWE-684): requirePolicy requires a subject ──

  /** A window that contains the fixed clock: the policy itself always allows. */
  private static Policy businessHours() {
    return JCustosPolicies.timeWindow("business-hours", LocalTime.of(9, 0), LocalTime.of(17, 0),
        ZoneOffset.UTC, Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC));
  }

  @Test
  @DisplayName("JS-SEC-157: requirePolicy without a bound subject throws, although the policy would allow")
  void requirePolicyWithoutSubjectThrows() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    registry.register(businessHours());
    JCustosServiceResolver.setPolicyRegistry(registry);

    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requirePolicy("business-hours"));
    assertTrue(ex.getMessage().contains("business-hours"));
    assertTrue(ex.getMessage().contains("no subject"));
    assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.requirePolicy("business-hours", "document", "doc-42", "read"));
  }

  @Test
  @DisplayName("JS-SEC-157: requirePolicy without a subject does not evaluate the policy")
  void requirePolicyWithoutSubjectDoesNotEvaluate() {
    // FixedRegistry.evaluate would answer Allowed; it must not be asked.
    policies.bind("any-policy", PolicyDecision.allowed("ok"));

    assertThrows(AccessDeniedException.class, () -> JCustosEnforcer.requirePolicy("any-policy"));
  }

  @Test
  @DisplayName("JS-SEC-157: with a bound subject the same policy passes as before")
  void requirePolicyWithSubjectUnchanged() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    registry.register(businessHours());
    JCustosServiceResolver.setPolicyRegistry(registry);
    bind(new TestUser("alice", Set.of(), Set.of()));

    assertDoesNotThrow(() -> JCustosEnforcer.requirePolicy("business-hours"));
  }

  @Test
  @DisplayName("JS-SEC-157: a policy that opted in to anonymous evaluation passes without a subject")
  void requirePolicyAnonymousOptIn() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    registry.register(JCustosPolicies.anonymous(businessHours()));
    JCustosServiceResolver.setPolicyRegistry(registry);

    assertDoesNotThrow(() -> JCustosEnforcer.requirePolicy("business-hours"));
  }

  @Test
  @DisplayName("JS-SEC-157: enforce on @RequiresPolicy without a subject throws, although the policy would allow")
  void enforceRequiresPolicyWithoutSubjectThrows() throws Exception {
    policies.bind("doc.policy", PolicyDecision.allowed("ok"));
    Method m = MixedClass.class.getMethod("policy");

    assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.enforce(m, MixedClass.class));
  }

  // ── enforce(...) generic path ─────────────────────────────────────

  @RequiresPermission("doc:read")
  static class AnnotatedClass {
    public void readDoc() {}
    public void unrelated() {}
  }

  @RequiresRole("ADMIN")
  static class AdminClass {
    public void adminOnly() {}
  }

  @Test
  @DisplayName("enforce reads class-level @RequiresPermission and passes when held")
  void enforceClassLevelPermissionHeld() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    Method m = AnnotatedClass.class.getMethod("readDoc");
    assertDoesNotThrow(() -> JCustosEnforcer.enforce(m, AnnotatedClass.class));
  }

  @Test
  @DisplayName("enforce throws when subject lacks the class-level permission")
  void enforceClassLevelPermissionMissing() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of()));
    Method m = AnnotatedClass.class.getMethod("readDoc");
    assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.enforce(m, AnnotatedClass.class));
  }

  @Test
  @DisplayName("enforce reads class-level @RequiresRole")
  void enforceClassLevelRole() throws Exception {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    Method m = AdminClass.class.getMethod("adminOnly");
    assertDoesNotThrow(() -> JCustosEnforcer.enforce(m, AdminClass.class));
  }

  @Test
  @DisplayName("enforce on an unannotated element is a no-op")
  void enforceUnannotated() throws Exception {
    // No annotation on this class — no subject required
    Method m = NoAnnotationClass.class.getMethod("doStuff");
    assertDoesNotThrow(
        () -> JCustosEnforcer.enforce(m, NoAnnotationClass.class));
  }

  static class NoAnnotationClass {
    public void doStuff() {}
  }

  @Test
  @DisplayName("enforce(Method, Class) overload delegates with method name")
  void enforceMethodClassOverload() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    Method m = AnnotatedClass.class.getMethod("readDoc");
    assertDoesNotThrow(() -> JCustosEnforcer.enforce(m, AnnotatedClass.class));
  }

  // ── JS-SEC-114: a method is enforced as it runs on the class passed in ──

  @RequiresRole("ADMIN")
  static class RestrictedBase {
    public void inherited() {}
  }

  @RequiresRole("USER")
  static class UserDerived extends RestrictedBase {
  }

  static class PlainBase {
    @RequiresRole("ADMIN")
    public void purge() {}
  }

  static class UnannotatedOverride extends PlainBase {
    @Override
    public void purge() {}
  }

  @Test
  @DisplayName("JS-SEC-114: an inherited method is enforced with the restriction of the class the call is served by")
  void inheritedMethodUsesTheServingClassRestriction() throws Exception {
    bind(new TestUser("alice", Set.of("USER"), Set.of()));
    Method m = UserDerived.class.getMethod("inherited");

    assertDoesNotThrow(() -> JCustosEnforcer.enforce(m, UserDerived.class),
        "the restriction of UserDerived applies, not the one of the base class");
    assertThrows(AccessDeniedException.class, () -> JCustosEnforcer.enforce(m, RestrictedBase.class),
        "invoked on the base class, the base class restriction applies");
  }

  @Test
  @DisplayName("JS-SEC-114: an un-annotated override keeps the restriction of the overridden method")
  void unannotatedOverrideKeepsTheRestriction() throws Exception {
    bind(new TestUser("alice", Set.of("USER"), Set.of()));
    Method m = UnannotatedOverride.class.getMethod("purge");

    assertThrows(AccessDeniedException.class, () -> JCustosEnforcer.enforce(m, UnannotatedOverride.class));
  }

  @Test
  @DisplayName("JS-SEC-114: an element that is not a method of the class keeps the element-then-class lookup")
  void unrelatedElementKeepsTheFallback() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    Method m = NoAnnotationClass.class.getMethod("doStuff");

    assertDoesNotThrow(() -> JCustosEnforcer.enforce(m, AnnotatedClass.class));
    bind(new TestUser("bob", Set.of(), Set.of()));
    assertThrows(AccessDeniedException.class, () -> JCustosEnforcer.enforce(m, AnnotatedClass.class));
  }

  // ── method-level annotations ──────────────────────────────────────

  static class MixedClass {
    @RequiresAnyPermission({"a", "b"})
    public void either() {}

    @RequiresAllPermissions({"a", "b"})
    public void both() {}

    @RequiresPolicy("doc.policy")
    public void policy() {}
  }

  @Test
  @DisplayName("enforce respects @RequiresAnyPermission at method level")
  void enforceAnyPermission() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("b")));
    Method m = MixedClass.class.getMethod("either");
    assertDoesNotThrow(() -> JCustosEnforcer.enforce(m, MixedClass.class));
  }

  @Test
  @DisplayName("enforce respects @RequiresAllPermissions at method level")
  void enforceAllPermissions() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("a")));
    Method m = MixedClass.class.getMethod("both");
    assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.enforce(m, MixedClass.class));
  }

  @Test
  @DisplayName("enforce respects @RequiresPolicy at method level")
  void enforceRequiresPolicy() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("doc.policy", PolicyDecision.denied("nope"));
    Method m = MixedClass.class.getMethod("policy");
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> JCustosEnforcer.enforce(m, MixedClass.class));
    assertTrue(ex.getMessage().contains("nope"));
  }

  // ── handle(AuthorizationDecision) — standalone row of the R024 table ──
  // The standalone adapter maps every non-Granted variant to an
  // AccessDeniedException (no navigation, no HTTP transport). These tests pin
  // the documented per-adapter mapping (see AuthorizationDecision javadoc).

  private static void invokeHandle(AuthorizationDecision decision) throws Throwable {
    Method m = JCustosEnforcer.class.getDeclaredMethod("handle", AuthorizationDecision.class);
    m.setAccessible(true);
    try {
      m.invoke(null, decision);
    } catch (java.lang.reflect.InvocationTargetException ite) {
      throw ite.getCause();
    }
  }

  @Test
  @DisplayName("handle(Granted) falls through without throwing")
  void handleGranted() {
    assertDoesNotThrow(() -> invokeHandle(AuthorizationDecision.granted()));
  }

  @Test
  @DisplayName("handle(Unauthenticated) throws AccessDeniedException 'Unauthenticated: …'")
  void handleUnauthenticated() {
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> invokeHandle(AuthorizationDecision.unauthenticated("no subject")));
    assertTrue(ex.getMessage().startsWith("Unauthenticated:"));
    assertTrue(ex.getMessage().contains("no subject"));
  }

  @Test
  @DisplayName("handle(Forbidden) throws AccessDeniedException carrying the reason")
  void handleForbidden() {
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> invokeHandle(AuthorizationDecision.forbidden("missing role ADMIN")));
    assertEquals("missing role ADMIN", ex.getMessage());
  }

  @Test
  @DisplayName("handle(StepUpRequired) throws AccessDeniedException preserving method + reason")
  void handleStepUp() {
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> invokeHandle(AuthorizationDecision.stepUpRequired("high-value op", "MFA")));
    assertTrue(ex.getMessage().contains("Step-up required"));
    assertTrue(ex.getMessage().contains("method=MFA"));
    assertTrue(ex.getMessage().contains("high-value op"));
  }
}
