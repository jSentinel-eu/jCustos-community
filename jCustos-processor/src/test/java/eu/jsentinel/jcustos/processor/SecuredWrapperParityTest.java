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
package eu.jsentinel.jcustos.processor;

import com.google.testing.compile.JavaFileObjects;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.JCustosEnforcer;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.standalone.SecuredProxy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.tools.JavaFileObject;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parity test for JS-SEC-156 (CWE-862, CWE-1068): the same fixture class must
 * yield the same decision for every method, whether the call is checked by the
 * run-time path or by the wrapper the processor generates.
 *
 * <p>The run-time side is {@link SecuredProxy#requireAllowed(Class, String)} -
 * {@code SecuredProxy}'s entry point for a class, which hands the method and
 * the class to {@code JCustosEnforcer.enforce} exactly as
 * {@code SecuredProxy.wrap} does for an interface. For a method the fixture
 * inherits, which {@code requireAllowed} does not look up, the test makes that
 * same enforcer call itself. The compile-time side calls the method on the
 * generated wrapper.</p>
 *
 * <p>Every fixture method is exercised for six subjects, with deny-by-default
 * off and on. The test also asserts that the matrix is not trivial: each
 * fixture must produce grants and denials.</p>
 *
 * <p>JS-SEC-159 (SA59, CWE-862) adds the fixtures whose methods override a
 * restricted interface or superclass declaration without repeating the
 * annotation - with no class-level restriction, under a native, a custom and
 * an inherited one - and pins their decisions explicitly as well, so a
 * restriction both paths had lost would not pass as parity. The composed
 * fixture covers JS-SEC-154 on the wrapper path.</p>
 */
@DisplayName("JS-SEC-156 — SecuredProxy and the generated wrapper decide alike")
class SecuredWrapperParityTest {

  private static final String ALLOWED = "ALLOWED";
  private static final String DENIED = "DENIED";

  private static final JavaFileObject PLAIN = JavaFileObjects.forSourceLines(
      "fixture.Plain",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "public class Plain {",
      "    @RequiresPermission(\"order:read\")",
      "    public String nativePermission() { return \"ok\"; }",
      "    @RequiresPermission({\"order:read\", \"order:delete\"})",
      "    public String nativePermissions() { return \"ok\"; }",
      "    @RequiresAnyPermission({\"order:delete\", \"order:export\"})",
      "    public String nativeAnyPermission() { return \"ok\"; }",
      "    @RequiresAllPermissions({\"order:read\", \"order:export\"})",
      "    public String nativeAllPermissions() { return \"ok\"; }",
      "    @RequiresRole(\"ADMIN\")",
      "    public String nativeRole() { return \"ok\"; }",
      "    @RequiresRole({\"ADMIN\", \"USER\"})",
      "    public String nativeAnyRole() { return \"ok\"; }",
      "    @ProtectedBy(OwnerOnly.class)",
      "    public String protectedBy() { return \"ok\"; }",
      "    @AdminOnly",
      "    public String consumerDefined() { return \"ok\"; }",
      "    public String unannotated() { return \"ok\"; }",
      "    @PublicRoute",
      "    public String publicRoute() { return \"ok\"; }",
      "}");

  private static final JavaFileObject NATIVE_CLASS_GUARD = JavaFileObjects.forSourceLines(
      "fixture.NativeClassGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@RequiresRole(\"ADMIN\")",
      "public class NativeClassGuard {",
      "    public String classLevel() { return \"ok\"; }",
      "    @PublicRoute",
      "    public String publicRoute() { return \"ok\"; }",
      "    @RequiresPermission(\"order:read\")",
      "    public String ownNative() { return \"ok\"; }",
      "    @ProtectedBy(OwnerOnly.class)",
      "    public String ownCustom() { return \"ok\"; }",
      "}");

  private static final JavaFileObject CUSTOM_CLASS_GUARD = JavaFileObjects.forSourceLines(
      "fixture.CustomClassGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@ProtectedBy(OwnerOnly.class)",
      "public class CustomClassGuard {",
      "    public String classLevel() { return \"ok\"; }",
      "    @PublicRoute",
      "    public String publicRoute() { return \"ok\"; }",
      "    @RequiresRole(\"ADMIN\")",
      "    public String ownNative() { return \"ok\"; }",
      "    @AdminOnly",
      "    public String ownCustom() { return \"ok\"; }",
      "}");

  private static final JavaFileObject BASE = JavaFileObjects.forSourceLines(
      "fixture.Base",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@RequiresPermission(\"order:read\")",
      "public class Base {",
      "    public String inherited() { return \"ok\"; }",
      "    public String overridden() { return \"ok\"; }",
      "    @RequiresRole(\"ADMIN\")",
      "    public String inheritedNative() { return \"ok\"; }",
      "    @AdminOnly",
      "    public String inheritedCustom() { return \"ok\"; }",
      "    @PublicRoute",
      "    public String inheritedPublicRoute() { return \"ok\"; }",
      "}");

  /** The class-level restriction is only inherited (core's annotations are {@code @Inherited}). */
  private static final JavaFileObject INHERITS_GUARD = JavaFileObjects.forSourceLines(
      "fixture.InheritsGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "public class InheritsGuard extends Base {",
      "    public String own() { return \"ok\"; }",
      "    @Override",
      "    public String overridden() { return \"ok\"; }",
      "    @PublicRoute",
      "    public String publicRoute() { return \"ok\"; }",
      "}");

  /** The subclass declares its own class-level restriction next to the inherited one. */
  private static final JavaFileObject OVERRIDES_GUARD = JavaFileObjects.forSourceLines(
      "fixture.OverridesGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@RequiresRole(\"USER\")",
      "public class OverridesGuard extends Base {",
      "    public String own() { return \"ok\"; }",
      "    @Override",
      "    public String overridden() { return \"ok\"; }",
      "}");

  /** A consumer-defined restriction that reaches the class through an interface. */
  private static final JavaFileObject MARKED = JavaFileObjects.forSourceLines(
      "fixture.Marked",
      "package fixture;",
      "",
      "@AdminOnly",
      "public interface Marked {",
      "    default String defaulted() { return \"ok\"; }",
      "}");

  private static final JavaFileObject IMPLEMENTS_MARKED = JavaFileObjects.forSourceLines(
      "fixture.ImplementsMarked",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "public class ImplementsMarked implements Marked {",
      "    public String own() { return \"ok\"; }",
      "    @RequiresPermission(\"order:read\")",
      "    public String ownNative() { return \"ok\"; }",
      "}");

  /** No restriction anywhere, the class is public as a whole. */
  private static final JavaFileObject PUBLIC_CLASS = JavaFileObjects.forSourceLines(
      "fixture.PublicClass",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@PublicRoute",
      "public class PublicClass {",
      "    public String open() { return \"ok\"; }",
      "    @RequiresRole(\"ADMIN\")",
      "    public String restricted() { return \"ok\"; }",
      "}");

  // ── JS-SEC-159 (SA59, CWE-862): restrictions on overridden supertype declarations ──

  /** An interface whose methods carry the restrictions; the @Secured classes override them bare. */
  private static final JavaFileObject GUARDED_CONTRACT = JavaFileObjects.forSourceLines(
      "fixture.GuardedContract",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "public interface GuardedContract {",
      "    @RequiresRole(\"ADMIN\")",
      "    String fromInterface();",
      "    @RequiresAnyPermission({\"order:delete\", \"order:export\"})",
      "    String fromInterfaceAnyPermission();",
      "    @AdminOnly",
      "    String fromInterfaceCustom();",
      "    @RequiresPermission(\"order:delete\")",
      "    default String fromInterfaceDefault() { return \"contract\"; }",
      "}");

  /** A superclass without a class-level restriction; its methods carry native and custom ones. */
  private static final JavaFileObject RESTRICTED_BASE = JavaFileObjects.forSourceLines(
      "fixture.RestrictedBase",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "public class RestrictedBase {",
      "    @RequiresRole(\"ADMIN\")",
      "    public String fromSuperclassNative() { return \"base\"; }",
      "    @RequiresPermission({\"order:read\", \"order:export\"})",
      "    public String fromSuperclassPermissions() { return \"base\"; }",
      "    @ProtectedBy(OwnerOnly.class)",
      "    public String fromSuperclassProtectedBy() { return \"base\"; }",
      "    @AdminOnly",
      "    public String fromSuperclassCustom() { return \"base\"; }",
      "    @RequiresRole(\"ADMIN\")",
      "    public String openedByOverride() { return \"base\"; }",
      "}");

  /** The overriding class repeats none of the restrictions and has no class-level one. */
  private static final JavaFileObject OVERRIDES_BARE = JavaFileObjects.forSourceLines(
      "fixture.OverridesBare",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "public class OverridesBare extends RestrictedBase implements GuardedContract {",
      "    @Override public String fromInterface() { return \"ok\"; }",
      "    @Override public String fromInterfaceAnyPermission() { return \"ok\"; }",
      "    @Override public String fromInterfaceCustom() { return \"ok\"; }",
      "    @Override public String fromInterfaceDefault() { return \"ok\"; }",
      "    @Override public String fromSuperclassNative() { return \"ok\"; }",
      "    @Override public String fromSuperclassPermissions() { return \"ok\"; }",
      "    @Override public String fromSuperclassProtectedBy() { return \"ok\"; }",
      "    @Override public String fromSuperclassCustom() { return \"ok\"; }",
      "    @PublicRoute",
      "    @Override public String openedByOverride() { return \"ok\"; }",
      "    public String own() { return \"ok\"; }",
      "}");

  /** The same overrides under a native class-level restriction of the @Secured class itself. */
  private static final JavaFileObject OVERRIDES_UNDER_NATIVE_GUARD = JavaFileObjects.forSourceLines(
      "fixture.OverridesUnderNativeGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@RequiresPermission(\"order:read\")",
      "public class OverridesUnderNativeGuard extends RestrictedBase implements GuardedContract {",
      "    @Override public String fromInterface() { return \"ok\"; }",
      "    @Override public String fromInterfaceAnyPermission() { return \"ok\"; }",
      "    @Override public String fromInterfaceCustom() { return \"ok\"; }",
      "    @Override public String fromSuperclassNative() { return \"ok\"; }",
      "    @Override public String fromSuperclassProtectedBy() { return \"ok\"; }",
      "    @PublicRoute",
      "    @Override public String openedByOverride() { return \"ok\"; }",
      "    public String own() { return \"ok\"; }",
      "}");

  /** The same overrides under a custom class-level restriction of the @Secured class itself. */
  private static final JavaFileObject OVERRIDES_UNDER_CUSTOM_GUARD = JavaFileObjects.forSourceLines(
      "fixture.OverridesUnderCustomGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@ProtectedBy(OwnerOnly.class)",
      "public class OverridesUnderCustomGuard extends RestrictedBase implements GuardedContract {",
      "    @Override public String fromInterface() { return \"ok\"; }",
      "    @Override public String fromInterfaceAnyPermission() { return \"ok\"; }",
      "    @Override public String fromInterfaceCustom() { return \"ok\"; }",
      "    @Override public String fromSuperclassNative() { return \"ok\"; }",
      "    @Override public String fromSuperclassCustom() { return \"ok\"; }",
      "    public String own() { return \"ok\"; }",
      "}");

  /** A superclass whose class-level restriction the @Secured subclass inherits. */
  private static final JavaFileObject GUARDED_BASE = JavaFileObjects.forSourceLines(
      "fixture.GuardedBase",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@RequiresRole(\"USER\")",
      "public class GuardedBase {",
      "    @RequiresRole(\"ADMIN\")",
      "    public String fromSuperclassNative() { return \"base\"; }",
      "    @AdminOnly",
      "    public String fromSuperclassCustom() { return \"base\"; }",
      "}");

  /** Overrides under a class-level restriction that is only inherited. */
  private static final JavaFileObject OVERRIDES_UNDER_INHERITED_GUARD = JavaFileObjects.forSourceLines(
      "fixture.OverridesUnderInheritedGuard",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "public class OverridesUnderInheritedGuard extends GuardedBase implements GuardedContract {",
      "    @Override public String fromInterface() { return \"ok\"; }",
      "    @Override public String fromInterfaceAnyPermission() { return \"ok\"; }",
      "    @Override public String fromInterfaceCustom() { return \"ok\"; }",
      "    @Override public String fromSuperclassNative() { return \"ok\"; }",
      "    @Override public String fromSuperclassCustom() { return \"ok\"; }",
      "}");

  /** A composed restriction (JS-SEC-154): the restriction sits on the annotation type. */
  private static final JavaFileObject COMPOSED_ADMIN = JavaFileObjects.forSourceLines(
      "fixture.ComposedAdmin",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
      "import java.lang.annotation.ElementType;",
      "import java.lang.annotation.Retention;",
      "import java.lang.annotation.RetentionPolicy;",
      "import java.lang.annotation.Target;",
      "",
      "@Retention(RetentionPolicy.RUNTIME)",
      "@Target({ElementType.TYPE, ElementType.METHOD})",
      "@RequiresRole(\"ADMIN\")",
      "public @interface ComposedAdmin { }");

  /** A composed restriction on a method of a class with a native class-level restriction. */
  private static final JavaFileObject COMPOSED_ON_METHOD = JavaFileObjects.forSourceLines(
      "fixture.ComposedOnMethod",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@RequiresPermission(\"order:read\")",
      "public class ComposedOnMethod {",
      "    @ComposedAdmin",
      "    public String composed() { return \"ok\"; }",
      "    public String classLevel() { return \"ok\"; }",
      "}");

  /**
   * XR08 (00.84.00): {@code @PropagateToken} is bound through {@code @JCustosAnnotation}
   * to a propagation advisor, not to an evaluator - on the class and on a method it is no
   * restriction for either path, so deny-by-default and the other restrictions apply.
   */
  private static final JavaFileObject PROPAGATING = JavaFileObjects.forSourceLines(
      "fixture.Propagating",
      "package fixture;",
      "import eu.jsentinel.jcustos.annotations.PropagateToken;",
      "import eu.jsentinel.jcustos.authorization.annotations.*;",
      "",
      "@Secured",
      "@PropagateToken",
      "public class Propagating {",
      "    public String unguarded() { return \"ok\"; }",
      "    @PropagateToken(strategy = \"exchange\", audience = \"billing\")",
      "    public String propagatesItself() { return \"ok\"; }",
      "    @RequiresRole(\"ADMIN\")",
      "    public String nativeRole() { return \"ok\"; }",
      "    @PropagateToken",
      "    @AdminOnly",
      "    public String customNextToPropagation() { return \"ok\"; }",
      "    @PublicRoute",
      "    public String publicRoute() { return \"ok\"; }",
      "}");

  private static final List<String> FIXTURES = List.of(
      "fixture.Plain",
      "fixture.NativeClassGuard",
      "fixture.CustomClassGuard",
      "fixture.InheritsGuard",
      "fixture.OverridesGuard",
      "fixture.ImplementsMarked",
      "fixture.PublicClass",
      "fixture.OverridesBare",
      "fixture.OverridesUnderNativeGuard",
      "fixture.OverridesUnderCustomGuard",
      "fixture.OverridesUnderInheritedGuard",
      "fixture.ComposedOnMethod",
      "fixture.Propagating");

  /** Subject name to roles and permissions; {@code null} is the anonymous caller. */
  private static final Map<String, List<Set<String>>> SUBJECTS = subjects();

  private GeneratedWrapperHarness harness;

  @BeforeEach
  void setUp() {
    GeneratedWrapperHarness.installServices();
    harness = GeneratedWrapperHarness.compile(
        PLAIN, NATIVE_CLASS_GUARD, CUSTOM_CLASS_GUARD, BASE, INHERITS_GUARD,
        OVERRIDES_GUARD, MARKED, IMPLEMENTS_MARKED, PUBLIC_CLASS,
        GUARDED_CONTRACT, RESTRICTED_BASE, OVERRIDES_BARE, OVERRIDES_UNDER_NATIVE_GUARD,
        OVERRIDES_UNDER_CUSTOM_GUARD, GUARDED_BASE, OVERRIDES_UNDER_INHERITED_GUARD,
        COMPOSED_ADMIN, COMPOSED_ON_METHOD, PROPAGATING,
        WrapperFixtures.OWNER_ONLY, WrapperFixtures.ADMIN_ONLY,
        WrapperFixtures.ADMIN_ONLY_EVALUATOR);
  }

  @AfterEach
  void tearDown() {
    GeneratedWrapperHarness.resetServices();
  }

  @Test
  @DisplayName("Every method of every fixture: identical decision for every subject, allow-by-omission and deny-by-default")
  void sameDecisionOnBothPaths() {
    List<String> differences = new ArrayList<>();
    int compared = 0;
    for (String fixtureName : FIXTURES) {
      Class<?> fixture = harness.load(fixtureName);
      Object wrapper = harness.newWrapper(fixtureName);
      assertEquals(fixtureName + "Secured", wrapper.getClass().getName());
      Set<String> seen = new java.util.TreeSet<>();
      for (Method method : guardedSurface(fixture)) {
        for (boolean denyByDefault : new boolean[] {false, true}) {
          for (Map.Entry<String, List<Set<String>>> subject : SUBJECTS.entrySet()) {
            JCustosServiceResolver.setDenyByDefault(denyByDefault);
            bind(subject);
            String runTime = decide(() -> runTimeCheck(fixture, method));
            String generated = decide(() -> GeneratedWrapperHarness.call(wrapper, method.getName()));
            compared++;
            seen.add(runTime);
            if (!runTime.equals(generated)) {
              differences.add(fixtureName + "#" + method.getName()
                  + " subject=" + subject.getKey() + " denyByDefault=" + denyByDefault
                  + ": run-time path " + runTime + ", generated wrapper " + generated);
            }
          }
        }
      }
      assertEquals(Set.of(ALLOWED, DENIED), seen,
          fixtureName + " must exercise grants and denials, nothing else");
    }
    assertTrue(differences.isEmpty(),
        differences.size() + " of " + compared + " decisions differ:\n"
            + String.join("\n", differences));
    assertTrue(compared >= 400, "the matrix shrank unexpectedly: " + compared);
  }

  @Test
  @DisplayName("The fixtures cover native, custom, inherited, unannotated and @PublicRoute methods")
  void fixturesCoverTheIntendedSurface() {
    Map<String, List<String>> expected = new LinkedHashMap<>();
    expected.put("fixture.Plain", List.of(
        "consumerDefined", "nativeAllPermissions", "nativeAnyPermission", "nativeAnyRole",
        "nativePermission", "nativePermissions", "nativeRole", "protectedBy", "publicRoute",
        "unannotated"));
    expected.put("fixture.NativeClassGuard", List.of(
        "classLevel", "ownCustom", "ownNative", "publicRoute"));
    expected.put("fixture.CustomClassGuard", List.of(
        "classLevel", "ownCustom", "ownNative", "publicRoute"));
    expected.put("fixture.InheritsGuard", List.of(
        "inherited", "inheritedCustom", "inheritedNative", "inheritedPublicRoute",
        "overridden", "own", "publicRoute"));
    expected.put("fixture.OverridesGuard", List.of(
        "inherited", "inheritedCustom", "inheritedNative", "inheritedPublicRoute",
        "overridden", "own"));
    expected.put("fixture.ImplementsMarked", List.of("defaulted", "own", "ownNative"));
    expected.put("fixture.PublicClass", List.of("open", "restricted"));
    List<String> overriddenSurface = List.of(
        "fromInterface", "fromInterfaceAnyPermission", "fromInterfaceCustom",
        "fromInterfaceDefault", "fromSuperclassCustom", "fromSuperclassNative",
        "fromSuperclassPermissions", "fromSuperclassProtectedBy", "openedByOverride", "own");
    expected.put("fixture.OverridesBare", overriddenSurface);
    expected.put("fixture.OverridesUnderNativeGuard", overriddenSurface);
    expected.put("fixture.OverridesUnderCustomGuard", overriddenSurface);
    expected.put("fixture.OverridesUnderInheritedGuard", List.of(
        "fromInterface", "fromInterfaceAnyPermission", "fromInterfaceCustom",
        "fromInterfaceDefault", "fromSuperclassCustom", "fromSuperclassNative"));
    expected.put("fixture.ComposedOnMethod", List.of("classLevel", "composed"));
    expected.put("fixture.Propagating", List.of(
        "customNextToPropagation", "nativeRole", "propagatesItself", "publicRoute", "unguarded"));
    for (Map.Entry<String, List<String>> entry : expected.entrySet()) {
      Class<?> fixture = harness.load(entry.getKey());
      List<String> names = guardedSurface(fixture).stream().map(Method::getName).toList();
      assertEquals(entry.getValue(), names, entry.getKey());
      // and the wrapper really overrides each of them
      Class<?> wrapper = harness.load(entry.getKey() + "Secured");
      for (String name : names) {
        assertTrue(Arrays.stream(wrapper.getDeclaredMethods())
                .anyMatch(declared -> declared.getName().equals(name)),
            wrapper.getName() + " does not override " + name);
      }
    }
  }

  /**
   * JS-SEC-159 (SA59, CWE-862): parity alone would also hold if both paths had lost the
   * restriction of an overridden declaration. These decisions are therefore pinned
   * explicitly, on both paths, with allow-by-omission - the setting under which an
   * unenforced restriction shows as a grant.
   */
  @Test
  @DisplayName("JS-SEC-159: an override without annotation keeps the restriction of the declaration it overrides, on both paths")
  void overriddenDeclarationsKeepTheirRestriction() {
    List<String[]> expectations = List.of(
        // fixture, method, subject, expected decision
        new String[] {"fixture.OverridesBare", "fromInterface", "reader", DENIED},
        new String[] {"fixture.OverridesBare", "fromInterface", "anonymous", DENIED},
        new String[] {"fixture.OverridesBare", "fromInterface", "admin", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromInterfaceAnyPermission", "reader", DENIED},
        new String[] {"fixture.OverridesBare", "fromInterfaceAnyPermission", "exporter", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromInterfaceCustom", "owner", DENIED},
        new String[] {"fixture.OverridesBare", "fromInterfaceCustom", "admin", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromInterfaceDefault", "reader", DENIED},
        new String[] {"fixture.OverridesBare", "fromInterfaceDefault", "owner", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromSuperclassNative", "reader", DENIED},
        new String[] {"fixture.OverridesBare", "fromSuperclassNative", "admin", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromSuperclassPermissions", "reader", DENIED},
        new String[] {"fixture.OverridesBare", "fromSuperclassPermissions", "exporter", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromSuperclassProtectedBy", "reader", DENIED},
        new String[] {"fixture.OverridesBare", "fromSuperclassProtectedBy", "owner", ALLOWED},
        new String[] {"fixture.OverridesBare", "fromSuperclassCustom", "owner", DENIED},
        new String[] {"fixture.OverridesBare", "fromSuperclassCustom", "admin", ALLOWED},
        // @PublicRoute on the override is the opt-out; it is written on the method that runs
        new String[] {"fixture.OverridesBare", "openedByOverride", "anonymous", ALLOWED},
        new String[] {"fixture.OverridesBare", "own", "anonymous", ALLOWED},
        // the class-level restriction of the @Secured class takes precedence (JS-SEC-114)
        new String[] {"fixture.OverridesUnderNativeGuard", "fromInterface", "reader", ALLOWED},
        new String[] {"fixture.OverridesUnderNativeGuard", "fromInterface", "nobody", DENIED},
        new String[] {"fixture.OverridesUnderNativeGuard", "fromSuperclassPermissions", "reader", DENIED},
        new String[] {"fixture.OverridesUnderCustomGuard", "fromInterface", "owner", ALLOWED},
        new String[] {"fixture.OverridesUnderCustomGuard", "fromInterface", "admin", ALLOWED},
        new String[] {"fixture.OverridesUnderCustomGuard", "fromSuperclassNative", "reader", DENIED},
        new String[] {"fixture.OverridesUnderInheritedGuard", "fromSuperclassNative", "reader", ALLOWED},
        new String[] {"fixture.OverridesUnderInheritedGuard", "fromSuperclassNative", "exporter", DENIED},
        // a composed restriction on the method wins over the class-level one (JS-SEC-154)
        new String[] {"fixture.ComposedOnMethod", "composed", "reader", DENIED},
        new String[] {"fixture.ComposedOnMethod", "composed", "admin", ALLOWED},
        new String[] {"fixture.ComposedOnMethod", "classLevel", "reader", ALLOWED});

    List<String> wrong = new ArrayList<>();
    JCustosServiceResolver.setDenyByDefault(false);
    for (String[] expectation : expectations) {
      Class<?> fixture = harness.load(expectation[0]);
      Object wrapper = harness.newWrapper(expectation[0]);
      Method method = guardedSurface(fixture).stream()
          .filter(candidate -> candidate.getName().equals(expectation[1]))
          .findFirst()
          .orElseThrow(() -> new AssertionError(expectation[0] + " has no " + expectation[1]));
      assertTrue(SUBJECTS.containsKey(expectation[2]), "unknown subject " + expectation[2]);
      List<Set<String>> grants = SUBJECTS.get(expectation[2]);
      if (grants == null) {
        GeneratedWrapperHarness.unbindSubject();
      } else {
        GeneratedWrapperHarness.bindSubject(expectation[2], grants.get(0), grants.get(1));
      }
      String runTime = decide(() -> runTimeCheck(fixture, method));
      String generated = decide(() -> GeneratedWrapperHarness.call(wrapper, method.getName()));
      String where = expectation[0] + "#" + expectation[1] + " subject=" + expectation[2];
      if (!expectation[3].equals(runTime)) {
        wrong.add(where + ": run-time path " + runTime + ", expected " + expectation[3]);
      }
      if (!expectation[3].equals(generated)) {
        wrong.add(where + ": generated wrapper " + generated + ", expected " + expectation[3]);
      }
    }
    assertTrue(wrong.isEmpty(), String.join("\n", wrong));
  }

  /**
   * XR08 (00.84.00): parity would also hold if both paths had taken {@code @PropagateToken}
   * for a restriction and failed alike. The decisions are pinned under deny-by-default,
   * where a method without a restriction is denied and only {@code @PublicRoute} opens it.
   */
  @Test
  @DisplayName("XR08: class-level @PropagateToken leaves deny-by-default in force, on both paths")
  void propagateTokenDoesNotSuspendDenyByDefault() {
    List<String[]> expectations = List.of(
        // method, subject, deny-by-default, expected decision
        new String[] {"unguarded", "admin", "true", DENIED},
        new String[] {"unguarded", "admin", "false", ALLOWED},
        new String[] {"propagatesItself", "admin", "true", DENIED},
        new String[] {"nativeRole", "reader", "true", DENIED},
        new String[] {"nativeRole", "admin", "true", ALLOWED},
        new String[] {"customNextToPropagation", "admin", "true", ALLOWED},
        new String[] {"customNextToPropagation", "owner", "false", DENIED},
        new String[] {"publicRoute", "anonymous", "true", ALLOWED});

    Class<?> fixture = harness.load("fixture.Propagating");
    Object wrapper = harness.newWrapper("fixture.Propagating");
    List<String> wrong = new ArrayList<>();
    for (String[] expectation : expectations) {
      Method method = guardedSurface(fixture).stream()
          .filter(candidate -> candidate.getName().equals(expectation[0]))
          .findFirst()
          .orElseThrow(() -> new AssertionError("fixture.Propagating has no " + expectation[0]));
      JCustosServiceResolver.setDenyByDefault(Boolean.parseBoolean(expectation[2]));
      assertTrue(SUBJECTS.containsKey(expectation[1]), "unknown subject " + expectation[1]);
      List<Set<String>> grants = SUBJECTS.get(expectation[1]);
      if (grants == null) {
        GeneratedWrapperHarness.unbindSubject();
      } else {
        GeneratedWrapperHarness.bindSubject(expectation[1], grants.get(0), grants.get(1));
      }
      String runTime = decide(() -> runTimeCheck(fixture, method));
      String generated = decide(() -> GeneratedWrapperHarness.call(wrapper, method.getName()));
      String where = "Propagating#" + expectation[0] + " subject=" + expectation[1]
          + " denyByDefault=" + expectation[2];
      if (!expectation[3].equals(runTime)) {
        wrong.add(where + ": run-time path " + runTime + ", expected " + expectation[3]);
      }
      if (!expectation[3].equals(generated)) {
        wrong.add(where + ": generated wrapper " + generated + ", expected " + expectation[3]);
      }
    }
    assertTrue(wrong.isEmpty(), String.join("\n", wrong));
  }

  // ── helpers ──────────────────────────────────────────────────────

  /** The run-time path for one method of a class - see the class comment. */
  private static void runTimeCheck(Class<?> fixture, Method method) {
    if (method.getDeclaringClass() == fixture) {
      SecuredProxy.requireAllowed(fixture, method.getName());
    } else {
      JCustosEnforcer.enforce(method, fixture);
    }
  }

  /** The public instance methods a caller reaches through the fixture, sorted by name. */
  private static List<Method> guardedSurface(Class<?> fixture) {
    return Arrays.stream(fixture.getMethods())
        .filter(method -> method.getDeclaringClass() != Object.class)
        .filter(method -> !Modifier.isStatic(method.getModifiers()))
        .filter(method -> !method.isBridge() && !method.isSynthetic())
        .sorted(Comparator.comparing(Method::getName))
        .toList();
  }

  private static String decide(ThrowingAction action) {
    try {
      action.run();
      return ALLOWED;
    } catch (AccessDeniedException denied) {
      return DENIED;
    } catch (Throwable other) {
      return other.getClass().getName() + ": " + other.getMessage();
    }
  }

  private static void bind(Map.Entry<String, List<Set<String>>> subject) {
    if (subject.getValue() == null) {
      GeneratedWrapperHarness.unbindSubject();
    } else {
      GeneratedWrapperHarness.bindSubject(
          subject.getKey(), subject.getValue().get(0), subject.getValue().get(1));
    }
  }

  private static Map<String, List<Set<String>>> subjects() {
    Map<String, List<Set<String>>> subjects = new LinkedHashMap<>();
    subjects.put("anonymous", null);
    subjects.put("nobody", List.of(Set.of(), Set.of()));
    subjects.put("reader", List.of(Set.of("USER"), Set.of("order:read")));
    subjects.put("owner", List.of(Set.of("USER"), Set.of("order:read", "order:delete")));
    subjects.put("exporter", List.of(Set.of(), Set.of("order:read", "order:export")));
    subjects.put("admin", List.of(Set.of("ADMIN"),
        Set.of("order:read", "order:delete", "order:export")));
    return subjects;
  }

  @FunctionalInterface
  private interface ThrowingAction {
    void run() throws Throwable;
  }
}
