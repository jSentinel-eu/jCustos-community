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

  private static final List<String> FIXTURES = List.of(
      "fixture.Plain",
      "fixture.NativeClassGuard",
      "fixture.CustomClassGuard",
      "fixture.InheritsGuard",
      "fixture.OverridesGuard",
      "fixture.ImplementsMarked",
      "fixture.PublicClass");

  /** Subject name to roles and permissions; {@code null} is the anonymous caller. */
  private static final Map<String, List<Set<String>>> SUBJECTS = subjects();

  private GeneratedWrapperHarness harness;

  @BeforeEach
  void setUp() {
    GeneratedWrapperHarness.installServices();
    harness = GeneratedWrapperHarness.compile(
        PLAIN, NATIVE_CLASS_GUARD, CUSTOM_CLASS_GUARD, BASE, INHERITS_GUARD,
        OVERRIDES_GUARD, MARKED, IMPLEMENTS_MARKED, PUBLIC_CLASS,
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
