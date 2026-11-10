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
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.tools.JavaFileObject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static eu.jsentinel.jcustos.processor.GeneratedWrapperHarness.bindSubject;
import static eu.jsentinel.jcustos.processor.GeneratedWrapperHarness.call;
import static eu.jsentinel.jcustos.processor.GeneratedWrapperHarness.unbindSubject;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Run-time regression tests for JS-SEC-156 (CWE-862): the wrapper the
 * processor generates is compiled, loaded and called against the real
 * {@code JCustosEnforcer}. Before the fix {@code delete} and {@code purge}
 * below ran for every caller, and deny-by-default had no effect on a wrapper.
 */
@DisplayName("JS-SEC-156 — generated wrapper at run time")
class SecuredWrapperRuntimeTest {

  /** The shape of the finding's PoC, with public methods. */
  private static final JavaFileObject ORDER_SERVICE = JavaFileObjects.forSourceLines(
      "fixture.OrderService",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
      "import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;",
      "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
      "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
      "",
      "@Secured",
      "public class OrderService {",
      "    @RequiresPermission(\"order:read\")",
      "    public String read(String id) { return \"order \" + id; }",
      "",
      "    @ProtectedBy(OwnerOnly.class)",
      "    public String delete(String id) { return \"deleted \" + id; }",
      "",
      "    @AdminOnly",
      "    public String purge() { return \"purged\"; }",
      "",
      "    public String ping() { return \"pong\"; }",
      "",
      "    @PublicRoute",
      "    public String health() { return \"ok\"; }",
      "",
      "    public long sum(int a, long[] more, java.util.List<Integer> numbers, Number extra) {",
      "        long total = a + extra.longValue();",
      "        for (long m : more) { total += m; }",
      "        for (Integer n : numbers) { total += n.longValue(); }",
      "        return total;",
      "    }",
      "}");

  private GeneratedWrapperHarness harness;
  private Object orders;

  @BeforeEach
  void setUp() {
    GeneratedWrapperHarness.installServices();
    harness = GeneratedWrapperHarness.compile(
        ORDER_SERVICE, WrapperFixtures.OWNER_ONLY,
        WrapperFixtures.ADMIN_ONLY, WrapperFixtures.ADMIN_ONLY_EVALUATOR);
    orders = harness.newWrapper("fixture.OrderService");
  }

  @AfterEach
  void tearDown() {
    GeneratedWrapperHarness.resetServices();
  }

  @Test
  @DisplayName("@ProtectedBy on a method: the wrapper throws AccessDeniedException without the permission")
  void protectedByMethodIsEnforced() throws Throwable {
    bindSubject("alice", Set.of(), Set.of("order:read"));
    AccessDeniedException denied = assertThrows(AccessDeniedException.class,
        () -> call(orders, "delete", "4711"));
    assertEquals("not the owner", denied.getMessage());

    bindSubject("owner", Set.of(), Set.of("order:delete"));
    assertEquals("deleted 4711", call(orders, "delete", "4711"));
  }

  @Test
  @DisplayName("A consumer-defined @JCustosAnnotation annotation: the wrapper throws without the role")
  void consumerDefinedAnnotationIsEnforced() throws Throwable {
    bindSubject("alice", Set.of("USER"), Set.of());
    AccessDeniedException denied = assertThrows(AccessDeniedException.class,
        () -> call(orders, "purge"));
    assertEquals("admins only", denied.getMessage());

    bindSubject("root", Set.of("ADMIN"), Set.of());
    assertEquals("purged", call(orders, "purge"));
  }

  @Test
  @DisplayName("An anonymous caller is denied on every restricted method")
  void anonymousCallerIsDenied() {
    unbindSubject();
    assertThrows(AccessDeniedException.class, () -> call(orders, "read", "1"));
    assertThrows(AccessDeniedException.class, () -> call(orders, "delete", "1"));
    assertThrows(AccessDeniedException.class, () -> call(orders, "purge"));
  }

  @Test
  @DisplayName("The native lowering keeps working next to the generic guard")
  void nativeAnnotationStillEnforced() throws Throwable {
    bindSubject("alice", Set.of(), Set.of());
    assertThrows(AccessDeniedException.class, () -> call(orders, "read", "1"));
    bindSubject("reader", Set.of(), Set.of("order:read"));
    assertEquals("order 1", call(orders, "read", "1"));
  }

  @Test
  @DisplayName("Under deny-by-default an unannotated method throws; @PublicRoute opens one; a restriction still decides")
  void denyByDefaultAppliesToTheWrapper() throws Throwable {
    bindSubject("reader", Set.of(), Set.of("order:read"));
    assertEquals("pong", call(orders, "ping"), "allow-by-omission: unannotated stays open");

    JCustosServiceResolver.setDenyByDefault(true);
    AccessDeniedException denied = assertThrows(AccessDeniedException.class,
        () -> call(orders, "ping"));
    assertTrue(denied.getMessage().startsWith("Denied by default"),
        "unexpected message: " + denied.getMessage());
    assertTrue(denied.getMessage().contains("fixture.OrderService#ping"),
        "unexpected message: " + denied.getMessage());
    assertEquals("ok", call(orders, "health"), "@PublicRoute is the explicit opt-out");
    assertEquals("order 1", call(orders, "read", "1"), "a restriction decides on its own");
    assertThrows(AccessDeniedException.class, () -> call(orders, "delete", "1"));

    JCustosServiceResolver.setDenyByDefault(false);
    assertEquals("pong", call(orders, "ping"), "switching it off restores the previous behaviour");
  }

  @Test
  @DisplayName("Without deny-by-default the generic guard of an unannotated method is a no-op - even with no service registered")
  void genericGuardIsANoOpUnderAllowByOmission() throws Throwable {
    // No authentication service, no authorisation service, no subject store: a
    // guard that did anything but return would fail here.
    GeneratedWrapperHarness.resetServices();
    assertEquals("pong", call(orders, "ping"));
    assertEquals("ok", call(orders, "health"));
    assertEquals(21L, call(orders, "sum", 1, new long[] {2, 3}, List.of(4, 5), 6));
  }

  @Test
  @DisplayName("The guard method is resolved with erased parameter types (primitive, array, generic)")
  void guardMethodResolvesWithErasedParameterTypes() throws Throwable {
    JCustosServiceResolver.setDenyByDefault(true);
    bindSubject("alice", Set.of(), Set.of());
    assertThrows(AccessDeniedException.class,
        () -> call(orders, "sum", 1, new long[] {2, 3}, List.of(4, 5), 6),
        "the unannotated generic method is guarded like any other");
  }

  @Test
  @DisplayName("A restriction inherited from a superclass or an interface is enforced by the wrapper")
  void inheritedClassLevelRestrictionIsEnforced() throws Throwable {
    JavaFileObject markedBase = JavaFileObjects.forSourceLines(
        "fixture.MarkedBase",
        "package fixture;",
        "@AdminOnly",
        "public class MarkedBase {",
        "    public String baseOp() { return \"base\"; }",
        "}");
    JavaFileObject markedDerived = JavaFileObjects.forSourceLines(
        "fixture.MarkedDerived",
        "package fixture;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "@Secured",
        "public class MarkedDerived extends MarkedBase {",
        "    public String op() { return \"derived\"; }",
        "}");
    JavaFileObject marked = JavaFileObjects.forSourceLines(
        "fixture.Marked",
        "package fixture;",
        "@AdminOnly",
        "public interface Marked { }");
    JavaFileObject markedImpl = JavaFileObjects.forSourceLines(
        "fixture.MarkedImpl",
        "package fixture;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "@Secured",
        "public class MarkedImpl implements Marked {",
        "    public String op() { return \"impl\"; }",
        "}");
    GeneratedWrapperHarness inherited = GeneratedWrapperHarness.compile(
        markedBase, markedDerived, marked, markedImpl,
        WrapperFixtures.ADMIN_ONLY, WrapperFixtures.ADMIN_ONLY_EVALUATOR);
    Object derived = inherited.newWrapper("fixture.MarkedDerived");
    Object impl = inherited.newWrapper("fixture.MarkedImpl");

    bindSubject("alice", Set.of("USER"), Set.of());
    assertThrows(AccessDeniedException.class, () -> call(derived, "op"));
    assertThrows(AccessDeniedException.class, () -> call(derived, "baseOp"));
    assertThrows(AccessDeniedException.class, () -> call(impl, "op"));

    bindSubject("root", Set.of("ADMIN"), Set.of());
    assertEquals("derived", call(derived, "op"));
    assertEquals("base", call(derived, "baseOp"));
    assertEquals("impl", call(impl, "op"));
  }

  @Test
  @DisplayName("A wrapper that cannot resolve its guarded method fails its initialisation instead of running unguarded")
  void staleWrapperFailsClosed() {
    JavaFileObject withPurge = JavaFileObjects.forSourceLines(
        "fixture.StaleService",
        "package fixture;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "@Secured",
        "public class StaleService {",
        "    @AdminOnly",
        "    public String purge() { return \"purged\"; }",
        "}");
    JavaFileObject withoutPurge = JavaFileObjects.forSourceLines(
        "fixture.StaleService",
        "package fixture;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "@Secured",
        "public class StaleService {",
        "    public String ping() { return \"pong\"; }",
        "}");
    Map<String, byte[]> wrapperOfOldSource = GeneratedWrapperHarness.classFiles(
        GeneratedWrapperHarness.compileOrFail(withPurge,
            WrapperFixtures.ADMIN_ONLY, WrapperFixtures.ADMIN_ONLY_EVALUATOR));
    Map<String, byte[]> classes = new HashMap<>(GeneratedWrapperHarness.classFiles(
        GeneratedWrapperHarness.compileOrFail(withoutPurge,
            WrapperFixtures.ADMIN_ONLY, WrapperFixtures.ADMIN_ONLY_EVALUATOR)));
    classes.put("fixture.StaleServiceSecured",
        wrapperOfOldSource.get("fixture.StaleServiceSecured"));
    GeneratedWrapperHarness stale = GeneratedWrapperHarness.of(classes);

    ExceptionInInitializerError failure = assertThrows(ExceptionInInitializerError.class,
        () -> stale.load("fixture.StaleServiceSecured"));
    IllegalStateException cause =
        assertInstanceOf(IllegalStateException.class, failure.getCause());
    assertTrue(cause.getMessage().contains(
            "the generated wrapper StaleServiceSecured cannot resolve fixture.StaleService#purge"),
        "unexpected message: " + cause.getMessage());
    assertInstanceOf(NoSuchMethodException.class, cause.getCause());
  }
}
