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

import com.google.testing.compile.Compilation;
import com.google.testing.compile.Compiler;
import com.google.testing.compile.JavaFileObjects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.tools.JavaFileObject;

import static com.google.testing.compile.CompilationSubject.assertThat;

@DisplayName("SecuredAnnotationProcessor — generated wrapper sources")
class SecuredAnnotationProcessorTest {

  private Compilation compile(JavaFileObject... sources) {
    return Compiler.javac()
        .withProcessors(new SecuredAnnotationProcessor())
        .compile(sources);
  }

  // ── positive cases ───────────────────────────────────────────────

  @Test
  @DisplayName("@RequiresPermission(\"doc:delete\") generates requirePermission(\"doc:delete\") + super-call")
  void singlePermissionGeneratesEnforcerCall() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DocService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class DocService {",
        "    @RequiresPermission(\"doc:delete\")",
        "    public void delete(final String id) {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeededWithoutWarnings();
    assertThat(result)
        .generatedSourceFile("demo.DocServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requirePermission(\"doc:delete\")");
    assertThat(result)
        .generatedSourceFile("demo.DocServiceSecured")
        .contentsAsUtf8String()
        .contains("super.delete(id)");
  }

  @Test
  @DisplayName("@RequiresPermission with multiple values lowers to requireAllPermissions(...)")
  void multiPermissionGeneratesRequireAllPermissions() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.ReportService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class ReportService {",
        "    @RequiresPermission({\"report:read\", \"report:export\"})",
        "    public void export() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.ReportServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requireAllPermissions(\"report:read\", \"report:export\")");
  }

  @Test
  @DisplayName("@RequiresAnyPermission generates requireAnyPermission(...)")
  void anyPermissionGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.AnyService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;",
        "",
        "@Secured",
        "public class AnyService {",
        "    @RequiresAnyPermission({\"a\", \"b\"})",
        "    public void touch() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.AnyServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requireAnyPermission(\"a\", \"b\")");
  }

  @Test
  @DisplayName("@RequiresAllPermissions generates requireAllPermissions(...)")
  void allPermissionsGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.AllService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresAllPermissions;",
        "",
        "@Secured",
        "public class AllService {",
        "    @RequiresAllPermissions({\"x\", \"y\"})",
        "    public void touch() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.AllServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requireAllPermissions(\"x\", \"y\")");
  }

  @Test
  @DisplayName("@RequiresRole with single role lowers to requireRole(role)")
  void singleRoleGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.AdminService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class AdminService {",
        "    @RequiresRole(\"ADMIN\")",
        "    public void cleanup() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.AdminServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requireRole(\"ADMIN\")");
  }

  @Test
  @DisplayName("@RequiresRole with multiple roles lowers to requireAnyRole(...)")
  void multiRoleGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.MultiRoleService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class MultiRoleService {",
        "    @RequiresRole({\"ADMIN\", \"EDITOR\"})",
        "    public void edit() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.MultiRoleServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requireAnyRole(\"ADMIN\", \"EDITOR\")");
  }

  @Test
  @DisplayName("@RequiresPolicy generates requirePolicy(name)")
  void policyGenerated() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.PolicyService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;",
        "",
        "@Secured",
        "public class PolicyService {",
        "    @RequiresPolicy(\"doc.owner-or-admin\")",
        "    public void edit() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result)
        .generatedSourceFile("demo.PolicyServiceSecured")
        .contentsAsUtf8String()
        .contains("JCustosEnforcer.requirePolicy(\"doc.owner-or-admin\")");
  }

  @Test
  @DisplayName("JS-SEC-156: an unannotated method gets the generic enforce call, so deny-by-default applies")
  void unannotatedMethodGetsGenericEnforce() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.MixedService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class MixedService {",
        "    @RequiresPermission(\"a\")",
        "    public void guarded() {}",
        "",
        "    public String unguarded(final String input) { return input; }",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeededWithoutWarnings();
    String generated = generatedFileContent(result, "demo.MixedServiceSecured");

    String unguardedBody = methodBody(generated, "public String unguarded(");
    assertContains(unguardedBody,
        "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, MixedService.class);");
    assertContains(unguardedBody, "return super.unguarded(input);");
    assertBefore(unguardedBody, "JCustosEnforcer.enforce(", "super.unguarded(input)");
    assertContains(generated,
        "private static final Method JCUSTOS_GUARD_METHOD_0 = "
            + "jcustosGuardMethod(\"unguarded\", String.class);");
    assertContains(generated, "return MixedService.class.getMethod(name, parameterTypes);");

    // the native lowering of the annotated method is untouched
    String guardedBody = methodBody(generated, "public void guarded(");
    assertContains(guardedBody, "JCustosEnforcer.requirePermission(\"a\");");
    if (guardedBody.contains("JCustosEnforcer.enforce(")) {
      throw new AssertionError("native method must keep its explicit call only:\n" + generated);
    }
  }

  @Test
  @DisplayName("Class-level annotation guards otherwise-unannotated methods")
  void classLevelAnnotationGuardsMethods() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.ClassGuardedService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "@RequiresRole(\"ADMIN\")",
        "public class ClassGuardedService {",
        "    public void one() {}",
        "    public void two() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    String generated = generatedFileContent(result, "demo.ClassGuardedServiceSecured");
    long requireRoleCalls = generated.lines()
        .filter(l -> l.contains("JCustosEnforcer.requireRole(\"ADMIN\")"))
        .count();
    if (requireRoleCalls != 2) {
      throw new AssertionError("expected 2 requireRole calls (one per method), got "
          + requireRoleCalls + "; source:\n" + generated);
    }
  }

  @Test
  @DisplayName("Method-level annotation wins over class-level")
  void methodLevelOverridesClassLevel() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.HybridService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "@RequiresRole(\"USER\")",
        "public class HybridService {",
        "    @RequiresPermission(\"admin:special\")",
        "    public void elevated() {}",
        "    public void ordinary() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    String generated = generatedFileContent(result, "demo.HybridServiceSecured");
    // elevated() picks permission, ordinary() falls back to class-level role
    if (!generated.contains("requirePermission(\"admin:special\")")) {
      throw new AssertionError("expected method-level requirePermission; got:\n" + generated);
    }
    if (!generated.contains("requireRole(\"USER\")")) {
      throw new AssertionError("expected class-level requireRole fallback; got:\n" + generated);
    }
  }

  // ── negative cases (delegated to proxybuilder) ───────────────────

  @Test
  @DisplayName("A method with two security annotations fails with processing/multiple-security-annotations (R031)")
  void multipleSecurityAnnotationsOnMethodRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DoubleAnnotatedService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class DoubleAnnotatedService {",
        "    @RequiresPermission(\"doc:delete\")",
        "    @RequiresRole(\"ADMIN\")",
        "    public void delete() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/multiple-security-annotations");
  }

  @Test
  @DisplayName("A class with two security annotations fails with processing/multiple-security-annotations (R031)")
  void multipleSecurityAnnotationsOnClassRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DoubleAnnotatedClass",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;",
        "",
        "@Secured",
        "@RequiresRole(\"ADMIN\")",
        "@RequiresAnyPermission({\"a\", \"b\"})",
        "public class DoubleAnnotatedClass {",
        "    public void op() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/multiple-security-annotations");
  }

  @Test
  @DisplayName("BL02: @RequiresPermission({}) on a method fails with processing/empty-security-annotation")
  void emptyPermissionArrayOnMethodRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.EmptyPermissionService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class EmptyPermissionService {",
        "    @RequiresPermission({})",
        "    public void delete() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/empty-security-annotation");
  }

  @Test
  @DisplayName("BL02: @RequiresRole({}) on a class fails with processing/empty-security-annotation")
  void emptyRoleArrayOnClassRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.EmptyRoleClass",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "@RequiresRole({})",
        "public class EmptyRoleClass {",
        "    public void op() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/empty-security-annotation");
  }

  @Test
  @DisplayName("BL02: a blank entry inside @RequiresAnyPermission fails the build")
  void blankPermissionEntryRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.BlankEntryService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;",
        "",
        "@Secured",
        "public class BlankEntryService {",
        "    @RequiresAnyPermission({\"doc:read\", \" \"})",
        "    public void read() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/empty-security-annotation");
  }

  @Test
  @DisplayName("BL02: @RequiresPolicy(\"\") fails with processing/empty-security-annotation")
  void blankPolicyRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.BlankPolicyService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;",
        "",
        "@Secured",
        "public class BlankPolicyService {",
        "    @RequiresPolicy(\"\")",
        "    public void op() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result)
        .hadErrorContaining("processing/empty-security-annotation");
  }

  @Test
  @DisplayName("@Secured on a final class produces a compile error")
  void finalClassRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.FinalService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public final class FinalService {",
        "    public void op() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
  }

  // ── JS-SEC-156 (CWE-862): generic guard and unenforceable annotations ──

  private static final JavaFileObject OWNER_ONLY = JavaFileObjects.forSourceLines(
      "demo.OwnerOnly",
      "package demo;",
      "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
      "import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;",
      "import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;",
      "import eu.jsentinel.jcustos.authorization.navigation.AccessContext;",
      "",
      "public final class OwnerOnly implements AuthorizationEvaluator<ProtectedBy> {",
      "    @Override",
      "    public AuthorizationDecision evaluate(AccessContext context, ProtectedBy annotation) {",
      "        return AuthorizationDecision.forbidden(\"always denied\");",
      "    }",
      "}");

  private static final JavaFileObject ADMIN_ONLY = JavaFileObjects.forSourceLines(
      "demo.AdminOnly",
      "package demo;",
      "import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;",
      "import java.lang.annotation.ElementType;",
      "import java.lang.annotation.Retention;",
      "import java.lang.annotation.RetentionPolicy;",
      "import java.lang.annotation.Target;",
      "",
      "@Retention(RetentionPolicy.RUNTIME)",
      "@Target({ElementType.TYPE, ElementType.METHOD})",
      "@JCustosAnnotation(AdminOnlyEvaluator.class)",
      "public @interface AdminOnly { }");

  private static final JavaFileObject ADMIN_ONLY_EVALUATOR = JavaFileObjects.forSourceLines(
      "demo.AdminOnlyEvaluator",
      "package demo;",
      "import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;",
      "import eu.jsentinel.jcustos.authorization.navigation.AccessContext;",
      "import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;",
      "",
      "public final class AdminOnlyEvaluator implements AccessEvaluator<AdminOnly> {",
      "    @Override",
      "    public AccessDecision evaluate(AccessContext context, AdminOnly annotation) {",
      "        return AccessDecision.rerouteToError(SecurityException.class, \"admins only\");",
      "    }",
      "}");

  @Test
  @DisplayName("JS-SEC-156: @ProtectedBy on a method yields an enforcer call instead of a bare super-call")
  void protectedByOnMethodGeneratesEnforcerCall() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.OrderService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class OrderService {",
        "    @ProtectedBy(OwnerOnly.class)",
        "    public void delete(String id, int[] lines, java.util.List<String> tags) {}",
        "}");

    Compilation result = compile(source, OWNER_ONLY);

    assertThat(result).succeededWithoutWarnings();
    String generated = generatedFileContent(result, "demo.OrderServiceSecured");
    String body = methodBody(generated, "public void delete(");
    assertContains(body, "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, OrderService.class);");
    assertBefore(body, "JCustosEnforcer.enforce(", "super.delete(id, lines, tags)");
    // resolved once, with the erased parameter types
    assertContains(generated,
        "private static final Method JCUSTOS_GUARD_METHOD_0 = "
            + "jcustosGuardMethod(\"delete\", String.class, int[].class, List.class);");
    assertContains(generated, "throw new IllegalStateException(");
  }

  @Test
  @DisplayName("JS-SEC-156: a consumer-defined @JCustosAnnotation annotation yields an enforcer call")
  void consumerDefinedAnnotationGeneratesEnforcerCall() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.PurgeService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class PurgeService {",
        "    @AdminOnly",
        "    public void purge() {}",
        "}");

    Compilation result = compile(source, ADMIN_ONLY, ADMIN_ONLY_EVALUATOR);

    assertThat(result).succeededWithoutWarnings();
    String generated = generatedFileContent(result, "demo.PurgeServiceSecured");
    String body = methodBody(generated, "public void purge(");
    assertContains(body, "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, PurgeService.class);");
    assertBefore(body, "JCustosEnforcer.enforce(", "super.purge()");
    assertContains(generated,
        "private static final Method JCUSTOS_GUARD_METHOD_0 = jcustosGuardMethod(\"purge\");");
  }

  @Test
  @DisplayName("JS-SEC-156: a class-level @ProtectedBy guards every method through the generic call")
  void classLevelCustomAnnotationGuardsMethods() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.OwnedService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "@ProtectedBy(OwnerOnly.class)",
        "public class OwnedService {",
        "    public void one() {}",
        "    public void two() {}",
        "}");

    Compilation result = compile(source, OWNER_ONLY);

    assertThat(result).succeededWithoutWarnings();
    String generated = generatedFileContent(result, "demo.OwnedServiceSecured");
    assertContains(methodBody(generated, "public void one("),
        "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, OwnedService.class);");
    assertContains(methodBody(generated, "public void two("),
        "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_1, OwnedService.class);");
  }

  @Test
  @DisplayName("JS-SEC-156: a restriction annotation on a protected method is a compile error")
  void annotatedProtectedMethodRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.IndexService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class IndexService {",
        "    @RequiresRole(\"ADMIN\")",
        "    protected void rebuildIndex() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result).hadErrorContaining("processing/unenforceable-security-annotation");
    assertThat(result).hadErrorContaining(
        "@RequiresRole on IndexService#rebuildIndex cannot be enforced");
    assertThat(result).hadErrorContaining("the method is protected");
    assertThat(result)
        .hadErrorContaining("processing/unenforceable-security-annotation")
        .inFile(source)
        .onLine(8);
  }

  @Test
  @DisplayName("JS-SEC-156: a restriction annotation on a package-private method is a compile error")
  void annotatedPackagePrivateMethodRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.ExportService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "",
        "@Secured",
        "public class ExportService {",
        "    @RequiresPermission(\"order:export\")",
        "    void export() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).failed();
    assertThat(result).hadErrorContaining(
        "processing/unenforceable-security-annotation: @RequiresPermission on "
            + "ExportService#export cannot be enforced");
    assertThat(result).hadErrorContaining("the method is package-private");
  }

  @Test
  @DisplayName("JS-SEC-156: @ProtectedBy and a consumer-defined annotation on non-public methods are compile errors too")
  void customAnnotationsOnNonPublicMethodsRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.HiddenService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class HiddenService {",
        "    @ProtectedBy(OwnerOnly.class)",
        "    protected void delete() {}",
        "    @AdminOnly",
        "    void purge() {}",
        "}");

    Compilation result = compile(source, OWNER_ONLY, ADMIN_ONLY, ADMIN_ONLY_EVALUATOR);

    assertThat(result).failed();
    assertThat(result).hadErrorContaining(
        "@ProtectedBy on HiddenService#delete cannot be enforced");
    assertThat(result).hadErrorContaining(
        "@AdminOnly on HiddenService#purge cannot be enforced");
  }

  @Test
  @DisplayName("JS-SEC-156: restriction annotations on final, static and private methods are named precisely")
  void annotatedFinalStaticPrivateMethodsRejected() {
    String[][] cases = {
        {"public final void op() {}", "the method is final"},
        {"public static void op() {}", "the method is static"},
        {"private void op() {}", "the method is private"},
    };
    for (String[] c : cases) {
      JavaFileObject source = JavaFileObjects.forSourceLines(
          "demo.FixedService",
          "package demo;",
          "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
          "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
          "",
          "@Secured",
          "public class FixedService {",
          "    @RequiresRole(\"ADMIN\")",
          "    " + c[0],
          "}");

      Compilation result = compile(source);

      assertThat(result).failed();
      assertThat(result).hadErrorContaining(
          "processing/unenforceable-security-annotation: @RequiresRole on "
              + "FixedService#op cannot be enforced");
      assertThat(result).hadErrorContaining(c[1]);
    }
  }

  @Test
  @DisplayName("JS-SEC-156: an annotated static method stays an error when proxybuilder only warns about static methods")
  void annotatedStaticMethodRejectedEvenWhenStaticMethodsOnlyWarn() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.StaticService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class StaticService {",
        "    @RequiresRole(\"ADMIN\")",
        "    public static void reset() {}",
        "    public void op() {}",
        "}");

    Compilation result = Compiler.javac()
        .withProcessors(new SecuredAnnotationProcessor())
        .withOptions("-Aproxybuilder.failOnStaticMethods=false")
        .compile(source);

    assertThat(result).failed();
    assertThat(result).hadErrorCount(1);
    assertThat(result).hadErrorContaining(
        "processing/unenforceable-security-annotation: @RequiresRole on "
            + "StaticService#reset cannot be enforced");
  }

  @Test
  @DisplayName("JS-SEC-156: a restriction annotation on a method excluded from the wrapper is a compile error")
  void annotatedExcludedMethodsRejected() {
    JavaFileObject skipped = JavaFileObjects.forSourceLines(
        "demo.SkippedService",
        "package demo;",
        "import com.svenruppert.proxybuilder.annotations.SkipProxy;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class SkippedService {",
        "    @SkipProxy",
        "    @RequiresRole(\"ADMIN\")",
        "    public void op() {}",
        "}");
    Compilation skippedResult = compile(skipped);
    assertThat(skippedResult).failed();
    assertThat(skippedResult).hadErrorContaining(
        "@RequiresRole on SkippedService#op cannot be enforced");
    assertThat(skippedResult).hadErrorContaining("excluded from the wrapper by @SkipProxy");

    JavaFileObject excluded = JavaFileObjects.forSourceLines(
        "demo.ExcludedService",
        "package demo;",
        "import com.svenruppert.proxybuilder.annotations.ProxyBuilderOptions;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "@ProxyBuilderOptions(excludeMethodNames = {\"op\"})",
        "public class ExcludedService {",
        "    @RequiresRole(\"ADMIN\")",
        "    public void op() {}",
        "    public void other() {}",
        "}");
    Compilation excludedResult = compile(excluded);
    assertThat(excludedResult).failed();
    assertThat(excludedResult).hadErrorContaining(
        "@RequiresRole on ExcludedService#op cannot be enforced");
    assertThat(excludedResult).hadErrorContaining(
        "excluded from the wrapper by @ProxyBuilderOptions(excludeMethodNames)");
  }

  @Test
  @DisplayName("JS-SEC-156: an annotated protected method inherited from a superclass is an error unless the subclass overrides it")
  void annotatedProtectedMethodOfSuperclassRejectedUnlessOverridden() {
    JavaFileObject base = JavaFileObjects.forSourceLines(
        "demo.BaseService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "public class BaseService {",
        "    @RequiresRole(\"ADMIN\")",
        "    protected void maintain() {}",
        "}");
    JavaFileObject inheriting = JavaFileObjects.forSourceLines(
        "demo.InheritingService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class InheritingService extends BaseService {",
        "    public void op() {}",
        "}");
    Compilation inherited = compile(base, inheriting);
    assertThat(inherited).failed();
    assertThat(inherited).hadErrorContaining(
        "@RequiresRole on BaseService#maintain cannot be enforced by the generated "
            + "wrapper of InheritingService");

    JavaFileObject overriding = JavaFileObjects.forSourceLines(
        "demo.OverridingService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class OverridingService extends BaseService {",
        "    @Override",
        "    @RequiresRole(\"ADMIN\")",
        "    public void maintain() {}",
        "}");
    Compilation overridden = compile(base, overriding);
    assertThat(overridden).succeededWithoutWarnings();
    assertContains(generatedFileContent(overridden, "demo.OverridingServiceSecured"),
        "JCustosEnforcer.requireRole(\"ADMIN\");");
  }

  @Test
  @DisplayName("JS-SEC-156: unannotated protected and package-private methods are still left alone without a diagnostic")
  void unannotatedNonPublicMethodsAreNotAnError() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.HelperService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@Secured",
        "public class HelperService {",
        "    @RequiresRole(\"ADMIN\")",
        "    public void op() { helper(); internal(); }",
        "    protected void helper() {}",
        "    void internal() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeededWithoutWarnings();
    String generated = generatedFileContent(result, "demo.HelperServiceSecured");
    if (generated.contains("helper()") || generated.contains("internal()")) {
      throw new AssertionError("non-public methods must not be overridden:\n" + generated);
    }
  }

  @Test
  @DisplayName("JS-SEC-156: a native and a custom restriction on one method fail with processing/multiple-security-annotations")
  void nativeAndCustomRestrictionOnOneMethodRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.DoubleGuardService",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class DoubleGuardService {",
        "    @RequiresRole(\"ADMIN\")",
        "    @ProtectedBy(OwnerOnly.class)",
        "    public void delete() {}",
        "}");

    Compilation result = compile(source, OWNER_ONLY);

    assertThat(result).failed();
    assertThat(result).hadErrorContaining(
        "processing/multiple-security-annotations: delete carries 2 security annotations");
    assertThat(result).hadErrorContaining("@RequiresRole, @ProtectedBy");
  }

  @Test
  @DisplayName("JS-SEC-156: a subclass that overrides its base's class-level restriction is not 'two annotations' and keeps its own")
  void subclassOverridesInheritedClassLevelRestriction() {
    JavaFileObject base = JavaFileObjects.forSourceLines(
        "demo.GuardedBase",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;",
        "",
        "@RequiresPermission(\"base:use\")",
        "public class GuardedBase {",
        "    public void inherited() {}",
        "}");
    JavaFileObject derived = JavaFileObjects.forSourceLines(
        "demo.GuardedDerived",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "@RequiresRole(\"USER\")",
        "public class GuardedDerived extends GuardedBase {",
        "    public void own() {}",
        "}");

    Compilation result = compile(base, derived);

    assertThat(result).succeededWithoutWarnings();
    String generated = generatedFileContent(result, "demo.GuardedDerivedSecured");
    // declared in the @Secured class: its own, declared restriction - natively
    String own = methodBody(generated, "public void own(");
    assertContains(own, "JCustosEnforcer.requireRole(\"USER\");");
    if (own.contains("base:use")) {
      throw new AssertionError("the inherited annotation must not win:\n" + generated);
    }
    // declared in the superclass: left to the run-time scanner, which starts at
    // the declaring class
    assertContains(methodBody(generated, "public void inherited("),
        "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, GuardedDerived.class);");
  }

  @Test
  @DisplayName("JS-SEC-156: a class-level restriction that is only inherited is resolved through the generic call")
  void inheritedClassLevelRestrictionUsesGenericCall() {
    JavaFileObject base = JavaFileObjects.forSourceLines(
        "demo.RoleBase",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "",
        "@RequiresRole(\"ADMIN\")",
        "public class RoleBase { }");
    JavaFileObject derived = JavaFileObjects.forSourceLines(
        "demo.RoleDerived",
        "package demo;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class RoleDerived extends RoleBase {",
        "    public void op() {}",
        "}");

    Compilation result = compile(base, derived);

    assertThat(result).succeededWithoutWarnings();
    assertContains(methodBody(generatedFileContent(result, "demo.RoleDerivedSecured"),
            "public void op("),
        "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, RoleDerived.class);");
  }

  @Test
  @DisplayName("JS-SEC-156: @PropagateToken is no restriction - the method is delegated as before, with a warning about deny-by-default")
  void propagateTokenIsNotARestriction() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.GatewayService",
        "package demo;",
        "import eu.jsentinel.jcustos.annotations.PropagateToken;",
        "import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class GatewayService {",
        "    @PropagateToken",
        "    public void call() {}",
        "    @PropagateToken",
        "    @RequiresRole(\"ADMIN\")",
        "    public void adminCall() {}",
        "    public void plain() {}",
        "}");

    Compilation result = compile(source);

    assertThat(result).succeeded();
    assertThat(result).hadWarningCount(1);
    assertThat(result).hadWarningContaining(
        "processing/deny-by-default-not-applied: call is delegated without a guard");
    String generated = generatedFileContent(result, "demo.GatewayServiceSecured");
    String call = methodBody(generated, "public void call(");
    if (call.contains("JCustosEnforcer.")) {
      throw new AssertionError("enforce() cannot evaluate @PropagateToken:\n" + generated);
    }
    assertContains(call, "super.call();");
    assertContains(methodBody(generated, "public void adminCall("),
        "JCustosEnforcer.requireRole(\"ADMIN\");");
    assertContains(methodBody(generated, "public void plain("),
        "JCustosEnforcer.enforce(JCUSTOS_GUARD_METHOD_0, GatewayService.class);");
  }

  @Test
  @DisplayName("JS-SEC-156: a custom restriction next to @PropagateToken cannot be enforced and fails the build")
  void customRestrictionNextToPropagateTokenRejected() {
    JavaFileObject source = JavaFileObjects.forSourceLines(
        "demo.MixedGatewayService",
        "package demo;",
        "import eu.jsentinel.jcustos.annotations.PropagateToken;",
        "import eu.jsentinel.jcustos.authorization.annotations.Secured;",
        "",
        "@Secured",
        "public class MixedGatewayService {",
        "    @PropagateToken",
        "    @AdminOnly",
        "    public void call() {}",
        "}");

    Compilation result = compile(source, ADMIN_ONLY, ADMIN_ONLY_EVALUATOR);

    assertThat(result).failed();
    assertThat(result).hadErrorContaining(
        "processing/unenforceable-security-annotation: @AdminOnly on call cannot be "
            + "enforced next to @PropagateToken");
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static void assertContains(String haystack, String needle) {
    if (!haystack.contains(needle)) {
      throw new AssertionError("expected to find\n  " + needle + "\nin:\n" + haystack);
    }
  }

  private static void assertBefore(String haystack, String first, String second) {
    int firstIdx = haystack.indexOf(first);
    int secondIdx = haystack.indexOf(second);
    if (firstIdx < 0 || secondIdx < 0 || firstIdx > secondIdx) {
      throw new AssertionError("expected '" + first + "' before '" + second + "' in:\n"
          + haystack);
    }
  }

  /** The text of one generated method, from its signature to the closing brace. */
  private static String methodBody(String generated, String signaturePrefix) {
    int start = generated.indexOf(signaturePrefix);
    if (start < 0) {
      throw new AssertionError("no method '" + signaturePrefix + "' in:\n" + generated);
    }
    int end = generated.indexOf("\n  }\n", start);
    if (end < 0) {
      throw new AssertionError("unterminated method '" + signaturePrefix + "' in:\n"
          + generated);
    }
    return generated.substring(start, end);
  }

  private static String generatedFileContent(Compilation compilation, String qualifiedName) {
    return compilation.generatedSourceFiles().stream()
        .filter(jfo -> jfo.getName().endsWith(qualifiedName.replace('.', '/') + ".java"))
        .findFirst()
        .map(jfo -> {
          try (var reader = jfo.openReader(true)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[1024];
            int n;
            while ((n = reader.read(buf)) > 0) {
              sb.append(buf, 0, n);
            }
            return sb.toString();
          } catch (Exception e) {
            throw new AssertionError("could not read " + qualifiedName, e);
          }
        })
        .orElseThrow(() -> new AssertionError(
            "no generated source file matched " + qualifiedName
                + "; generated: " + compilation.generatedSourceFiles()));
  }
}
