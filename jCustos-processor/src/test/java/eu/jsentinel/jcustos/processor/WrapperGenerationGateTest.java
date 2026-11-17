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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Whether the processor generates a wrapper at all. A class whose restriction the
 * wrapper cannot enforce gets the compile error <em>and no wrapper</em>: a wrapper that
 * leaves a restricted method out must not reach the generated sources, not even of a
 * failed build that an IDE keeps using. Methods the wrapper legitimately leaves alone
 * (static ones where proxybuilder only warns, {@code @SkipProxy @PublicRoute}) do not
 * stop the wrapper. {@code SecuredAnnotationProcessorTest} pins the diagnostics; this
 * class pins the gate behind them. The JDK compiler writes into real directories,
 * because the in-memory harness hides the generated files of a failed compilation.
 */
@DisplayName("SecuredAnnotationProcessor - an unenforceable restriction yields no wrapper, a harmless exclusion does not")
class WrapperGenerationGateTest {

  private static final String COMPOSED_ADMIN = """
      package demo;
      import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
      import java.lang.annotation.Retention;
      import java.lang.annotation.RetentionPolicy;
      @Retention(RetentionPolicy.RUNTIME)
      @RequiresRole("ADMIN")
      public @interface ComposedAdmin { }
      """;

  private static final String SUPER_ADMIN = """
      package demo;
      import java.lang.annotation.Retention;
      import java.lang.annotation.RetentionPolicy;
      @Retention(RetentionPolicy.RUNTIME)
      @ComposedAdmin
      public @interface SuperAdmin { }
      """;

  @TempDir
  Path work;

  @Test
  @DisplayName("XR06: a class-level restriction on a public method the wrapper skips - error, no wrapper")
  void classLevelRestrictionOnSkippedMethod_generatesNoWrapper() throws IOException {
    Outcome outcome = compile(List.of(), source("SkippingService", """
        package demo;
        import com.svenruppert.proxybuilder.annotations.SkipProxy;
        import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
        import eu.jsentinel.jcustos.authorization.annotations.Secured;
        @Secured @RequiresRole("ADMIN") public class SkippingService {
          @SkipProxy public void export() {}
          public void op() {}
        }
        """));

    assertFalse(outcome.success(), outcome.toString());
    assertTrue(outcome.hasError("processing/unenforceable-security-annotation: the class-level "
        + "restriction @RequiresRole of SkippingService applies to SkippingService#export"), outcome.toString());
    assertFalse(wrapperGenerated("SkippingService"),
        "a wrapper that leaves export() unguarded must not be generated");
  }

  @Test
  @DisplayName("XR08: a restriction composed two levels deep on a method - error, no wrapper")
  void nestedCompositionOnMethod_generatesNoWrapper() throws IOException {
    Outcome outcome = compile(List.of(),
        source("ComposedAdmin", COMPOSED_ADMIN),
        source("SuperAdmin", SUPER_ADMIN),
        source("DeepMethodService", """
            package demo;
            import eu.jsentinel.jcustos.authorization.annotations.Secured;
            @Secured public class DeepMethodService {
              @SuperAdmin public void purge() {}
            }
            """));

    assertFalse(outcome.success(), outcome.toString());
    assertTrue(outcome.hasError("processing/nested-composed-security-annotation"), outcome.toString());
    assertFalse(wrapperGenerated("DeepMethodService"));
  }

  @Test
  @DisplayName("XR08: a restriction composed two levels deep on the class - error, no wrapper")
  void nestedCompositionOnClass_generatesNoWrapper() throws IOException {
    Outcome outcome = compile(List.of(),
        source("ComposedAdmin", COMPOSED_ADMIN),
        source("SuperAdmin", SUPER_ADMIN),
        source("DeepClassService", """
            package demo;
            import eu.jsentinel.jcustos.authorization.annotations.Secured;
            @Secured @SuperAdmin public class DeepClassService {
              public void purge() {}
            }
            """));

    assertFalse(outcome.success(), outcome.toString());
    assertTrue(outcome.hasError("processing/nested-composed-security-annotation"), outcome.toString());
    assertFalse(wrapperGenerated("DeepClassService"));
  }

  @Test
  @DisplayName("a static method (proxybuilder only warning) and a skipped @PublicRoute method do not stop the wrapper")
  void harmlessExclusions_doNotStopTheWrapper() throws IOException {
    Outcome outcome = compile(List.of("-Aproxybuilder.failOnStaticMethods=false"),
        source("HelperService", """
            package demo;
            import com.svenruppert.proxybuilder.annotations.SkipProxy;
            import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
            import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
            import eu.jsentinel.jcustos.authorization.annotations.Secured;
            @Secured @RequiresRole("ADMIN") public class HelperService {
              public static String version() { return "1"; }
              @SkipProxy @PublicRoute public void health() {}
              public void op() {}
            }
            """));

    assertTrue(outcome.success(), outcome.toString());
    assertTrue(wrapperGenerated("HelperService"),
        "the wrapper never covers these methods, and they are meant to stay open: " + outcome);
  }

  @Test
  @DisplayName("JS-SEC-156: a restriction on an Object method, which the wrapper never overrides - error, no wrapper")
  void restrictedObjectMethod_generatesNoWrapper() throws IOException {
    Outcome outcome = compile(List.of(), source("TalkativeService", """
        package demo;
        import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
        import eu.jsentinel.jcustos.authorization.annotations.Secured;
        @Secured public class TalkativeService {
          @RequiresRole("ADMIN") @Override public String toString() { return "secret"; }
          public void op() {}
        }
        """));

    assertFalse(outcome.success(), outcome.toString());
    assertTrue(outcome.hasError("processing/unenforceable-security-annotation: @RequiresRole on "
        + "TalkativeService#toString cannot be enforced"), outcome.toString());
    assertTrue(outcome.hasError("is an Object method"), outcome.toString());
    assertFalse(wrapperGenerated("TalkativeService"));
  }

  @Test
  @DisplayName("BL02: @RequiresAllPermissions({}) fails with processing/empty-security-annotation")
  void emptyAllPermissionsArrayRejected() throws IOException {
    Outcome outcome = compile(List.of(), source("AllEmptyService", """
        package demo;
        import eu.jsentinel.jcustos.authorization.annotations.RequiresAllPermissions;
        import eu.jsentinel.jcustos.authorization.annotations.Secured;
        @Secured public class AllEmptyService {
          @RequiresAllPermissions({}) public void export() {}
        }
        """));

    assertFalse(outcome.success(), outcome.toString());
    assertTrue(outcome.hasError("processing/empty-security-annotation: "
        + "@RequiresAllPermissions on export carries an empty value array"), outcome.toString());
  }

  // ── helpers ──────────────────────────────────────────────────────

  private record Outcome(boolean success, List<Diagnostic<? extends JavaFileObject>> diagnostics) {
    boolean hasError(String text) {
      return diagnostics.stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR
          && d.getMessage(Locale.ROOT).contains(text));
    }

    @Override
    public String toString() {
      StringBuilder text = new StringBuilder("success=").append(success);
      diagnostics.forEach(d -> text.append("\n  ").append(d.getKind()).append(' ')
          .append(d.getMessage(Locale.ROOT)));
      return text.toString();
    }
  }

  private Path source(String simpleName, String code) throws IOException {
    Path dir = Files.createDirectories(work.resolve("src/demo"));
    return Files.writeString(dir.resolve(simpleName + ".java"), code);
  }

  private boolean wrapperGenerated(String simpleName) {
    return Files.exists(work.resolve("generated/demo/" + simpleName + "Secured.java"));
  }

  private Outcome compile(List<String> options, Path... sources) throws IOException {
    Path classes = Files.createDirectories(work.resolve("classes"));
    Path generated = Files.createDirectories(work.resolve("generated"));
    List<String> arguments = new ArrayList<>(List.of("-proc:full"));
    arguments.addAll(options);

    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector<JavaFileObject> collector = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
             javac.getStandardFileManager(collector, Locale.ROOT, StandardCharsets.UTF_8)) {
      files.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(classes));
      files.setLocationFromPaths(StandardLocation.SOURCE_OUTPUT, List.of(generated));
      JavaCompiler.CompilationTask task = javac.getTask(null, files, collector, arguments, null,
          files.getJavaFileObjectsFromPaths(List.of(sources)));
      task.setProcessors(List.of(new SecuredAnnotationProcessor()));
      boolean success = task.call();
      return new Outcome(success, List.copyOf(collector.getDiagnostics()));
    }
  }
}
