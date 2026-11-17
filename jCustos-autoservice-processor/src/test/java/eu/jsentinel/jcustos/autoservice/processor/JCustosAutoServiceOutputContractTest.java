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
package eu.jsentinel.jcustos.autoservice.processor;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.FilerException;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The exact bytes of the {@code META-INF/services} file, the diagnostics that accompany
 * it, and what a rejected implementation leaves behind. The other tests of this module
 * check that an entry is present; these pin the file line by line, so a dropped line
 * break, a hand-written entry moved below the marker or a rejected class that still
 * reaches the file fails here. Real javac, real Filer, in-memory output.
 */
@DisplayName("JCustosAutoServiceProcessor - services-file bytes, diagnostics, rejected implementations")
class JCustosAutoServiceOutputContractTest {

  private static final String SERVICES = "META-INF/services/com.example.Api";
  private static final String API = """
      package com.example;
      public interface Api {}
      """;
  private static final String VALID = """
      package com.example;
      import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
      @JCustosAutoService(Api.class)
      public final class Valid implements Api {}
      """;

  @TempDir
  Path work;

  // ── exact file content and the summary note ──────────────────────

  @Test
  @DisplayName("a clean build writes the marker and one sorted entry per line, and notes the entry count")
  void cleanBuild_writesExactLinesAndCountsEntries() throws IOException {
    Map<String, String> sources = sources("com.example.Api", API,
        "com.example.ZImpl", impl("ZImpl"),
        "com.example.AImpl", impl("AImpl"));

    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources);

    assertTrue(r.success, summary(r));
    assertEquals(JCustosAutoServiceProcessor.MARKER + "\n"
            + "com.example.AImpl\n"
            + "com.example.ZImpl\n",
        r.resourceAsString(SERVICES));
    assertTrue(hasNote(r, "AutoService: wrote " + SERVICES + " with 2 entries"), summary(r));
    assertFalse(hasNote(r, "mixed-file-detected"),
        "a file without hand-written entries is not mixed: " + summary(r));
  }

  @Test
  @DisplayName("a single entry is counted in the singular")
  void singleEntry_isCountedInTheSingular() throws IOException {
    InMemoryCompiler.Result r = InMemoryCompiler.compile(
        sources("com.example.Api", API, "com.example.Valid", VALID));

    assertTrue(r.success, summary(r));
    assertTrue(hasNote(r, "AutoService: wrote " + SERVICES + " with 1 entry"), summary(r));
    assertFalse(hasNote(r, "with 1 entries"), summary(r));
  }

  @Test
  @DisplayName("hand-written entries stay above the marker, comments are dropped, and the mixed file is reported as a NOTE")
  void handWrittenEntries_stayAboveTheMarker() throws IOException {
    String existing = "# maintained by hand\n"
        + "\n"
        + "com.example.HandWritten \n"
        + JCustosAutoServiceProcessor.MARKER + "\n"
        + "com.example.Earlier\n";

    InMemoryCompiler.Result r = InMemoryCompiler.compile(
        sources("com.example.Api", API, "com.example.Valid", VALID),
        Map.of(SERVICES, existing.getBytes(StandardCharsets.UTF_8)));

    assertTrue(r.success, summary(r));
    assertEquals("com.example.HandWritten\n"
            + JCustosAutoServiceProcessor.MARKER + "\n"
            + "com.example.Earlier\n"
            + "com.example.Valid\n",
        r.resourceAsString(SERVICES),
        "hand-written entry (trimmed) above the marker, earlier and current generated entries below");
    assertTrue(r.diagnostics.stream()
            .anyMatch(d -> d.getKind() == Diagnostic.Kind.NOTE
                && d.getMessage(Locale.ROOT).contains("autoservice/mixed-file-detected: " + SERVICES)),
        summary(r));
    assertFalse(r.diagnostics.stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.WARNING),
        "a mixed file is a supported state, not a warning: " + summary(r));
  }

  // ── rejected implementations leave no entry ──────────────────────

  @Test
  @DisplayName("an abstract implementation is reported and not registered next to a valid one")
  void abstractImpl_isNotRegistered() throws IOException {
    assertRejected("com.example.Rejected", """
        package com.example;
        import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
        @JCustosAutoService(Api.class)
        public abstract class Rejected implements Api {}
        """, "autoservice/abstract");
  }

  @Test
  @DisplayName("a non-public implementation is reported and not registered next to a valid one")
  void nonPublicImpl_isNotRegistered() throws IOException {
    assertRejected("com.example.Rejected", """
        package com.example;
        import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
        @JCustosAutoService(Api.class)
        final class Rejected implements Api {}
        """, "autoservice/non-public-impl");
  }

  @Test
  @DisplayName("an implementation without a public no-arg constructor is reported and not registered")
  void implWithoutNoArgConstructor_isNotRegistered() throws IOException {
    assertRejected("com.example.Rejected", """
        package com.example;
        import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
        @JCustosAutoService(Api.class)
        public final class Rejected implements Api {
          private Rejected() {}
        }
        """, "autoservice/missing-no-arg-ctor");
  }

  @Test
  @DisplayName("an inner (non-static member) class is reported and not registered")
  void innerClass_isNotRegistered() throws IOException {
    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources("com.example.Api", API,
        "com.example.Valid", VALID,
        "com.example.Outer", """
            package com.example;
            import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
            public final class Outer {
              @JCustosAutoService(Api.class)
              public class Inner implements Api {}
            }
            """));

    assertFalse(r.success, summary(r));
    assertTrue(hasError(r, "autoservice/non-static-nested")
            && hasError(r, "non-static nested type cannot be a ServiceLoader provider"),
        summary(r));
    assertEquals(JCustosAutoServiceProcessor.MARKER + "\ncom.example.Valid\n",
        r.resourceAsString(SERVICES), "the inner class must not be registered");
  }

  @Test
  @DisplayName("an array type declared as SPI is reported as not a class or interface")
  void arraySpi_isReportedAsNotAType() throws IOException {
    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources("com.example.Api", API,
        "com.example.Odd", """
            package com.example;
            import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
            @JCustosAutoService(Api[].class)
            public final class Odd implements Api {}
            """));

    assertFalse(r.success, summary(r));
    assertTrue(hasError(r, "autoservice/spi-not-a-type"), summary(r));
    assertTrue(r.generatedResources.keySet().stream().noneMatch(p -> p.startsWith("META-INF/services/")),
        "no services file for an SPI that is not a type: " + r.generatedResources.keySet());
  }

  // ── neighbours in the same compilation ──────────────────────────

  @Test
  @DisplayName("the processor claims @JCustosAutoService: a later processor for the same annotation is not handed it")
  void annotationIsClaimed() throws IOException {
    RecordingProcessor later = new RecordingProcessor();

    InMemoryCompiler.Result r = InMemoryCompiler.compile(
        sources("com.example.Api", API, "com.example.Valid", VALID), Map.of(), List.of(later));

    assertTrue(r.success, summary(r));
    assertTrue(later.seen.isEmpty(),
        "a claimed annotation is not passed on to later processors, got " + later.seen);
  }

  @Test
  @DisplayName("a services file another processor has already created is an ERROR naming the path, not a silent loss")
  void servicesFileTakenByAnotherProcessor_isAnError() throws IOException {
    // A real class-output directory: javac's Filer recognises a second write to the
    // same path only for real files (the in-memory objects are never "the same file").
    Path sourceDir = Files.createDirectories(work.resolve("src/com/example"));
    Path classes = Files.createDirectories(work.resolve("classes"));
    List<Path> sourceFiles = List.of(
        Files.writeString(sourceDir.resolve("Api.java"), API),
        Files.writeString(sourceDir.resolve("Valid.java"), VALID));

    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector<JavaFileObject> collector = new DiagnosticCollector<>();
    boolean success;
    try (StandardJavaFileManager files =
             javac.getStandardFileManager(collector, Locale.ROOT, StandardCharsets.UTF_8)) {
      files.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(classes));
      JavaCompiler.CompilationTask task = javac.getTask(null, files, collector,
          List.of("-proc:full"), null, files.getJavaFileObjectsFromPaths(sourceFiles));
      task.setProcessors(List.of(new CompetingWriter(SERVICES), new JCustosAutoServiceProcessor()));
      success = task.call();
    }

    InMemoryCompiler.Result r = new InMemoryCompiler.Result(success, collector.getDiagnostics(), Map.of());
    assertFalse(r.success, summary(r));
    assertTrue(hasError(r, "Failed to write " + SERVICES + ": "), summary(r));
    assertEquals("com.example.FromElsewhere\n",
        Files.readString(classes.resolve(SERVICES)), "the other processor's file is left as it is");
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static void assertRejected(String fqn, String source, String code) throws IOException {
    InMemoryCompiler.Result r = InMemoryCompiler.compile(sources("com.example.Api", API,
        "com.example.Valid", VALID, fqn, source));

    assertFalse(r.success, summary(r));
    assertTrue(hasError(r, code), "expected " + code + ": " + summary(r));
    assertEquals(JCustosAutoServiceProcessor.MARKER + "\ncom.example.Valid\n",
        r.resourceAsString(SERVICES), "a rejected implementation must not be registered");
  }

  private static String impl(String simpleName) {
    return """
        package com.example;
        import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
        @JCustosAutoService(Api.class)
        public final class %s implements Api {}
        """.formatted(simpleName);
  }

  private static Map<String, String> sources(String... fqnAndSource) {
    Map<String, String> sources = new LinkedHashMap<>();
    for (int i = 0; i < fqnAndSource.length; i += 2) {
      sources.put(fqnAndSource[i], fqnAndSource[i + 1]);
    }
    return sources;
  }

  private static boolean hasNote(InMemoryCompiler.Result r, String text) {
    return r.diagnostics.stream()
        .anyMatch(d -> d.getKind() == Diagnostic.Kind.NOTE && d.getMessage(Locale.ROOT).contains(text));
  }

  private static boolean hasError(InMemoryCompiler.Result r, String text) {
    return r.diagnostics.stream()
        .anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR && d.getMessage(Locale.ROOT).contains(text));
  }

  private static String summary(InMemoryCompiler.Result r) {
    StringBuilder text = new StringBuilder("success=").append(r.success);
    r.diagnostics.forEach(d -> text.append("\n  ").append(d.getKind()).append(' ')
        .append(d.getMessage(Locale.ROOT)));
    return text.toString();
  }

  /** A later processor for the same annotation; records every annotation it is handed. */
  @SupportedAnnotationTypes("eu.jsentinel.jcustos.autoservice.api.JCustosAutoService")
  private static final class RecordingProcessor extends AbstractProcessor {
    private final List<String> seen = new ArrayList<>();

    @Override
    public SourceVersion getSupportedSourceVersion() {
      return SourceVersion.latestSupported();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
      annotations.forEach(a -> seen.add(a.getQualifiedName().toString()));
      return false;
    }
  }

  /** Creates {@code path} in the first round, as a second services generator would. */
  @SupportedAnnotationTypes("*")
  private static final class CompetingWriter extends AbstractProcessor {
    private final String path;
    private boolean written;

    private CompetingWriter(String path) {
      this.path = path;
    }

    @Override
    public SourceVersion getSupportedSourceVersion() {
      return SourceVersion.latestSupported();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
      if (written) {
        return false;
      }
      written = true;
      try {
        FileObject file = processingEnv.getFiler()
            .createResource(StandardLocation.CLASS_OUTPUT, "", path);
        try (Writer w = file.openWriter()) {
          w.write("com.example.FromElsewhere\n");
        }
      } catch (FilerException alreadyThere) {
        throw new AssertionError("the competing writer must be first", alreadyThere);
      } catch (IOException io) {
        throw new UncheckedIOException(io);
      }
      return false;
    }
  }
}
