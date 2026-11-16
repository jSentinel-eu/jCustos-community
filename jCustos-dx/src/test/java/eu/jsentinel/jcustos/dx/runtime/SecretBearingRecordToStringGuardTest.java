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
package eu.jsentinel.jcustos.dx.runtime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassModel;
import java.lang.classfile.MethodModel;
import java.lang.classfile.instruction.InvokeDynamicInstruction;
import java.lang.reflect.RecordComponent;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Structural guard for JS-SEC-127 / JS-SEC-088 (CWE-532) in {@code jCustos-dx}: a record that
 * carries a secret in a component must not rely on the compiler-generated
 * {@code toString()}, which prints every component into any log line or exception message
 * that stringifies the record.
 *
 * <p>The same guard runs in every library module; the one in {@code jCustos-core}
 * ({@code eu.jsentinel.jcustos.boundary.SecretBearingRecordToStringGuardTest}) is the
 * reference, and the naming rule below is kept identical in all copies - a module cannot
 * see another module's test classes. The test walks the compiled main classes of this
 * module, so a record added later is covered without anyone remembering this test. A
 * component counts as secret-bearing when its name is one of {@link #SECRET_NAMES}, or one
 * of {@link #PACKAGE_NAMES} in the packages listed there. A component whose type is a class
 * of jCustos with a written {@code toString()} masks itself and is not a leak.</p>
 */
@DisplayName("JS-SEC-127 — secret-bearing records of jCustos-dx override toString")
class SecretBearingRecordToStringGuardTest {

  /** Component names (lower case) that hold a plaintext secret, in every package. */
  private static final Set<String> SECRET_NAMES = Set.of(
      "token", "tokenplain", "plaintoken", "secret", "password",
      "refreshtoken", "accesstoken", "bootstraptoken", "idtoken", "idtokenhint",
      "accesstokenforathash", "privatekey", "clientsecret", "pkceverifier", "codeverifier",
      "proofcompact");

  /**
   * Further secret names in the packages (and sub-packages) given: the token itself in a
   * {@code value}, the authorisation code, and the body of a token-endpoint response.
   */
  private static final Map<String, Set<String>> PACKAGE_NAMES = Map.of(
      "eu.jsentinel.jcustos.authentication", Set.of("value"),
      "eu.jsentinel.jcustos.credential", Set.of("value"),
      "eu.jsentinel.jcustos.accountlifecycle", Set.of("value"),
      "eu.jsentinel.jcustos.bootstrap", Set.of("value"),
      "eu.jsentinel.jcustos.oauth2", Set.of("code", "codeforchash", "body"),
      "eu.jsentinel.jcustos.oidc", Set.of("code", "codeforchash"),
      "eu.jsentinel.jcustos.propagation", Set.of("body"));

  private static final String JCUSTOS_PACKAGE = "eu.jsentinel.jcustos";

  private record Plain(String token) {
  }

  private record Masked(String token) {
    @Override
    public String toString() {
      return "Masked[token=***]";
    }
  }

  @Test
  @DisplayName("the detector tells a generated toString from a written one")
  void detectorSelfCheck() throws Exception {
    assertTrue(hasGeneratedToString(Plain.class));
    assertFalse(hasGeneratedToString(Masked.class));
    assertEquals(List.of("token"), secretComponents(Plain.class));
    assertFalse(masksItself(String.class));
    assertFalse(masksItself(char[].class));
  }

  @Test
  @DisplayName("no record with a secret-bearing component keeps the generated toString")
  void secretBearingRecordsOverrideToString() throws Exception {
    Path classes = mainClasses();
    List<Class<?>> records = new ArrayList<>();
    int classFiles = recordsUnder(classes, records);

    // Self-check: the walk saw this module's classes and its records.
    assertTrue(classFiles > 0, "no class files under " + classes);
    assertTrue(records.size() >= 15,
        "expected the record types of jCustos-dx under " + classes + ", found " + records);

    Set<String> offenders = new TreeSet<>();
    Set<String> guarded = new TreeSet<>();
    for (Class<?> record : records) {
      List<String> secrets = secretComponents(record);
      if (secrets.isEmpty()) {
        continue;
      }
      guarded.add(record.getName());
      if (hasGeneratedToString(record)) {
        offenders.add(record.getName() + " " + secrets);
      }
    }
    assertTrue(offenders.isEmpty(),
        "records with a secret-bearing component must override toString() and mask it "
            + "(JS-SEC-127, CWE-532): " + offenders);
  }

  private static List<String> secretComponents(Class<?> record) {
    Set<String> packageNames = new TreeSet<>();
    PACKAGE_NAMES.forEach((pkg, names) -> {
      if (record.getPackageName().equals(pkg) || record.getPackageName().startsWith(pkg + ".")) {
        packageNames.addAll(names);
      }
    });
    List<String> found = new ArrayList<>();
    for (RecordComponent component : record.getRecordComponents()) {
      String name = component.getName().toLowerCase(Locale.ROOT);
      if ((SECRET_NAMES.contains(name) || packageNames.contains(name))
          && !masksItself(component.getType())) {
        found.add(component.getName());
      }
    }
    return found;
  }

  /** Whether {@code type} is a jCustos class with a written {@code toString()}. */
  private static boolean masksItself(Class<?> type) {
    if (type.isPrimitive() || type.isArray() || !type.getPackageName().startsWith(JCUSTOS_PACKAGE)) {
      return false;
    }
    try {
      return type.isRecord() ? !hasGeneratedToString(type) : declaresToString(type);
    } catch (IOException e) {
      throw new IllegalStateException("cannot read " + type.getName(), e);
    }
  }

  private static boolean declaresToString(Class<?> type) {
    try {
      type.getDeclaredMethod("toString");
      return true;
    } catch (NoSuchMethodException inherited) {
      return false;
    }
  }

  /** Root of the compiled main classes of this module, located through a main class. */
  private static Path mainClasses() throws URISyntaxException {
    Path location = Path.of(
        JCustosRuntime.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    assertTrue(Files.isDirectory(location),
        "the guard walks a class directory; the module is on the class path as " + location);
    return location;
  }

  /** Adds the records under {@code classes} to {@code records}; returns the number of class files. */
  private static int recordsUnder(Path classes, List<Class<?>> records) throws IOException {
    ClassLoader loader = JCustosRuntime.class.getClassLoader();
    int seen = 0;
    try (Stream<Path> files = Files.walk(classes)) {
      for (Path file : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".class"))::iterator) {
        String relative = classes.relativize(file).toString();
        if (relative.endsWith("module-info.class") || relative.endsWith("package-info.class")) {
          continue;
        }
        seen++;
        String name = relative.substring(0, relative.length() - ".class".length())
            .replace(file.getFileSystem().getSeparator(), ".");
        try {
          Class<?> type = Class.forName(name, false, loader);
          if (type.isRecord()) {
            records.add(type);
          }
        } catch (ClassNotFoundException | LinkageError unloadable) {
          throw new IllegalStateException("cannot load " + name, unloadable);
        }
      }
    }
    return seen;
  }

  /**
   * A record's implicit {@code toString()} is compiled to an {@code invokedynamic} call of
   * {@code java.lang.runtime.ObjectMethods.bootstrap}; a written one is not.
   */
  private static boolean hasGeneratedToString(Class<?> record) throws IOException {
    String resource = record.getName().replace('.', '/') + ".class";
    byte[] bytes;
    try (var in = record.getClassLoader().getResourceAsStream(resource)) {
      assertTrue(in != null, "class file not found: " + resource);
      bytes = in.readAllBytes();
    }
    ClassModel model = ClassFile.of().parse(bytes);
    for (MethodModel method : model.methods()) {
      if (method.methodName().equalsString("toString")
          && method.methodType().equalsString("()Ljava/lang/String;")) {
        return method.code().map(code -> code.elementStream().anyMatch(
            element -> element instanceof InvokeDynamicInstruction indy
                && indy.bootstrapMethod().owner().descriptorString()
                    .equals("Ljava/lang/runtime/ObjectMethods;"))).orElse(false);
      }
    }
    throw new IllegalStateException("record without toString(): " + record.getName());
  }
}
