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
package eu.jsentinel.jcustos.boundary;

import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
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
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Structural guard for JS-SEC-127 / JS-SEC-088 (CWE-532): a record of
 * {@code jCustos-core} that carries a secret in a component must not rely on
 * the compiler-generated {@code toString()}, which prints every component.
 *
 * <p>The test walks the compiled main classes of the module, so a record added
 * later is covered without anyone remembering this test. A component counts as
 * secret-bearing when its name is one of {@link #SECRET_NAMES}; in the packages
 * of {@link #VALUE_PACKAGES} a component called {@code value} counts as well,
 * because there it holds the token itself ({@code HeaderValue.value},
 * {@code BootstrapToken.value}).</p>
 *
 * <p>A component whose <em>type</em> masks itself is not a leak: a
 * {@code SecretValue} or a {@code SelectorVerifierToken} prints
 * {@code <redacted>} whatever record holds it. The guard therefore skips a
 * component whose type belongs to this module and has a written
 * {@code toString()}; a {@code String}, a {@code char[]} or a {@code Map} never
 * qualifies.</p>
 */
@DisplayName("JS-SEC-127 — secret-bearing records override toString")
class SecretBearingRecordToStringGuardTest {

  /** Component names (lower case) that hold a plaintext secret. */
  private static final Set<String> SECRET_NAMES = Set.of(
      "token", "tokenplain", "plaintoken", "secret", "password",
      "refreshtoken", "accesstoken", "bootstraptoken");

  /** Packages (and their sub-packages) in which a component named {@code value} is a secret. */
  private static final List<String> VALUE_PACKAGES = List.of(
      "eu.jsentinel.jcustos.authentication",
      "eu.jsentinel.jcustos.credential",
      "eu.jsentinel.jcustos.accountlifecycle",
      "eu.jsentinel.jcustos.bootstrap");

  private static final String MODULE_PACKAGE = "eu.jsentinel.jcustos";

  private record Plain(String token) {
  }

  private record Masked(String token) {
    @Override
    public String toString() {
      return "Masked[token=***]";
    }
  }

  private record HoldsMasked(Masked token) {
  }

  @Test
  @DisplayName("the detector tells a generated toString from a written one")
  void detectorSelfCheck() throws Exception {
    assertTrue(hasGeneratedToString(Plain.class));
    assertFalse(hasGeneratedToString(Masked.class));
    assertTrue(masksItself(Masked.class));
    assertFalse(masksItself(Plain.class));
    assertFalse(masksItself(String.class));
    assertFalse(masksItself(char[].class));
    assertEquals(List.of("token"), secretComponents(Plain.class));
    assertEquals(List.of(), secretComponents(HoldsMasked.class),
        "a component of a self-masking type is not a leak");
  }

  @Test
  @DisplayName("no record with a secret-bearing component keeps the generated toString")
  void secretBearingRecordsOverrideToString() throws Exception {
    Path classes = mainClasses();
    List<Class<?>> records = recordsUnder(classes);

    // Self-check: the walk found the module's records, among them two known ones.
    assertTrue(records.size() >= 100,
        "expected the record types of jCustos-core under " + classes + ", found " + records.size());
    assertTrue(records.contains(HeaderValue.class), "HeaderValue was not visited");
    assertTrue(records.contains(TokenService.TokenPair.class), "TokenPair was not visited");

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
    // Self-check of the naming rule: the records of the finding are recognised.
    assertTrue(guarded.containsAll(Set.of(
            "eu.jsentinel.jcustos.credential.propagation.HeaderValue",
            "eu.jsentinel.jcustos.authentication.TokenService$TokenPair",
            "eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService$IssuedToken",
            "eu.jsentinel.jcustos.accountlifecycle.PasswordResetService$IssuedToken",
            "eu.jsentinel.jcustos.accountlifecycle.EmailVerificationService$IssuedToken",
            "eu.jsentinel.jcustos.bootstrap.CreateInitialAdminCommand",
            "eu.jsentinel.jcustos.bootstrap.BootstrapToken")),
        "the naming rule no longer recognises a known secret-bearing record: " + guarded);
  }

  private static List<String> secretComponents(Class<?> record) throws IOException {
    boolean valuePackage = VALUE_PACKAGES.stream().anyMatch(
        p -> record.getPackageName().equals(p) || record.getPackageName().startsWith(p + "."));
    List<String> found = new ArrayList<>();
    for (RecordComponent component : record.getRecordComponents()) {
      String name = component.getName().toLowerCase(Locale.ROOT);
      boolean secretName = SECRET_NAMES.contains(name)
          || (valuePackage && name.equals("value"));
      if (secretName && !masksItself(component.getType())) {
        found.add(component.getName());
      }
    }
    return found;
  }

  /**
   * @return whether {@code type} is a class of this module with a written
   *     {@code toString()} — the type then decides what is printed, not the
   *     record that holds it
   */
  private static boolean masksItself(Class<?> type) throws IOException {
    if (type.isPrimitive() || type.isArray()
        || !type.getPackageName().startsWith(MODULE_PACKAGE)) {
      return false;
    }
    if (type.isRecord()) {
      return !hasGeneratedToString(type);
    }
    try {
      type.getDeclaredMethod("toString");
      return true;
    } catch (NoSuchMethodException inherited) {
      return false;
    }
  }

  /** Root of the compiled main classes of jCustos-core, located through a main class. */
  private static Path mainClasses() throws URISyntaxException {
    Path location = Path.of(
        HeaderValue.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    assertTrue(Files.isDirectory(location),
        "the guard walks a class directory; jCustos-core is on the class path as " + location);
    return location;
  }

  private static List<Class<?>> recordsUnder(Path classes) throws IOException {
    List<Class<?>> records = new ArrayList<>();
    ClassLoader loader = HeaderValue.class.getClassLoader();
    try (Stream<Path> files = Files.walk(classes)) {
      for (Path file : (Iterable<Path>) files.filter(
          f -> f.toString().endsWith(".class"))::iterator) {
        String relative = classes.relativize(file).toString();
        if (relative.endsWith("module-info.class") || relative.endsWith("package-info.class")) {
          continue;
        }
        String name = relative.substring(0, relative.length() - ".class".length())
            .replace(file.getFileSystem().getSeparator(), ".");
        Class<?> type;
        try {
          type = Class.forName(name, false, loader);
        } catch (ClassNotFoundException | LinkageError unloadable) {
          throw new IllegalStateException("cannot load " + name, unloadable);
        }
        if (type.isRecord()) {
          records.add(type);
        }
      }
    }
    return records;
  }

  /**
   * A record's implicit {@code toString()} is compiled to an {@code invokedynamic}
   * call of {@code java.lang.runtime.ObjectMethods.bootstrap}; a written one is not.
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
