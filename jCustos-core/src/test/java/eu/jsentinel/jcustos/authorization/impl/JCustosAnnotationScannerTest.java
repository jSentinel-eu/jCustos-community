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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JCustosAnnotationScanner")
class JCustosAnnotationScannerTest {

  private JCustosAnnotationScanner scanner;

  @BeforeEach
  void setUp() {
    scanner = new JCustosAnnotationScanner();
  }

  @Test
  @DisplayName("class without restriction annotation returns empty")
  void noAnnotation_returnsEmpty() {
    var result = scanner.scan(PlainView.class);
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("class with restriction annotation returns pair")
  void withAnnotation_returnsPair() {
    var result = scanner.scan(ProtectedView.class);
    assertTrue(result.isPresent());
    var pair = result.get();
    assertEquals(StubEvaluator.class, pair.accessEvaluatorClass());
    assertEquals(StubEvaluator.class, pair.evaluatorClass());
    assertInstanceOf(StubRestriction.class, pair.annotation());
  }

  @Test
  @DisplayName("method with restriction annotation returns pair")
  void methodWithAnnotation_returnsPair() throws NoSuchMethodException {
    Method method = ProtectedHandler.class.getDeclaredMethod("delete");

    var result = scanner.scan(method);

    assertTrue(result.isPresent());
    assertEquals(StubEvaluator.class, result.get().evaluatorClass());
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-070: a method without its own restriction takes the class-level restriction")
  void methodInheritsClassRestriction() throws NoSuchMethodException {
    Method method = ClassProtectedHandler.class.getDeclaredMethod("anyMethod");
    var result = scanner.scan(method);
    assertTrue(result.isPresent(), "class-level restriction must apply to the un-annotated method");
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-070: @PublicRoute on the method opts out of the class-level restriction")
  void publicRouteMethodOptsOut() throws NoSuchMethodException {
    Method method = ClassProtectedHandler.class.getDeclaredMethod("open");
    assertTrue(scanner.scan(method).isEmpty(),
        "an explicit @PublicRoute on the method is the opt-out and wins over the class default");
  }

  @Test
  @DisplayName("result is cached across calls")
  void resultIsCached() {
    var first = scanner.scan(ProtectedView.class);
    var second = scanner.scan(ProtectedView.class);
    assertSame(first, second);
  }

  @Test
  @DisplayName("multiple restriction annotations throws IllegalStateException")
  void multipleAnnotations_throws() {
    assertThrows(IllegalStateException.class,
        () -> scanner.scan(DualAnnotatedView.class));
  }

  @Test
  @DisplayName("non-security annotations alongside the restriction are filtered out")
  void filtersNonJCustosAnnotations() {
    var result = scanner.scan(MixedAnnotatedView.class);
    assertTrue(result.isPresent(),
        "@Deprecated alongside @StubRestriction must not bump the security count past 1");
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-040: a routed subclass inherits the superclass restriction (walk, not @Inherited)")
  void subclassInheritsSuperclassRestriction() {
    // StubRestriction is deliberately NOT @Inherited, so this exercises the explicit
    // superclass walk that generalizes inheritance to consumer-defined restriction annotations.
    var result = scanner.scan(SubclassOfProtected.class);
    assertTrue(result.isPresent(),
        "a subclass of a @StubRestriction base must inherit the restriction, not scan as public");
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-040: the most-derived restriction wins over an inherited one")
  void mostDerivedRestrictionWins() {
    var result = scanner.scan(OverridingSubclass.class);
    assertTrue(result.isPresent());
    assertInstanceOf(AnotherRestriction.class, result.get().annotation(),
        "the subclass's own restriction must win over the inherited base restriction");
  }

  @Test
  @DisplayName("JS-SEC-040: a plain subclass of a plain base still scans as empty")
  void plainSubclassStillEmpty() {
    assertTrue(scanner.scan(PlainSubclass.class).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-081: a sub-interface inherits the restriction of its super-interface")
  void subInterfaceInheritsSuperInterfaceRestriction() {
    var result = scanner.scan(SubContract.class);
    assertTrue(result.isPresent(),
        "an interface extending a @StubRestriction interface must inherit the restriction");
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-081: a method redeclared on the sub-interface still carries the super-interface restriction")
  void redeclaredInterfaceMethodInheritsRestriction() throws NoSuchMethodException {
    Method redeclared = SubContract.class.getDeclaredMethod("operation");
    assertTrue(scanner.scan(redeclared).isPresent(),
        "the redeclaring interface has no annotation of its own, the super-interface's must apply");
  }

  @Test
  @DisplayName("JS-SEC-081: the sub-interface's own restriction wins over the inherited one")
  void subInterfaceOwnRestrictionWins() {
    var result = scanner.scan(OverridingContract.class);
    assertTrue(result.isPresent());
    assertInstanceOf(AnotherRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-081: a plain sub-interface of a plain interface still scans as empty")
  void plainSubInterfaceStillEmpty() {
    assertTrue(scanner.scan(PlainSubContract.class).isEmpty());
  }

  // ── Test fixtures ─────────────────────────────────────────────

  @Retention(RetentionPolicy.RUNTIME)
  @JCustosAnnotation(StubEvaluator.class)
  @interface StubRestriction {
  }

  @Retention(RetentionPolicy.RUNTIME)
  @JCustosAnnotation(StubEvaluator.class)
  @interface AnotherRestriction {
  }

  static class StubEvaluator implements AccessEvaluator<Annotation> {
    @Override
    public AccessDecision evaluate(AccessContext context, Annotation annotation) {
      return AccessDecision.granted();
    }
  }

  static class PlainView {
  }

  @StubRestriction
  static class ProtectedView {
  }

  @StubRestriction
  @AnotherRestriction
  static class DualAnnotatedView {
  }

  @SuppressWarnings("DeprecatedIsStillUsed")
  @StubRestriction
  @Deprecated
  static class MixedAnnotatedView {
  }

  static class ProtectedHandler {
    @StubRestriction
    void delete() {
    }
  }

  // JS-SEC-040: subclass of a restriction-annotated base — inherits via the scanner walk.
  static class SubclassOfProtected extends ProtectedView {
  }

  // JS-SEC-040: subclass with its OWN restriction — most-derived wins over the base's.
  @AnotherRestriction
  static class OverridingSubclass extends ProtectedView {
  }

  // JS-SEC-040: subclass of a plain (unannotated) base stays empty.
  static class PlainSubclass extends PlainView {
  }

  /** JS-SEC-070 fixture: restriction on the class, methods carry none or an explicit opt-out. */
  @StubRestriction
  static final class ClassProtectedHandler {
    void anyMethod() {
    }

    @PublicRoute
    void open() {
    }
  }


  // JS-SEC-081: interface hierarchy fixtures.
  @StubRestriction
  interface RestrictedContract {
    void operation();
  }

  interface SubContract extends RestrictedContract {
    @Override
    void operation();
  }

  @AnotherRestriction
  interface OverridingContract extends RestrictedContract {
  }

  interface PlainContract {
  }

  interface PlainSubContract extends PlainContract {
  }
}
