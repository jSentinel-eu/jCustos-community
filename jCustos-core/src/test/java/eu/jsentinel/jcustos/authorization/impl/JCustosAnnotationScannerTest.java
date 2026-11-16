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
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.roles.RequiresRoleEvaluator;
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

  @Test
  @DisplayName("JS-SEC-154: a composed @AdminOnly yields the @RequiresRole declared on the annotation type")
  void composedAnnotation_yieldsTheMetaRestriction() {
    var result = scanner.scan(ComposedAdminView.class);

    assertTrue(result.isPresent(),
        "@AdminOnly carries @RequiresRole(\"ADMIN\"); the view must not scan as unprotected");
    RequiresRole restriction = assertInstanceOf(RequiresRole.class, result.get().annotation());
    assertArrayEquals(new String[] {"ADMIN"}, restriction.value(),
        "the attribute values of the restriction on the annotation type must be preserved");
    assertEquals(RequiresRoleEvaluator.class, result.get().evaluatorClass());
  }

  @Test
  @DisplayName("JS-SEC-154: a composed annotation on a method is resolved as well")
  void composedAnnotationOnMethod_yieldsTheMetaRestriction() throws NoSuchMethodException {
    Method method = ComposedHandler.class.getDeclaredMethod("delete");

    var result = scanner.scan(method);

    assertTrue(result.isPresent());
    assertInstanceOf(StubRestriction.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-154: a subclass inherits the composed restriction of its base class")
  void composedAnnotation_isInheritedBySubclass() {
    var result = scanner.scan(SubclassOfComposed.class);

    assertTrue(result.isPresent());
    assertInstanceOf(RequiresRole.class, result.get().annotation());
  }

  @Test
  @DisplayName("JS-SEC-154: a composed annotation next to a direct restriction is 'more than one'")
  void composedPlusDirectRestriction_throws() {
    assertThrows(IllegalStateException.class,
        () -> scanner.scan(ComposedAndDirectView.class));
  }

  @Test
  @DisplayName("JS-SEC-154: an annotation type carrying two restrictions is 'more than one'")
  void composedAnnotationWithTwoRestrictions_throws() {
    assertThrows(IllegalStateException.class,
        () -> scanner.scan(DoublyComposedView.class));
  }

  @Test
  @DisplayName("JS-SEC-154: a restriction annotation that is itself meta-annotated with a restriction is 'more than one'")
  void restrictionCarryingAnotherRestriction_throws() {
    assertThrows(IllegalStateException.class,
        () -> scanner.scan(RestrictionOnRestrictionView.class));
  }

  @Test
  @DisplayName("a restriction composed two or more levels deep fails closed instead of opening the element")
  void deeperCompositionFailsClosed() throws NoSuchMethodException {
    IllegalStateException twoLevels = assertThrows(IllegalStateException.class,
        () -> scanner.scan(TwoLevelsDeepView.class),
        "@TwoLevels -> @ComposedStub -> @StubRestriction is not resolved, so it must not scan open");
    assertTrue(twoLevels.getMessage().contains("one level deep"), twoLevels.getMessage());
    assertThrows(IllegalStateException.class, () -> scanner.scan(ThreeLevelsDeepView.class));
    Method method = DeeplyComposedHandler.class.getDeclaredMethod("purge");
    assertThrows(IllegalStateException.class, () -> scanner.scan(method));
    assertThrows(IllegalStateException.class,
        () -> scanner.scan(method, DeeplyComposedHandler.class));
  }

  @Test
  @DisplayName("an annotation bound through @JCustosAnnotation to a non-evaluator is no restriction")
  void nonEvaluatorBindingIsNoRestriction() throws NoSuchMethodException {
    assertTrue(scanner.scan(AdvisedView.class).isEmpty(),
        "a binding the enforcer cannot evaluate must not make the class scan as restricted");
    Method method = AdvisedHandler.class.getDeclaredMethod("call");
    assertTrue(scanner.scan(method, AdvisedHandler.class).isEmpty());
    // next to a real restriction it is not "a second one"
    assertSame(StubRestriction.class,
        scanner.scan(AdvisedAndRestrictedView.class).orElseThrow().annotation().annotationType());
    // and a composition of it neither restricts nor fails
    assertTrue(scanner.scan(ComposedAdviceView.class).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-154: an annotation type without a restriction contributes nothing")
  void plainMetaAnnotation_contributesNothing() {
    assertTrue(scanner.scan(PlainMarkedView.class).isEmpty());
  }

  // ── JS-SEC-114 (CWE-862, CWE-863): inherited and overriding methods ──────────

  private static String roleOf(java.util.Optional<AnnotationAccessEvaluatorPair<Annotation>> result) {
    assertTrue(result.isPresent(), "a restriction must apply");
    return ((RequiresRole) result.get().annotation()).value()[0];
  }

  @Test
  @DisplayName("JS-SEC-114: a method the handler class inherits takes the restriction of the handler class")
  void inheritedMethod_takesTheRestrictionOfTheHandlerClass() throws NoSuchMethodException {
    Method inherited = AdminHandlers.class.getMethod("deleteAll");
    assertEquals(CrudHandlers.class, inherited.getDeclaringClass(),
        "the premise: the Method names the base class, not the handler class");

    assertTrue(scanner.scan(inherited).isEmpty(),
        "scanned alone, the method only knows the base class - which carries nothing");
    assertEquals("ADMIN", roleOf(scanner.scan(inherited, AdminHandlers.class)));
  }

  @Test
  @DisplayName("JS-SEC-114: the same inherited method is judged per handler class")
  void inheritedMethod_isJudgedPerHandlerClass() throws NoSuchMethodException {
    Method inherited = CrudHandlers.class.getMethod("deleteAll");

    assertEquals("ADMIN", roleOf(scanner.scan(inherited, AdminHandlers.class)));
    assertEquals("USER", roleOf(scanner.scan(inherited, UserHandlers.class)));
    assertTrue(scanner.scan(inherited, CrudHandlers.class).isEmpty());
    assertSame(scanner.scan(inherited, AdminHandlers.class), scanner.scan(inherited, AdminHandlers.class),
        "results are cached per method and handler class");
  }

  @Test
  @DisplayName("JS-SEC-114: an override without an annotation keeps the restriction of the overridden method")
  void overridingMethod_keepsTheRestrictionOfTheOverriddenMethod() throws NoSuchMethodException {
    Method override = TenantOps.class.getMethod("purge");
    assertEquals(TenantOps.class, override.getDeclaringClass());

    assertEquals("ADMIN", roleOf(scanner.scan(override)));
    assertEquals("ADMIN", roleOf(scanner.scan(override, TenantOps.class)));
    assertEquals("ADMIN", roleOf(scanner.scan((java.lang.reflect.AnnotatedElement) override)));
  }

  @Test
  @DisplayName("JS-SEC-114: the base Method handed in with the handler class is resolved to the override that runs")
  void baseMethodWithHandlerClass_isResolvedToTheOverride() throws NoSuchMethodException {
    Method base = BaseOps.class.getMethod("audit");

    assertEquals("ADMIN", roleOf(scanner.scan(base)), "the base declaration itself");
    assertEquals("USER", roleOf(scanner.scan(base, RelabelledOps.class)),
        "RelabelledOps overrides audit() with its own restriction - that one runs");
    assertEquals(RelabelledOps.class,
        JCustosAnnotationScanner.effectiveMethod(base, RelabelledOps.class).getDeclaringClass());
  }

  @Test
  @DisplayName("JS-SEC-114: the nearest overridden declaration wins")
  void nearestOverriddenDeclarationWins() throws NoSuchMethodException {
    assertEquals("USER", roleOf(scanner.scan(LeafOps.class.getMethod("audit"))),
        "LeafOps overrides RelabelledOps#audit (USER), which overrides BaseOps#audit (ADMIN)");
  }

  @Test
  @DisplayName("JS-SEC-114: a restriction on an interface method reaches the implementing method")
  void interfaceMethodRestriction_reachesTheImplementation() throws NoSuchMethodException {
    assertEquals("ADMIN", roleOf(scanner.scan(ArchiveService.class.getMethod("wipe"))));
    assertEquals("ADMIN", roleOf(scanner.scan(SubArchive.class.getDeclaredMethod("wipe"))),
        "a method redeclared on a sub-interface keeps the restriction of the super-interface method");
  }

  @Test
  @DisplayName("JS-SEC-114: an inherited method that implements an interface of the handler class takes the interface restriction")
  void inheritedImplementation_ofAnInterfaceTheHandlerClassNames() throws NoSuchMethodException {
    Method inherited = PlainArchive.class.getMethod("wipe");

    assertTrue(scanner.scan(inherited).isEmpty(), "PlainArchive knows nothing of the Archive interface");
    assertEquals("ADMIN", roleOf(scanner.scan(inherited, ArchiveHandlers.class)),
        "ArchiveHandlers extends PlainArchive implements Archive - wipe() implements Archive#wipe there");
  }

  @Test
  @DisplayName("JS-SEC-114: a generic handler method is matched through its bridge method")
  void genericOverride_isMatchedThroughTheBridge() throws NoSuchMethodException {
    assertEquals("ADMIN", roleOf(scanner.scan(TextSink.class.getMethod("accept", String.class))));
  }

  @Test
  @DisplayName("JS-SEC-114: the class restriction still comes before an overridden declaration (pre-00.84 results unchanged)")
  void classRestrictionComesBeforeTheOverriddenDeclaration() throws NoSuchMethodException {
    assertEquals("USER", roleOf(scanner.scan(UserScopedOps.class.getMethod("purge"))),
        "UserScopedOps carries @RequiresRole(USER) and overrides purge() without an annotation");
  }

  @Test
  @DisplayName("JS-SEC-114: @PublicRoute on the overriding method is the opt-out; on the overridden one it is not inherited")
  void publicRoute_countsOnTheMethodThatRuns() throws NoSuchMethodException {
    assertTrue(scanner.scan(OpenedOps.class.getMethod("purge")).isEmpty(),
        "the override says @PublicRoute - the explicit opt-out wins");
    assertEquals("ADMIN", roleOf(scanner.scan(ReclosedOps.class.getMethod("purge"))),
        "ReclosedOps overrides the @PublicRoute override without an annotation: "
            + "the opt-out is not inherited, the restriction further up applies");
  }

  @Test
  @DisplayName("JS-SEC-114: static and private methods take part in no override")
  void staticAndPrivateMethods_areNotOverrides() throws NoSuchMethodException {
    assertTrue(scanner.scan(HidingOps.class.getDeclaredMethod("helper")).isEmpty(),
        "a static method hides, it does not override");
    assertTrue(scanner.scan(HidingOps.class.getDeclaredMethod("internal")).isEmpty(),
        "a private method of the same name in the base class is not overridden");
  }

  @Test
  @DisplayName("JS-SEC-114: a handler class that does not inherit the method is a wiring error, not 'no restriction'")
  void unrelatedHandlerClass_isRefused() throws NoSuchMethodException {
    Method method = CrudHandlers.class.getMethod("deleteAll");
    assertThrows(IllegalArgumentException.class, () -> scanner.scan(method, TenantOps.class));
  }

  @Test
  @DisplayName("JS-SEC-114: more than one restriction on an overridden declaration is still an error")
  void twoRestrictionsOnTheOverriddenDeclaration_throw() throws NoSuchMethodException {
    Method override = DualOverride.class.getMethod("purge");
    assertThrows(IllegalStateException.class, () -> scanner.scan(override));
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

  // JS-SEC-154: composed ("meta") annotation fixtures.
  @RequiresRole("ADMIN")
  @Retention(RetentionPolicy.RUNTIME)
  @interface AdminOnly {
  }

  @AdminOnly
  static class ComposedAdminView {
  }

  static class SubclassOfComposed extends ComposedAdminView {
  }

  @StubRestriction
  @Retention(RetentionPolicy.RUNTIME)
  @interface ComposedStub {
  }

  static class ComposedHandler {
    @ComposedStub
    void delete() {
    }
  }

  @AdminOnly
  @StubRestriction
  static class ComposedAndDirectView {
  }

  @StubRestriction
  @AnotherRestriction
  @Retention(RetentionPolicy.RUNTIME)
  @interface DoublyComposed {
  }

  @DoublyComposed
  static class DoublyComposedView {
  }

  @StubRestriction
  @Retention(RetentionPolicy.RUNTIME)
  @JCustosAnnotation(StubEvaluator.class)
  @interface RestrictionOnRestriction {
  }

  @RestrictionOnRestriction
  static class RestrictionOnRestrictionView {
  }

  @ComposedStub
  @Retention(RetentionPolicy.RUNTIME)
  @interface TwoLevels {
  }

  @TwoLevels
  static class TwoLevelsDeepView {
  }

  @TwoLevels
  @Retention(RetentionPolicy.RUNTIME)
  @interface ThreeLevels {
  }

  @ThreeLevels
  static class ThreeLevelsDeepView {
  }

  static class DeeplyComposedHandler {
    @TwoLevels
    public void purge() {
    }
  }

  /** Bound through @JCustosAnnotation to a type that is neither kind of evaluator. */
  static final class Advisor {
  }

  @Retention(RetentionPolicy.RUNTIME)
  @JCustosAnnotation(Advisor.class)
  @interface Advised {
  }

  @Advised
  static class AdvisedView {
  }

  @Advised
  static class AdvisedHandler {
    @Advised
    public void call() {
    }
  }

  @Advised
  @StubRestriction
  static class AdvisedAndRestrictedView {
  }

  @Advised
  @Retention(RetentionPolicy.RUNTIME)
  @interface ComposedAdvice {
  }

  @ComposedAdvice
  static class ComposedAdviceView {
  }

  @Retention(RetentionPolicy.RUNTIME)
  @interface PlainMarker {
  }

  @PlainMarker
  static class PlainMarkedView {
  }

  // JS-SEC-114: inherited and overriding handler methods.

  /** Shared CRUD plumbing, no annotation of its own. */
  public static class CrudHandlers {
    public void deleteAll() {
    }
  }

  @RequiresRole("ADMIN")
  public static class AdminHandlers extends CrudHandlers {
    public void own() {
    }
  }

  @RequiresRole("USER")
  public static class UserHandlers extends CrudHandlers {
  }

  public static class BaseOps {
    @RequiresRole("ADMIN")
    public void purge() {
    }

    @RequiresRole("ADMIN")
    public void audit() {
    }

    public static void helper() {
    }

    @RequiresRole("ADMIN")
    @SuppressWarnings("unused")
    private void internal() {
    }
  }

  public static class TenantOps extends BaseOps {
    @Override
    public void purge() {
    }
  }

  public static class RelabelledOps extends BaseOps {
    @Override
    @RequiresRole("USER")
    public void audit() {
    }
  }

  public static class LeafOps extends RelabelledOps {
    @Override
    public void audit() {
    }
  }

  @RequiresRole("USER")
  public static class UserScopedOps extends BaseOps {
    @Override
    public void purge() {
    }
  }

  public static class OpenedOps extends BaseOps {
    @Override
    @PublicRoute
    public void purge() {
    }
  }

  public static class ReclosedOps extends OpenedOps {
    @Override
    public void purge() {
    }
  }

  public static class HidingOps extends BaseOps {
    public static void helper() {
    }

    @SuppressWarnings("unused")
    void internal() {
    }
  }

  public interface Archive {
    @RequiresRole("ADMIN")
    void wipe();
  }

  public interface SubArchive extends Archive {
    @Override
    void wipe();
  }

  public static class ArchiveService implements Archive {
    @Override
    public void wipe() {
    }
  }

  public static class PlainArchive {
    public void wipe() {
    }
  }

  public static class ArchiveHandlers extends PlainArchive implements Archive {
  }

  public interface Sink<T> {
    @RequiresRole("ADMIN")
    void accept(T value);
  }

  public static class TextSink implements Sink<String> {
    @Override
    public void accept(String value) {
    }
  }

  public static class DualBase {
    @StubRestriction
    @AnotherRestriction
    public void purge() {
    }
  }

  public static class DualOverride extends DualBase {
    @Override
    public void purge() {
    }
  }
}
