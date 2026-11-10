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
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Scans annotated elements for {@link JCustosAnnotation}-meta-annotated
 * restriction annotations and resolves the corresponding evaluator class.
 * <p>
 * A restriction is found in three places: written on the element itself, inherited
 * from the superclass or an implemented interface (JS-SEC-040, JS-SEC-081), or
 * declared on an annotation type the element carries - a <em>composed</em>
 * annotation such as {@code @RequiresRole("ADMIN") @interface AdminOnly}
 * (JS-SEC-154). Composition is resolved exactly one level deep: an annotation on
 * an annotation on an annotation is not followed. An element may carry one
 * restriction only, however it is written; a second one raises
 * {@link IllegalStateException}.
 * <p>
 * <strong>Methods (JS-SEC-070, JS-SEC-114).</strong> The restriction of a method is
 * looked up in this order, and the first hit wins:
 * <ol>
 *   <li>the restriction written on the method that runs;</li>
 *   <li>{@link PublicRoute} on that method - the explicit opt-out, the result is
 *       empty;</li>
 *   <li>the restriction of the class the method is invoked on, as
 *       {@link #scan(Class)} resolves it;</li>
 *   <li>the restriction written on a declaration the method overrides or
 *       implements, in a superclass or an interface, the nearest one first.</li>
 * </ol>
 * "The class the method is invoked on" is the declaring class for
 * {@link #scan(Method)}. That is wrong for a method a handler class merely
 * <em>inherits</em>: {@code AdminHandlers.class.getMethod("deleteAll")} yields a
 * {@code Method} of the base class, and the {@code Method} does not remember
 * {@code AdminHandlers}. Callers that know the class pass it to
 * {@link #scan(Method, Class)}.
 * <p>
 * Results are cached per element. This class is Vaadin-free and can be
 * unit-tested independently.
 */
public final class JCustosAnnotationScanner {

  /** Creates a new scanner with an empty cache. */
  public JCustosAnnotationScanner() {
  }

  private final Map<AnnotatedElement, Optional<AnnotationAccessEvaluatorPair<Annotation>>> cache =
      new ConcurrentHashMap<>();

  /** Results of {@link #scan(Method, Class)}; the pair of both is the key (JS-SEC-114). */
  private final Map<MethodOnClass, Optional<AnnotationAccessEvaluatorPair<Annotation>>> methodCache =
      new ConcurrentHashMap<>();

  /** Cache key of {@link #scan(Method, Class)}. */
  private record MethodOnClass(Method method, Class<?> handlerClass) {
  }

  /**
   * Scans the given class for a restriction annotation and returns the
   * annotation together with the evaluator class declared via
   * {@link JCustosAnnotation}.
   *
   * @param navigationTarget the class to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Class<?> navigationTarget) {
    return scan((AnnotatedElement) navigationTarget);
  }

  /**
   * Scans the given method for a restriction annotation and returns the
   * annotation together with the evaluator class declared via
   * {@link JCustosAnnotation}. The method is taken to be invoked on its declaring
   * class; see the class description for the lookup order and
   * {@link #scan(Method, Class)} for methods a class inherits.
   *
   * @param method the method to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Method method) {
    return scan((AnnotatedElement) method);
  }

  /**
   * Scans a method as it is invoked on {@code handlerClass} (JS-SEC-114, CWE-862).
   * <p>
   * A {@code Method} obtained through {@code handlerClass.getMethod(...)} belongs to the
   * class that declares it. For an inherited method that is a base class, and
   * {@link #scan(Method)} then never sees the restriction of the class the request is
   * actually served by: {@code @RequiresRole("ADMIN") class AdminHandlers extends
   * CrudHandlers} left {@code CrudHandlers#deleteAll} open to everybody. This overload
   * resolves the method that runs on {@code handlerClass} - the override, if the class
   * or one of its superclasses has one - and falls back to the restriction of
   * {@code handlerClass} itself. The lookup order is the one in the class description.
   *
   * @param method       the handler method, declared by {@code handlerClass} or by one of
   *                     its supertypes; non-null
   * @param handlerClass the class whose instance serves the call; non-null
   * @return the pair, or empty if no restriction applies
   * @throws IllegalArgumentException if {@code handlerClass} is not a subtype of the
   *                                  class that declares {@code method}
   * @throws IllegalStateException    if more than one restriction annotation is found on
   *                                  one element
   * @since 00.84.00
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Method method, Class<?> handlerClass) {
    Objects.requireNonNull(method, "method must not be null");
    Objects.requireNonNull(handlerClass, "handlerClass must not be null");
    if (!method.getDeclaringClass().isAssignableFrom(handlerClass)) {
      // A wiring error, and one that must not be answered with "no restriction".
      throw new IllegalArgumentException(handlerClass.getName() + " does not inherit "
          + method.getDeclaringClass().getName() + "#" + method.getName());
    }
    return methodCache.computeIfAbsent(
        new MethodOnClass(method, handlerClass),
        key -> doScanMethod(effectiveMethod(key.method(), key.handlerClass()), key.handlerClass()));
  }

  /**
   * The declaration that applies when {@code method} is invoked on an instance of
   * {@code handlerClass}: the most derived declaration with the same signature in the
   * superclass chain of {@code handlerClass}; for a method no class in that chain
   * declares (an interface method, a default method), the most derived redeclaration in
   * the interfaces of {@code handlerClass}; otherwise {@code method} itself.
   *
   * @param method       the method as the caller obtained it; non-null
   * @param handlerClass the class whose instance serves the call; non-null
   * @return the declaration that applies, never {@code null}
   * @since 00.84.00
   */
  public static Method effectiveMethod(Method method, Class<?> handlerClass) {
    Objects.requireNonNull(method, "method must not be null");
    Objects.requireNonNull(handlerClass, "handlerClass must not be null");
    if (!isOverridable(method)) {
      return method;
    }
    for (Class<?> type = handlerClass; type != null && type != Object.class; type = type.getSuperclass()) {
      if (type == method.getDeclaringClass()) {
        return method;
      }
      if (type.isInterface()) {
        break;
      }
      Method redeclared = declaredWithSignature(type, method.getName(), method.getParameterTypes());
      if (redeclared != null && isOverridable(redeclared)) {
        return redeclared;
      }
    }
    Method mostDerived = method;
    for (Class<?> implemented : interfacesOf(handlerClass)) {
      Class<?> current = mostDerived.getDeclaringClass();
      if (implemented == current || !current.isAssignableFrom(implemented)) {
        continue;
      }
      Method redeclared = declaredWithSignature(implemented, method.getName(), method.getParameterTypes());
      if (redeclared != null && isOverridable(redeclared)) {
        mostDerived = redeclared;
      }
    }
    return mostDerived;
  }

  /** Every interface {@code type} is or implements, directly or through a supertype. */
  private static Set<Class<?>> interfacesOf(Class<?> type) {
    Set<Class<?>> interfaces = new LinkedHashSet<>();
    collectInterfaces(type, interfaces);
    return interfaces;
  }

  private static void collectInterfaces(Class<?> type, Set<Class<?>> interfaces) {
    if (type == null) {
      return;
    }
    if (type.isInterface() && !interfaces.add(type)) {
      return;
    }
    collectInterfaces(type.getSuperclass(), interfaces);
    for (Class<?> implemented : type.getInterfaces()) {
      collectInterfaces(implemented, interfaces);
    }
  }

  /**
   * Scans the given annotated element for a restriction annotation and returns
   * the annotation together with the evaluator class declared via
   * {@link JCustosAnnotation}.
   *
   * @param element the annotated element to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(AnnotatedElement element) {
    return cache.computeIfAbsent(element, this::doScan);
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> doScan(AnnotatedElement element) {
    Optional<AnnotationAccessEvaluatorPair<Annotation>> declared = scanDeclared(element);
    if (declared.isPresent()) {
      return declared;
    }
    // JS-SEC-040 (CWE-863): a routed subclass of a security-annotated superclass must inherit
    // the restriction (most-derived wins) — otherwise the subclass scans as unprotected and,
    // under allow-by-omission, falls through to unguarded dispatch. `@Inherited` (added to the
    // shipped restriction annotations) already surfaces via getAnnotations() above, but it does
    // NOT cover consumer-defined restriction annotations; walking the superclass chain here
    // generalizes inheritance to any @JCustosAnnotation-meta-annotated annotation. Methods do
    // not inherit annotations, so only Class elements are walked up the superclass chain.
    //
    // JS-SEC-070 (CWE-862): a method without a restriction of its own takes the restriction
    // declared on (or inherited by) its class. The REST filter, the start-up discovery check and
    // the OpenAPI metadata all treat a class-level restriction as applying to every method, so
    // the scanner has to agree — otherwise a handler wired by Method ran unguarded under
    // allow-by-omission while the start-up check reported it as protected. An explicit
    // @PublicRoute on the method is the opt-out and wins over the class default.
    if (element instanceof Method method) {
      return afterOwnRestriction(method, method.getDeclaringClass());
    }
    if (element instanceof Class<?> clazz) {
      Class<?> superClass = clazz.getSuperclass();
      if (superClass != null && superClass != Object.class) {
        Optional<AnnotationAccessEvaluatorPair<Annotation>> inherited = doScan(superClass);
        if (inherited.isPresent()) {
          return inherited;
        }
      }
      // JS-SEC-081 (CWE-862): SecuredProxy guards interface types, and a sub-interface that
      // redeclares or adds methods used to shed the restriction declared on its super-interface
      // (the superclass of an interface is null, so the walk above never saw it). Interfaces are
      // walked after the superclass chain, in declaration order; the first restriction wins.
      for (Class<?> implemented : clazz.getInterfaces()) {
        Optional<AnnotationAccessEvaluatorPair<Annotation>> fromInterface = doScan(implemented);
        if (fromInterface.isPresent()) {
          return fromInterface;
        }
      }
    }
    return Optional.empty();
  }

  /** {@link #scan(Method, Class)} for a method that is already the one that runs. */
  private Optional<AnnotationAccessEvaluatorPair<Annotation>> doScanMethod(Method method, Class<?> handlerClass) {
    Optional<AnnotationAccessEvaluatorPair<Annotation>> declared = scanDeclared(method);
    if (declared.isPresent()) {
      return declared;
    }
    return afterOwnRestriction(method, handlerClass);
  }

  /**
   * Steps two to four of the method lookup, for a method without a restriction of its own.
   * <p>
   * JS-SEC-114 (CWE-862, CWE-863): the last step is new. A method that overrides or
   * implements a restricted declaration without repeating the annotation used to scan as
   * unrestricted whenever its class carried no restriction either - annotations on methods
   * are not inherited in Java - so {@code TenantOps#purge}, overriding
   * {@code @RequiresRole("ADMIN") BaseOps#purge}, was served to everybody. The step comes
   * after the class restriction on purpose: every lookup that found a restriction before
   * 00.84.00 finds the same one now, and only a result that used to be empty can change.
   * {@code @PublicRoute} on an overridden declaration is not inherited; the opt-out has to
   * be written on the method that runs.
   */
  private Optional<AnnotationAccessEvaluatorPair<Annotation>> afterOwnRestriction(
      Method method, Class<?> handlerClass) {
    if (method.isAnnotationPresent(PublicRoute.class)) {
      return Optional.empty();
    }
    Optional<AnnotationAccessEvaluatorPair<Annotation>> fromClass = doScan(handlerClass);
    if (fromClass.isPresent()) {
      return fromClass;
    }
    return scanOverridden(method, handlerClass);
  }

  /**
   * Looks for a restriction on the declarations {@code method} overrides or implements
   * when it runs on {@code handlerClass}. The walk starts at {@code handlerClass}, not at
   * the class that declares the method: a method inherited from a base class may implement
   * an interface only the handler class names. The order is the one {@link #doScan} uses
   * for classes - the type itself, the superclass chain, then the interfaces - and the
   * first declaration that carries a restriction wins.
   */
  private Optional<AnnotationAccessEvaluatorPair<Annotation>> scanOverridden(
      Method method, Class<?> handlerClass) {
    if (!isOverridable(method)) {
      return Optional.empty();
    }
    List<Class<?>[]> signatures = new ArrayList<>();
    signatures.add(method.getParameterTypes());
    addBridgeSignatures(method.getDeclaringClass(), method.getName(), signatures);
    return scanOverriddenIn(handlerClass, method.getName(), signatures, new HashSet<>());
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> scanOverriddenIn(
      Class<?> type, String name, List<Class<?>[]> signatures, Set<Class<?>> visited) {
    if (type == null || type == Object.class || !visited.add(type)) {
      return Optional.empty();
    }
    boolean declaresIt = false;
    for (Class<?>[] signature : signatures) {
      Method declared = declaredWithSignature(type, name, signature);
      if (declared == null || !isOverridable(declared)) {
        continue;
      }
      Optional<AnnotationAccessEvaluatorPair<Annotation>> restriction = scanDeclared(declared);
      if (restriction.isPresent()) {
        return restriction;
      }
      declaresIt = true;
    }
    List<Class<?>[]> known = signatures;
    if (declaresIt) {
      known = new ArrayList<>(signatures);
      addBridgeSignatures(type, name, known);
    }
    Optional<AnnotationAccessEvaluatorPair<Annotation>> fromSuperclass =
        scanOverriddenIn(type.getSuperclass(), name, known, visited);
    if (fromSuperclass.isPresent()) {
      return fromSuperclass;
    }
    for (Class<?> implemented : type.getInterfaces()) {
      Optional<AnnotationAccessEvaluatorPair<Annotation>> fromInterface =
          scanOverriddenIn(implemented, name, known, visited);
      if (fromInterface.isPresent()) {
        return fromInterface;
      }
    }
    return Optional.empty();
  }

  /**
   * A method that implements a generic declaration has other parameter types than the
   * declaration it overrides ({@code handle(String)} against {@code handle(T)}, erased to
   * {@code handle(Object)}). The compiler records the link as a bridge method in the same
   * class; its parameter types are the signature to look for further up.
   */
  private static void addBridgeSignatures(Class<?> type, String name, List<Class<?>[]> signatures) {
    for (Method candidate : type.getDeclaredMethods()) {
      if (!candidate.isBridge() || !candidate.getName().equals(name)) {
        continue;
      }
      Class<?>[] bridged = candidate.getParameterTypes();
      boolean alreadyKnown = false;
      boolean bridgesKnown = false;
      for (Class<?>[] signature : signatures) {
        alreadyKnown |= Arrays.equals(signature, bridged);
        bridgesKnown |= accepts(bridged, signature);
      }
      if (bridgesKnown && !alreadyKnown) {
        signatures.add(bridged);
      }
    }
  }

  /** @return whether every parameter type of {@code wider} accepts the one of {@code narrower} */
  private static boolean accepts(Class<?>[] wider, Class<?>[] narrower) {
    if (wider.length != narrower.length) {
      return false;
    }
    for (int i = 0; i < wider.length; i++) {
      if (!wider[i].isAssignableFrom(narrower[i])) {
        return false;
      }
    }
    return true;
  }

  private static Method declaredWithSignature(Class<?> type, String name, Class<?>[] parameterTypes) {
    Method bridge = null;
    for (Method candidate : type.getDeclaredMethods()) {
      if (candidate.getName().equals(name)
          && Arrays.equals(candidate.getParameterTypes(), parameterTypes)) {
        if (!candidate.isBridge()) {
          return candidate;
        }
        bridge = candidate;
      }
    }
    return bridge;
  }

  /** Static and private methods are neither overridden nor do they override anything. */
  private static boolean isOverridable(Method method) {
    int modifiers = method.getModifiers();
    return !Modifier.isStatic(modifiers) && !Modifier.isPrivate(modifiers);
  }

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> scanDeclared(AnnotatedElement element) {
    // Only the element's OWN restriction annotations — getDeclaredAnnotations() excludes
    // @Inherited annotations surfaced from a superclass, so the explicit superclass walk in
    // doScan() stays the single, authoritative inheritance mechanism (most-derived wins) and a
    // subclass that overrides its base's restriction is never counted as "more than one".
    List<Annotation> list = new ArrayList<>();
    for (Annotation declared : element.getDeclaredAnnotations()) {
      if (isRestriction(declared)) {
        list.add(declared);
      }
      // JS-SEC-154 (CWE-862): a composed annotation - an annotation type that itself carries a
      // restriction, e.g. `@RequiresRole("ADMIN") @interface AdminOnly` - used to compile and
      // then protect nothing, because only annotations carrying @JCustosAnnotation directly
      // were recognised. The restriction declared on the annotation type is resolved one level
      // deep and counts like a restriction written on the element itself, so the "more than
      // one restriction" rule below covers every combination: two restrictions on the composed
      // type, a composed annotation next to a direct one, or two composed annotations.
      for (Annotation meta : declared.annotationType().getDeclaredAnnotations()) {
        if (isRestriction(meta)) {
          list.add(meta);
        }
      }
    }

    return switch (list.size()) {
      case 0 -> Optional.empty();
      case 1 -> {
        Annotation annotation = list.getFirst();
        JCustosAnnotation navAnno = annotation.annotationType()
            .getAnnotation(JCustosAnnotation.class);
        Class<?> evaluatorClass = navAnno.value();
        var pair = new AnnotationAccessEvaluatorPair<>(annotation, evaluatorClass);
        yield Optional.of(pair);
      }
      default -> throw new IllegalStateException(
          "More than one @JCustosAnnotation is not allowed on " + element);
    };
  }

  private static boolean isRestriction(Annotation annotation) {
    return annotation.annotationType().isAnnotationPresent(JCustosAnnotation.class);
  }
}
