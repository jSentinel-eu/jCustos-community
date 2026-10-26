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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Arrays.stream;

/**
 * Scans annotated elements for {@link JCustosAnnotation}-meta-annotated
 * restriction annotations and resolves the corresponding evaluator class.
 * <p>
 * Results are cached per class. This class is Vaadin-free and can be
 * unit-tested independently.
 */
public final class JCustosAnnotationScanner {

  /** Creates a new scanner with an empty cache. */
  public JCustosAnnotationScanner() {
  }

  private final Map<AnnotatedElement, Optional<AnnotationAccessEvaluatorPair<Annotation>>> cache =
      new ConcurrentHashMap<>();

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
   * {@link JCustosAnnotation}.
   *
   * @param method the method to scan
   * @return the pair, or empty if no restriction annotation is present
   * @throws IllegalStateException if more than one restriction annotation is found
   */
  public Optional<AnnotationAccessEvaluatorPair<Annotation>> scan(Method method) {
    return scan((AnnotatedElement) method);
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
      if (method.isAnnotationPresent(PublicRoute.class)) {
        return Optional.empty();
      }
      return doScan(method.getDeclaringClass());
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

  private Optional<AnnotationAccessEvaluatorPair<Annotation>> scanDeclared(AnnotatedElement element) {
    // Only the element's OWN restriction annotations — getDeclaredAnnotations() excludes
    // @Inherited annotations surfaced from a superclass, so the explicit superclass walk in
    // doScan() stays the single, authoritative inheritance mechanism (most-derived wins) and a
    // subclass that overrides its base's restriction is never counted as "more than one".
    List<Annotation> list = stream(element.getDeclaredAnnotations())
        .filter(a -> a.annotationType().isAnnotationPresent(JCustosAnnotation.class))
        .toList();

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
}
