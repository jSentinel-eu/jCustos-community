package eu.jsentinel.jcustos.dx.rest.handlers;

import static java.util.Objects.requireNonNull;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * Discovers unprotected handlers by scanning the handler classes an application
 * names, so a REST application gets the same startup check Vaadin gets from its
 * router.
 *
 * <p>Pass the classes whose methods serve requests:
 *
 * <pre>{@code
 * RestSecurity.bootstrap()
 *     .discoverHandlers(new ClassScanningRestHandlerDiscovery(DocumentHandlers.class, AdminHandlers.class))
 *     .install();
 * }</pre>
 *
 * <p>A method counts as protected when a restriction applies to it - written on
 * the method, on the handler class, or on a declaration the method overrides -
 * or when it is marked {@link PublicRoute}.
 *
 * <p>JS-SEC-114 (CWE-862): the verdict is not computed here. Every public
 * instance method the handler class has, <em>inherited ones included</em>, is
 * put to {@link RestAuthorizationFilter#isOpenByOmission(Method, Class)} - the
 * question {@code RestAuthorizationFilter} answers with the same lookups when
 * a request arrives through
 * {@code authorizeAndHandle(request, response, handler, method, handlerClass)}.
 * Until 00.84.00 the discovery looked at the handler class once and then only
 * at the methods it declares itself: a class-level restriction reported every
 * method as protected while the filter served an inherited one to everybody,
 * and an unprotected inherited method was never reported at all.
 *
 * <p>The verdict holds for handlers wired with their handler class. A filter
 * call that passes an inherited {@code Method} without the handler class sees
 * the class that declares the method instead, and may decide differently.
 *
 * <p>What this cannot see is a handler you never pass in. The check is only as
 * complete as the list, which is the price of REST having no registry to
 * enumerate.
 *
 * @since 00.82.00
 */
public final class ClassScanningRestHandlerDiscovery implements RestHandlerDiscovery {

  private final List<Class<?>> handlerClasses;

  /**
   * @param handlerClasses classes whose non-static methods serve REST requests
   */
  public ClassScanningRestHandlerDiscovery(Class<?>... handlerClasses) {
    requireNonNull(handlerClasses, "handlerClasses must not be null");
    this.handlerClasses = List.copyOf(Arrays.asList(handlerClasses));
  }

  @Override
  public Stream<String> discoverUnannotatedHandlerNames() {
    List<String> unprotected = new ArrayList<>();
    for (Class<?> handlerClass : handlerClasses) {
      // JS-SEC-114: getMethods(), not getDeclaredMethods() - a handler class serves the
      // public methods it inherits just as it serves its own.
      for (Method method : handlerClass.getMethods()) {
        if (method.isSynthetic() || method.isBridge() || Modifier.isStatic(method.getModifiers())) {
          continue;
        }
        if (method.getDeclaringClass() == Object.class) {
          continue;
        }
        if (isOpenByOmission(method, handlerClass)) {
          unprotected.add(handlerClass.getName() + "#" + method.getName());
        }
      }
    }
    // Drained here on purpose: a stream that throws while the bootstrap reads it
    // would fail the boot far from its cause.
    return unprotected.stream();
  }

  @Override
  public boolean handlersAvailable() {
    return !handlerClasses.isEmpty();
  }

  private static boolean isOpenByOmission(Method method, Class<?> handlerClass) {
    try {
      return RestAuthorizationFilter.isOpenByOmission(method, handlerClass);
    } catch (RuntimeException tooManyAnnotations) {
      // More than one security annotation is a configuration error the scanner
      // reports elsewhere. Counting it as protected keeps this check from
      // claiming the handler is unguarded, which it demonstrably is not.
      return false;
    }
  }
}
