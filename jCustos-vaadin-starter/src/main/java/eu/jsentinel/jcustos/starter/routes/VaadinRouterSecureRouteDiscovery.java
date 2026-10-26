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
package eu.jsentinel.jcustos.starter.routes;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.impl.JCustosAnnotationScanner;
import eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;

import java.util.stream.Stream;

/**
 * Default {@link SecureRouteDiscovery}: enumerates Vaadin's
 * application-scope routes and emits the {@code policy()} value of
 * every {@link SecureRoute}-annotated navigation target whose policy
 * string is non-empty.
 *
 * <p>Lives in {@code security-vaadin-starter} because the
 * {@code @SecureRoute} annotation is owned by this module; the
 * {@code SecureRouteDiscovery} SPI lives in {@code security-dx-vaadin}
 * because the bootstrap consumes it without depending on the starter
 * package.
 *
 * <p>Falls back to an empty stream when Vaadin's application-scope
 * routes are not yet initialised.
 *
 * @since 00.73.00
 */
public final class VaadinRouterSecureRouteDiscovery implements SecureRouteDiscovery {

  private final JCustosAnnotationScanner scanner = new JCustosAnnotationScanner();

  @Override
  public Stream<String> discoverPolicyNames() {
    try {
      return RouteConfiguration.forApplicationScope()
          .getAvailableRoutes().stream()
          .map(RouteData::getNavigationTarget)
          .filter(c -> c != null && c.isAnnotationPresent(SecureRoute.class))
          .map(c -> c.getAnnotation(SecureRoute.class).policy())
          .filter(s -> s != null && !s.isEmpty());
    } catch (RuntimeException ignored) {
      return Stream.empty();
    }
  }

  @Override
  public Stream<String> discoverConstraintlessRouteNames() {
    try {
      return RouteConfiguration.forApplicationScope()
          .getAvailableRoutes().stream()
          .map(RouteData::getNavigationTarget)
          .filter(c -> c != null && c.isAnnotationPresent(SecureRoute.class))
          .filter(VaadinRouterSecureRouteDiscovery::isConstraintless)
          .map(Class::getSimpleName);
    } catch (RuntimeException ignored) {
      return Stream.empty();
    }
  }

  @Override
  public Stream<String> discoverUnannotatedRouteNames() {
    try {
      // RF (exit-review): collect eagerly (toList) INSIDE the try so any per-element
      // exception is caught here, not later when the bootstrap drains the stream outside
      // this method's try/catch (which would take the whole boot down — RF05).
      return RouteConfiguration.forApplicationScope()
          .getAvailableRoutes().stream()
          .map(RouteData::getNavigationTarget)
          .filter(c -> c != null && isConsumerRoute(c) && isUnannotated(c))
          .map(Class::getSimpleName)
          .toList()
          .stream();
    } catch (RuntimeException ignored) {
      return Stream.empty();
    }
  }

  @Override
  public boolean routesAvailable() {
    // RF (exit-review): probe the registry so the bootstrap can tell "no un-annotated
    // routes" apart from "registry not readable" and raise a loud
    // deny-by-default/discovery-unavailable instead of a silent green STRICT boot (RF03).
    try {
      RouteConfiguration.forApplicationScope().getAvailableRoutes();
      return true;
    } catch (RuntimeException notAvailable) {
      return false;
    }
  }

  /**
   * RF (exit-review, RF02): the deny-by-default diagnostic is about the <em>consumer's</em>
   * routes. Until 00.84.00 the framework's own {@code SessionManagementRoute} was excluded here
   * by type because it carried no annotation; it now carries {@code @ProtectedBy} and scans as
   * protected, so no route needs a type-based exclusion any more (JS-SEC-068, CWE-306).
   */
  private static boolean isConsumerRoute(Class<?> target) {
    // JS-SEC-068 (CWE-306): the framework's SessionManagementRoute now carries
    // @ProtectedBy, so it scans as protected like any consumer route and needs no
    // type-based exclusion. The method stays as the single place such an
    // exclusion would live.
    return target != null;
  }

  /**
   * RF (exit-review, RF05): a route may legitimately be un-annotated, or it may carry more
   * than one {@code @JCustosAnnotation} — which makes {@code scanner.scan} throw. A misconfigured
   * multi-annotation route is <em>annotated</em> (not a deny-by-default risk) and must not abort
   * discovery, so the scan is guarded per element and such a route is skipped rather than fatal.
   */
  private boolean isUnannotated(Class<?> target) {
    if (target.isAnnotationPresent(PublicRoute.class)) {
      return false;
    }
    try {
      return scanner.scan(target).isEmpty();
    } catch (RuntimeException multipleAnnotations) {
      return false;
    }
  }

  private static boolean isConstraintless(Class<?> target) {
    SecureRoute a = target.getAnnotation(SecureRoute.class);
    return a.roles().length == 0
        && a.permissions().length == 0
        && a.policy().isEmpty();
  }
}
