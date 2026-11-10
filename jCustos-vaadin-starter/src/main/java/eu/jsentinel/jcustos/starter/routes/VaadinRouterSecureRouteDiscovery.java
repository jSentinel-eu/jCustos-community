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

import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver.Restriction;
import eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.router.RouterLayout;
import com.vaadin.flow.server.RouteRegistry;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Default {@link SecureRouteDiscovery}: enumerates Vaadin's
 * application-scope routes and emits the {@code policy()} value of
 * every {@link SecureRoute} restriction that applies to a route and
 * whose policy string is non-empty.
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
 * <p><strong>Same decision as at run time (JS-SEC-154, CWE-862):</strong> which
 * restrictions apply to a route is answered by {@link RouteRestrictionResolver}, the
 * class {@code AuthorizationListener} enforces navigation with. A restriction therefore
 * counts wherever the listener finds it - on the navigation target, on a superclass, as a
 * composed annotation, or on a {@code RouterLayout} of the route's layout chain - and a
 * route is reported as un-annotated exactly when the listener would let it pass by
 * omission. A route class is looked at once per path: an alias may use another layout
 * than the route, so it counts as un-annotated as soon as one of its paths is open.
 *
 * @since 00.73.00
 */
public final class VaadinRouterSecureRouteDiscovery implements SecureRouteDiscovery {

  private final RouteRestrictionResolver resolver = new RouteRestrictionResolver();

  private final Supplier<RouteRegistry> registry;

  /** Creates a discovery over Vaadin's application-scope route registry. */
  public VaadinRouterSecureRouteDiscovery() {
    this(() -> RouteConfiguration.forApplicationScope().getHandledRegistry());
  }

  /**
   * Creates a discovery over the given registry - for tests that register routes without
   * a running {@code VaadinService}.
   *
   * @param registry supplies the registry to read; may throw when it is not available
   */
  VaadinRouterSecureRouteDiscovery(Supplier<RouteRegistry> registry) {
    this.registry = Objects.requireNonNull(registry, "registry");
  }

  @Override
  public Stream<String> discoverPolicyNames() {
    try {
      // JS-SEC-154: collected eagerly inside the try, like the un-annotated routes below.
      Set<String> policyNames = new LinkedHashSet<>();
      for (Restriction restriction : secureRouteRestrictions()) {
        String policy = ((SecureRoute) restriction.annotation()).policy();
        if (policy != null && !policy.isEmpty()) {
          policyNames.add(policy);
        }
      }
      return policyNames.stream();
    } catch (RuntimeException ignored) {
      return Stream.empty();
    }
  }

  @Override
  public Stream<String> discoverConstraintlessRouteNames() {
    try {
      Set<String> names = new LinkedHashSet<>();
      for (Restriction restriction : secureRouteRestrictions()) {
        if (isConstraintless((SecureRoute) restriction.annotation())) {
          names.add(restriction.source().getSimpleName());
        }
      }
      return names.stream();
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
      RouteRegistry routes = registry.get();
      return routes.getRegisteredRoutes().stream()
          .filter(route -> route.getNavigationTarget() != null
              && isConsumerRoute(route.getNavigationTarget())
              && isUnannotated(routes, route))
          .map(route -> route.getNavigationTarget().getSimpleName())
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
      registry.get().getRegisteredRoutes();
      return true;
    } catch (RuntimeException notAvailable) {
      return false;
    }
  }

  /**
   * JS-SEC-154 (CWE-862): every {@link SecureRoute} restriction that applies to a registered
   * route - found on the target, inherited, composed, or declared on a layout of one of the
   * route's layout chains. A layout shared by several routes is listed once.
   */
  private List<Restriction> secureRouteRestrictions() {
    RouteRegistry routes = registry.get();
    Set<Restriction> found = new LinkedHashSet<>();
    for (RouteData route : routes.getRegisteredRoutes()) {
      Class<?> target = route.getNavigationTarget();
      if (target == null) {
        continue;
      }
      for (List<Class<? extends RouterLayout>> chain
          : RouteRestrictionResolver.layoutChains(routes, route)) {
        try {
          for (Restriction restriction : resolver.resolve(target, chain)) {
            if (restriction.annotation() instanceof SecureRoute) {
              found.add(restriction);
            }
          }
        } catch (RuntimeException multipleAnnotations) {
          // a route or layout with more than one restriction fails at navigation time;
          // it must not abort the discovery of the other routes (RF05)
        }
      }
    }
    return new ArrayList<>(found);
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
   * <p>
   * JS-SEC-154 (CWE-862): the classification is {@link RouteRestrictionResolver#isOpenByOmission}
   * - the one the listener denies by under deny-by-default - applied to every path of the
   * route. A restriction on a layout protects the route; {@code @PublicRoute} on the target
   * declares it public.
   */
  private boolean isUnannotated(RouteRegistry routes, RouteData route) {
    Class<?> target = route.getNavigationTarget();
    try {
      for (List<Class<? extends RouterLayout>> chain
          : RouteRestrictionResolver.layoutChains(routes, route)) {
        if (resolver.isOpenByOmission(target, chain)) {
          return true;
        }
      }
      return false;
    } catch (RuntimeException multipleAnnotations) {
      return false;
    }
  }

  private static boolean isConstraintless(SecureRoute a) {
    return a.roles().length == 0
        && a.permissions().length == 0
        && a.policy().isEmpty();
  }
}
