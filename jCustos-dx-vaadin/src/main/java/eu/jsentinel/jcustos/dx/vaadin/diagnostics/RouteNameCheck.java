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
package eu.jsentinel.jcustos.dx.vaadin.diagnostics;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import com.vaadin.flow.router.RouteConfiguration;

/**
 * Tells whether a route name resolves to a route in Vaadin's application-scope registry
 * (JS-SEC-152, CWE-636). The login route and the step-up route are published as names;
 * the authorisation listener sends a denied visitor there. A name no route is registered
 * under cannot be rerouted to - the listener then answers with the error view - so the
 * bootstrap and the diagnostics report it before the first visitor finds out.
 * <p>
 * The check reads the application scope at the moment it runs. A route that is registered
 * later, or in the session scope only, is reported as not registered.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RouteNameCheck {

  /**
   * Outcome of a route-name check.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public enum Result {
    /** A route is registered under the name. */
    REGISTERED,
    /** The registry was read and holds no route under the name. */
    UNREGISTERED,
    /**
     * The registry could not be read - no {@code VaadinService} is current, as in a
     * {@code ServletContextListener}, a static initialiser or a {@code main} method.
     * Nothing can be said about the name.
     * <p>
     * Inside {@code VaadinServiceInitListener.serviceInit} the service <em>is</em> current
     * ({@code VaadinService.init()} runs its init listeners with the service as current
     * instance), so a bootstrap called from there is checked against the routes the servlet
     * container registered at context start-up.
     */
    UNAVAILABLE
  }

  private RouteNameCheck() {
    // utility
  }

  /**
   * Checks one route name against the application-scope route registry.
   *
   * @param routeName the route name; {@code null} or blank counts as not registered
   * @return the outcome, never {@code null}
   */
  public static Result check(String routeName) {
    RouteConfiguration routes;
    try {
      routes = RouteConfiguration.forApplicationScope();
      routes.getAvailableRoutes();
    } catch (RuntimeException notAvailable) {
      return Result.UNAVAILABLE;
    }
    if (routeName == null || routeName.isBlank()) {
      return Result.UNREGISTERED;
    }
    try {
      return routes.getRoute(routeName).isPresent() ? Result.REGISTERED : Result.UNREGISTERED;
    } catch (RuntimeException invalidPath) {
      return Result.UNREGISTERED;
    }
  }
}
