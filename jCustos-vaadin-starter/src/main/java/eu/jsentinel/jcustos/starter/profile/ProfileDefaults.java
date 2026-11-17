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
package eu.jsentinel.jcustos.starter.profile;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.ParentLayout;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.router.RoutePrefix;

import java.util.List;
import java.util.Optional;

/**
 * The fail-closed settings the production and strict profiles add to the bootstrap mode
 * (JS-SEC-168, CWE-1188): {@code denyByDefault(true)} and the route of the application's
 * {@link LoginView}.
 * <p>
 * Only an unambiguous login route counts; anything else leaves it to the application
 * ({@code .loginRoute(...)}, default {@code "login"}):
 * <ol>
 *   <li>When the route registry can be read - the bootstrap runs inside
 *       {@code VaadinServiceInitListener.serviceInit} - the registered routes whose target
 *       extends {@link LoginView}: exactly one, or, of several, the one the registered
 *       {@link LoginListener} names as its login view. A route with parameters does not
 *       count.</li>
 *   <li>Otherwise the {@code @Route} of the registered {@link LoginListener}'s login view,
 *       when it names the whole path: an explicit value without parameters, and no
 *       {@code @RoutePrefix} on its layouts unless the route is absolute.</li>
 * </ol>
 */
final class ProfileDefaults {

  private ProfileDefaults() {
    // utility
  }

  /**
   * Sets deny-by-default and, when it is unambiguous, the login route.
   *
   * @param bootstrap the builder the profile is applied to
   */
  static void applyFailClosed(VaadinJCustosBootstrap bootstrap) {
    bootstrap.denyByDefault(true);
    loginRoute().ifPresent(bootstrap::loginRoute);
  }

  /** @return the route of the application's login view, when it is unambiguous */
  static Optional<String> loginRoute() {
    Optional<Class<? extends LoginView>> listenerTarget = loginListenerTarget();
    Optional<List<RouteData>> registered = registeredRoutes();
    if (registered.isPresent()) {
      return fromRegistry(registered.get(), listenerTarget.orElse(null));
    }
    return listenerTarget.flatMap(ProfileDefaults::fromAnnotation);
  }

  private static Optional<String> fromRegistry(List<RouteData> routes, Class<? extends LoginView> preferred) {
    List<RouteData> loginRoutes = routes.stream()
        .filter(route -> LoginView.class.isAssignableFrom(route.getNavigationTarget()))
        .filter(route -> route.getRouteParameters().isEmpty())
        .filter(route -> !route.getTemplate().isBlank())
        .toList();
    if (loginRoutes.size() == 1) {
      return Optional.of(loginRoutes.getFirst().getTemplate());
    }
    if (preferred != null) {
      List<RouteData> named = loginRoutes.stream()
          .filter(route -> route.getNavigationTarget().equals(preferred))
          .toList();
      if (named.size() == 1) {
        return Optional.of(named.getFirst().getTemplate());
      }
    }
    if (loginRoutes.size() > 1) {
      HasLogger.staticLogger().debug("starter-profile/login-route-ambiguous: {} LoginView routes "
          + "are registered; the login route is left to .loginRoute(...)", loginRoutes.size());
    }
    return Optional.empty();
  }

  private static Optional<String> fromAnnotation(Class<? extends LoginView> target) {
    Route route = target.getAnnotation(Route.class);
    if (route == null || Route.NAMING_CONVENTION.equals(route.value())) {
      return Optional.empty();
    }
    String path = trimSlashes(route.value());
    if (path.isEmpty() || path.contains(":") || path.contains("*")) {
      return Optional.empty();
    }
    if (!route.absolute() && hasRoutePrefix(route.layout())) {
      return Optional.empty();
    }
    return Optional.of(path);
  }

  /** @return whether a layout of the chain adds a prefix to the path */
  private static boolean hasRoutePrefix(Class<?> layout) {
    Class<?> current = layout;
    while (current != null && current != UI.class) {
      if (current.isAnnotationPresent(RoutePrefix.class)) {
        return true;
      }
      ParentLayout parent = current.getAnnotation(ParentLayout.class);
      current = parent == null ? null : parent.value();
    }
    return false;
  }

  private static String trimSlashes(String value) {
    String path = value.strip();
    while (path.startsWith("/")) {
      path = path.substring(1);
    }
    while (path.endsWith("/")) {
      path = path.substring(0, path.length() - 1);
    }
    return path;
  }

  private static Optional<Class<? extends LoginView>> loginListenerTarget() {
    try {
      Optional<LoginListener<Object>> listener = LoginListeners.findLoginListener();
      return listener.map(LoginListener::loginNavigationTarget);
    } catch (RuntimeException noSingleListener) {
      // several listeners registered, or one that fails: not unambiguous
      return Optional.empty();
    }
  }

  /** @return the application-scope routes, or empty when no service is current */
  private static Optional<List<RouteData>> registeredRoutes() {
    try {
      return Optional.of(RouteConfiguration.forApplicationScope().getAvailableRoutes());
    } catch (RuntimeException registryUnavailable) {
      return Optional.empty();
    }
  }
}
