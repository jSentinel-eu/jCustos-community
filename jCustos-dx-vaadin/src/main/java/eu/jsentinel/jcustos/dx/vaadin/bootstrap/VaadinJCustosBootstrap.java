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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.dx.bootstrap.CommonJCustosBootstrap;

/**
 * Vaadin-specific fluent bootstrap. Entry point:
 * {@link VaadinSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface VaadinJCustosBootstrap
    extends CommonJCustosBootstrap<VaadinJCustosBootstrap> {

  /**
   * Records the configured subject type for downstream observers
   * (e.g. the Vaadin starter). Optional.
   *
   * @param subjectType non-null subject Class
   * @return this builder
   */
  VaadinJCustosBootstrap subjectType(Class<?> subjectType);

  /**
   * Records the application's login route name. Optional; the starter
   * uses this for default-after-login routing.
   *
   * @param route non-null route name (e.g. {@code "login"})
   * @return this builder
   */
  VaadinJCustosBootstrap loginRoute(String route);

  /**
   * Configures the step-up authentication route. Forwarded to
   * {@code JCustosServiceResolver.setStepUpRouteName(...)}.
   *
   * @param route non-blank route name
   * @return this builder
   */
  VaadinJCustosBootstrap stepUpRoute(String route);

  /**
   * Marks the bootstrap as opting into the secured-UI components.
   * Consumed by the Vaadin starter in Phase 3.
   *
   * @return this builder
   */
  VaadinJCustosBootstrap securedComponents();

  /**
   * Opts into the framework's {@code SessionManagementRoute} without an
   * access requirement. Since 00.84.00 the route then denies every
   * subject and the bootstrap reports
   * {@code session-management-view-without-requirement} (an error in
   * PRODUCTION and STRICT) — use
   * {@link #sessionManagementView(eu.jsentinel.jcustos.components.SecuredVisibility.Requirement)}.
   *
   * @return this builder
   * @deprecated since 00.84.00; pass the requirement (JS-SEC-068, CWE-306)
   */
  @Deprecated(since = "00.84.00")
  VaadinJCustosBootstrap sessionManagementView();

  /**
   * Opts into the framework's {@code SessionManagementRoute} and names
   * the roles and permissions a subject must hold to open it and to
   * revoke sessions from it (JS-SEC-068, CWE-306). Requires a
   * store-backed session configuration.
   *
   * @param requirement non-empty roles/permissions requirement
   * @return this builder
   * @throws UnsupportedOperationException from the default method; every
   *     shipped implementation overrides it
   * @since 00.84.00
   */
  default VaadinJCustosBootstrap sessionManagementView(
      eu.jsentinel.jcustos.components.SecuredVisibility.Requirement requirement) {
    throw new UnsupportedOperationException(
        "sessionManagementView(Requirement) is not supported by " + getClass().getName());
  }

  /**
   * V00.74: Configures the Vaadin {@code Component} class to render
   * when navigation is denied. Published to
   * {@link eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext}
   * for the starter's authorization listener to consume at attach
   * time (alternative to the framework default redirect).
   *
   * @param errorViewClass non-null component class
   * @return this builder
   * @since 00.74.00
   */
  VaadinJCustosBootstrap errorView(Class<?> errorViewClass);

  /**
   * V00.74: Configures the route name to navigate to after a
   * successful login. Published to
   * {@link eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext}
   * for the starter's login-flow callback to consume.
   *
   * @param route non-blank route name (without leading slash)
   * @return this builder
   * @since 00.74.00
   */
  VaadinJCustosBootstrap afterLoginRoute(String route);

  /**
   * V00.74: Configures the route name of the password-reset view.
   * Published to
   * {@link eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext}
   * so the application's login view can link to it.
   *
   * @param route non-blank route name (without leading slash)
   * @return this builder
   * @since 00.74.00
   */
  VaadinJCustosBootstrap passwordResetRoute(String route);

  /**
   * V00.73 (Konzept §8.5): opt into bootstrap-time discovery of
   * {@code @SecureRoute}-annotated classes. With {@code true}, the
   * default {@code VaadinRouterSecureRouteDiscovery} is used to
   * enumerate routes; the bootstrap then cross-checks every
   * {@code @SecureRoute(policy="…")} against the policy names
   * registered via {@code .policies(...)}. Mismatches surface as
   * {@code secure-route/unknown-policy} (STRICT throws).
   *
   * <p>Default: {@code false} — preserves V00.72 runtime-only
   * behaviour. When disabled, the bootstrap logs INFO
   * {@code secure-route/discovery-disabled}.
   *
   * @param enabled {@code true} to enable
   * @return this builder
   */
  VaadinJCustosBootstrap discoverSecureRoutes(boolean enabled);

  /**
   * V00.73 (Konzept §8.5): escape hatch — registers a custom
   * {@link eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery}
   * instead of the default {@code VaadinRouterSecureRouteDiscovery}.
   * Useful for lazy-loading setups that do not have Vaadin's
   * {@code RouteConfiguration} available at install-time. Implies
   * {@code .discoverSecureRoutes(true)}.
   *
   * @param discovery non-null discovery implementation
   * @return this builder
   */
  VaadinJCustosBootstrap discoverSecureRoutes(
      eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery discovery);

  /**
   * Applies a starter profile (e.g.
   * {@code VaadinJCustosStarter.developmentDefaults()}) to this
   * builder. The starter modules (downstream of
   * {@code security-dx-vaadin}) declare their profiles to implement
   * the {@link java.util.function.Consumer} contract on this builder
   * type; the profile sets defaults before any later builder calls so
   * user-provided overrides always win.
   *
   * @param profile starter profile that accepts this builder, never {@code null}
   * @return this builder
   */
  default VaadinJCustosBootstrap use(
      java.util.function.Consumer<? super VaadinJCustosBootstrap> profile) {
    java.util.Objects.requireNonNull(profile, "profile").accept(this);
    return this;
  }
}
