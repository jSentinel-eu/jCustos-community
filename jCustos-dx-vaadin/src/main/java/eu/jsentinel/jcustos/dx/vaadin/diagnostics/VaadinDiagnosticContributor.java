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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;

/**
 * Vaadin-side {@link DiagnosticContributor}. Adds Vaadin-specific
 * findings to {@code JCustosDiagnostics.inspect()}.
 * <p>
 * Rules:
 * <ul>
 *   <li>{@code vaadin/step-up-route-blank} — step-up route configured
 *       but the route name is empty/whitespace.</li>
 *   <li>{@code vaadin/login-route-unresolved} — no route is registered under
 *       {@code JCustosServiceResolver.loginRouteName()} (JS-SEC-152).</li>
 *   <li>{@code vaadin/step-up-route-unresolved} — no route is registered under
 *       {@code JCustosServiceResolver.stepUpRouteName()} (JS-SEC-152).</li>
 * </ul>
 * The two {@code -unresolved} rules need Vaadin's route registry. Where it cannot be
 * read - {@code inspect()} called without a current {@code VaadinService} - they stay
 * silent; the bootstrap reports that case as {@code vaadin/route-check-unavailable}.
 * The bootstrap also carries the severity: a warning, and an error in STRICT and
 * PRODUCTION (see {@code VaadinJCustosBootstrap}).
 * Additional rules (SessionManagementView without SessionStore,
 * {@code @SecureRoute} referencing an unknown policy,
 * {@code subjectType} without store) require a route registry that is
 * not part of the V00.72 surface; they are reserved for V00.73 when
 * the starter's PolicyRegistry hook lands.
 *
 * @since 00.72.00
 */
@JCustosAutoService(DiagnosticContributor.class)
public final class VaadinDiagnosticContributor implements DiagnosticContributor {

  /**
   * Finding code: the login route name does not resolve to a registered route (JS-SEC-152).
   *
   * @since 00.84.00
   */
  public static final String LOGIN_ROUTE_UNRESOLVED = "vaadin/login-route-unresolved";

  /**
   * Finding code: the step-up route name does not resolve to a registered route (JS-SEC-152).
   *
   * @since 00.84.00
   */
  public static final String STEP_UP_ROUTE_UNRESOLVED = "vaadin/step-up-route-unresolved";

  /**
   * Suggested fix of {@link #LOGIN_ROUTE_UNRESOLVED}.
   *
   * @since 00.84.00
   */
  public static final String LOGIN_ROUTE_UNRESOLVED_FIX =
      "Register the login view under that route, or publish its real route name via "
          + "VaadinSecurity.bootstrap().loginRoute(...).";

  /**
   * Suggested fix of {@link #STEP_UP_ROUTE_UNRESOLVED}.
   *
   * @since 00.84.00
   */
  public static final String STEP_UP_ROUTE_UNRESOLVED_FIX =
      "Register a view under that route that renders the MFA / re-authentication challenge, or "
          + "publish its real route name via VaadinSecurity.bootstrap().stepUpRoute(...).";

  /** ServiceLoader requires a public no-arg constructor. */
  public VaadinDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "vaadin";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    try {
      String stepUp = JCustosServiceResolver.stepUpRouteName();
      if (stepUp == null || stepUp.isBlank()) {
        builder.addWarning(new ServiceWarning(
            "vaadin/step-up-route-blank",
            "Step-up route name is blank.",
            "Set a non-empty step-up route via VaadinSecurity.bootstrap().stepUpRoute(...)."));
      }
    } catch (RuntimeException e) {
      builder.addWarning(new ServiceWarning(
          "vaadin/rule-failed",
          "step-up-route check failed: " + e.getClass().getSimpleName() + ": " + e.getMessage(),
          "Inspect JCustosServiceResolver state."));
    }
    // JS-SEC-152 (CWE-636, CWE-285): the listener reroutes a denied visitor to these two
    // names. A name without a registered route cannot be rerouted to; the visitor then
    // lands in the error view instead of the login or step-up screen.
    try {
      String login = JCustosServiceResolver.loginRouteName();
      if (RouteNameCheck.check(login) == RouteNameCheck.Result.UNREGISTERED) {
        builder.addWarning(new ServiceWarning(
            LOGIN_ROUTE_UNRESOLVED,
            loginRouteUnresolvedMessage(login),
            LOGIN_ROUTE_UNRESOLVED_FIX));
      }
      String stepUp = JCustosServiceResolver.stepUpRouteName();
      if (stepUp != null && !stepUp.isBlank()
          && RouteNameCheck.check(stepUp) == RouteNameCheck.Result.UNREGISTERED) {
        builder.addWarning(new ServiceWarning(
            STEP_UP_ROUTE_UNRESOLVED,
            stepUpRouteUnresolvedMessage(stepUp),
            STEP_UP_ROUTE_UNRESOLVED_FIX));
      }
    } catch (RuntimeException e) {
      builder.addWarning(new ServiceWarning(
          "vaadin/rule-failed",
          "route-name check failed: " + e.getClass().getSimpleName() + ": " + e.getMessage(),
          "Inspect JCustosServiceResolver state."));
    }
  }

  /**
   * Message of {@link #LOGIN_ROUTE_UNRESOLVED}, shared with the bootstrap finding.
   *
   * @param routeName the unresolved login route name
   * @return the finding's message
   * @since 00.84.00
   */
  public static String loginRouteUnresolvedMessage(String routeName) {
    return "No route is registered under the login route name '" + routeName + "'. An "
        + "unauthenticated visitor of a restricted view is sent to the error view instead of "
        + "the login view.";
  }

  /**
   * Message of {@link #STEP_UP_ROUTE_UNRESOLVED}, shared with the bootstrap finding.
   *
   * @param routeName the unresolved step-up route name
   * @return the finding's message
   * @since 00.84.00
   */
  public static String stepUpRouteUnresolvedMessage(String routeName) {
    return "No route is registered under the step-up route name '" + routeName + "'. A "
        + "StepUpRequired decision sends the subject to the error view instead of a step-up "
        + "view.";
  }
}
