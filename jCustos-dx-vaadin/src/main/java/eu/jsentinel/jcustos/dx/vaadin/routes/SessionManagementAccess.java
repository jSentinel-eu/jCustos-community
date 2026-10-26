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
package eu.jsentinel.jcustos.dx.vaadin.routes;

import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;

import java.util.Optional;

/**
 * Access evaluator behind {@code @ProtectedBy} on
 * {@link SessionManagementRoute} (JS-SEC-068, CWE-306).
 *
 * <p>The route ships without a consumer annotation, so until 00.84.00
 * it was exempt from deny-by-default and reachable by every visitor
 * once a {@code SessionStore} was configured — including the Revoke
 * buttons. This evaluator closes that: it reads the
 * {@link Requirement} the bootstrap published through
 * {@link SessionManagementContext} and decides
 *
 * <ul>
 *   <li>{@code Forbidden} when no requirement was published — the route
 *       fails closed rather than open;</li>
 *   <li>{@code Unauthenticated} when no subject is bound;</li>
 *   <li>{@code Granted} only when the subject holds every required role
 *       and permission, {@code Forbidden} otherwise.</li>
 * </ul>
 *
 * <p>Vaadin instantiates the evaluator through its instantiator, hence
 * the public no-argument constructor.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class SessionManagementAccess implements AuthorizationEvaluator<ProtectedBy> {

  /** Reason when the bootstrap published no requirement. */
  public static final String REASON_NO_REQUIREMENT = "session-management:no-requirement-configured";
  /** Reason when no subject is bound. */
  public static final String REASON_UNAUTHENTICATED = "session-management:unauthenticated";
  /** Reason when the bound subject lacks a required role or permission. */
  public static final String REASON_NOT_MET = "session-management:requirement-not-met";

  /** Required by the Vaadin instantiator. */
  public SessionManagementAccess() {
  }

  @Override
  public AuthorizationDecision evaluate(AccessContext context, ProtectedBy annotation) {
    Optional<Requirement> requirement = SessionManagementContext.requirement();
    if (requirement.isEmpty()) {
      // JS-SEC-068 (CWE-306): no requirement configured — deny, never fall open.
      return AuthorizationDecision.forbidden(REASON_NO_REQUIREMENT);
    }
    Optional<JCustosSubject> subject = context.subject();
    if (subject.isEmpty()) {
      return AuthorizationDecision.unauthenticated(REASON_UNAUTHENTICATED);
    }
    JCustosSubject s = subject.get();
    return SecuredVisibility.isAllowed(requirement.get(), s, s)
        ? AuthorizationDecision.granted()
        : AuthorizationDecision.forbidden(REASON_NOT_MET);
  }
}
