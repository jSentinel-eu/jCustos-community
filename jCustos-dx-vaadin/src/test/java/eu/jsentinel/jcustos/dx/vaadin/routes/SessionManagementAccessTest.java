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

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SessionManagementAccess (JS-SEC-068)")
class SessionManagementAccessTest {

  private static final PermissionName ADMIN_SESSIONS = new PermissionName("admin:sessions");
  private static final RoleName ADMIN = new RoleName("ADMIN");

  private final SessionManagementAccess evaluator = new SessionManagementAccess();

  @AfterEach
  void reset() {
    SessionManagementContext.reset();
  }

  private static AccessContext context(Optional<JCustosSubject> subject) {
    return new AccessContext(subject, "vaadin-route", "session-management", "navigate", Map.of());
  }

  private static JCustosSubject subject(Set<RoleName> roles, Set<PermissionName> permissions) {
    return new JCustosSubject("alice", "Alice", roles, permissions);
  }

  @Test
  @DisplayName("no published requirement → Forbidden, never open")
  void noRequirementForbidden() {
    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject(Set.of(ADMIN), Set.of(ADMIN_SESSIONS)))), null);
    AuthorizationDecision.Forbidden forbidden = assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals(SessionManagementAccess.REASON_NO_REQUIREMENT, forbidden.reason());
  }

  @Test
  @DisplayName("requirement published, no subject → Unauthenticated")
  void noSubjectUnauthenticated() {
    SessionManagementContext.publish(new InMemorySessionStore(), null, Requirement.permission(ADMIN_SESSIONS));
    AuthorizationDecision decision = evaluator.evaluate(context(Optional.empty()), null);
    AuthorizationDecision.Unauthenticated unauthenticated =
        assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
    assertEquals(SessionManagementAccess.REASON_UNAUTHENTICATED, unauthenticated.reason());
  }

  @Test
  @DisplayName("subject without the permission → Forbidden")
  void subjectWithoutPermissionForbidden() {
    SessionManagementContext.publish(new InMemorySessionStore(), null, Requirement.permission(ADMIN_SESSIONS));
    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject(Set.of(ADMIN), Set.of()))), null);
    AuthorizationDecision.Forbidden forbidden = assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals(SessionManagementAccess.REASON_NOT_MET, forbidden.reason());
  }

  @Test
  @DisplayName("subject holding the permission → Granted")
  void subjectWithPermissionGranted() {
    SessionManagementContext.publish(new InMemorySessionStore(), null, Requirement.permission(ADMIN_SESSIONS));
    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject(Set.of(), Set.of(ADMIN_SESSIONS)))), null);
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("an empty requirement publishes nothing — the route stays closed")
  void emptyRequirementPublishesNothing() {
    SessionManagementContext.publish(new InMemorySessionStore(), null, Requirement.none());
    assertTrue(SessionManagementContext.requirement().isEmpty());
    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject(Set.of(ADMIN), Set.of(ADMIN_SESSIONS)))), null);
    assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
  }
}
