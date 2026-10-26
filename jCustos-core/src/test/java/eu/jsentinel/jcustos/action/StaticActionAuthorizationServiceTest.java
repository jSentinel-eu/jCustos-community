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
package eu.jsentinel.jcustos.action;

import eu.jsentinel.jcustos.audit.ActionDenied;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StaticActionAuthorizationService")
class StaticActionAuthorizationServiceTest {

  private final ActionPermission deleteUser = new ActionPermission("USER_ADMINISTRATION_DELETE");

  @Test
  @DisplayName("isAllowed true when subject's permission set carries the action name")
  void isAllowed_match() {
    StaticActionAuthorizationService<String> service = service(
        permissionsFor("alice", new PermissionName("USER_ADMINISTRATION_DELETE")));

    assertTrue(service.isAllowed("alice", deleteUser));
  }

  @Test
  @DisplayName("isAllowed false when subject lacks the permission")
  void isAllowed_noMatch() {
    StaticActionAuthorizationService<String> service = service(
        permissionsFor("alice", new PermissionName("USER_READ")));

    assertFalse(service.isAllowed("alice", deleteUser));
  }

  @Test
  @DisplayName("a wildcard grant authorizes a specific action via PermissionMatcher (R027)")
  void isAllowed_wildcard() {
    ActionPermission delete = new ActionPermission("doc:delete");
    StaticActionAuthorizationService<String> service = service(
        permissionsFor("alice", new PermissionName("doc:*")));

    assertTrue(service.isAllowed("alice", delete),
        "a doc:* wildcard grant must authorize doc:delete, like the annotation path");
  }

  @Test
  @DisplayName("isAllowed false for null subject or null permission")
  void isAllowed_nullArguments() {
    StaticActionAuthorizationService<String> service = service(permissionsFor("alice"));

    assertFalse(service.isAllowed(null, deleteUser));
    assertFalse(service.isAllowed("alice", null));
  }

  @Test
  @DisplayName("requireAllowed runs silently when the permission is held")
  void requireAllowed_passes() {
    StaticActionAuthorizationService<String> service = service(
        permissionsFor("alice", new PermissionName("USER_ADMINISTRATION_DELETE")));

    assertDoesNotThrow(() -> service.requireAllowed("alice", deleteUser));
  }

  @Test
  @DisplayName("requireAllowed throws AccessDeniedException with the action name")
  void requireAllowed_denies() {
    StaticActionAuthorizationService<String> service = service(permissionsFor("alice"));

    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> service.requireAllowed("alice", deleteUser));
    assertTrue(ex.getMessage().contains(deleteUser.name()));
  }

  @Test
  @DisplayName("denial path emits ACTION_DENIED audit event before throwing")
  void requireAllowed_emitsAuditEvent() {
    RecordingAudit audit = new RecordingAudit();
    StaticActionAuthorizationService<String> service =
        new StaticActionAuthorizationService<>(permissionsFor("alice"), audit);

    assertThrows(AccessDeniedException.class,
        () -> service.requireAllowed("alice", deleteUser));

    assertEquals(1, audit.events.size());
    ActionDenied event = (ActionDenied) audit.events.get(0);
    assertEquals(deleteUser.name(), event.action());
    assertTrue(event.subjectId().startsWith("String@"),
        "subject id must lead with the subject's class simple name");
  }

  @Test
  @DisplayName("JS-SEC-083: an explicit SubjectIdResolver supplies the audit subjectId")
  void requireAllowed_auditsResolverSubjectId() {
    RecordingAudit audit = new RecordingAudit();
    StaticActionAuthorizationService<String> service = new StaticActionAuthorizationService<>(
        permissionsFor("alice"), audit, s -> SubjectId.of("user-7"));

    assertThrows(AccessDeniedException.class, () -> service.requireAllowed("alice", deleteUser));

    ActionDenied event = (ActionDenied) audit.events.get(0);
    assertEquals("user-7", event.subjectId(), "ActionDenied.subjectId must equal resolver.resolve(user).value()");
  }

  @Test
  @DisplayName("JS-SEC-083: without an explicit resolver the registered SubjectIdResolver is used")
  void requireAllowed_auditsRegisteredResolverSubjectId() {
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("registered-" + s));
    try {
      RecordingAudit audit = new RecordingAudit();
      StaticActionAuthorizationService<String> service =
          new StaticActionAuthorizationService<>(permissionsFor("alice"), audit);

      assertThrows(AccessDeniedException.class, () -> service.requireAllowed("alice", deleteUser));

      assertEquals("registered-alice", ((ActionDenied) audit.events.get(0)).subjectId());
    } finally {
      JCustosServiceResolver.resetAll();
    }
  }

  @Test
  @DisplayName("audit-sink failure must not block the AccessDeniedException")
  void auditFailureIsSwallowed() {
    JCustosAuditService throwingAudit = new JCustosAuditService() {
      @Override public void publish(AuditEvent event) {
        throw new RuntimeException("audit boom");
      }

      @Override public List<AuditEvent> query(AuditQuery query) {
        return List.of();
      }
    };
    StaticActionAuthorizationService<String> service =
        new StaticActionAuthorizationService<>(permissionsFor("alice"), throwingAudit);

    assertThrows(AccessDeniedException.class,
        () -> service.requireAllowed("alice", deleteUser));
  }

  @Test
  @DisplayName("requireAllowed with null permission also denies")
  void requireAllowed_nullPermission() {
    StaticActionAuthorizationService<String> service = service(permissionsFor("alice"));
    assertThrows(AccessDeniedException.class,
        () -> service.requireAllowed("alice", null));
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private StaticActionAuthorizationService<String> service(AuthorizationService<String> authz) {
    return new StaticActionAuthorizationService<>(authz, new RecordingAudit());
  }

  private static AuthorizationService<String> permissionsFor(String subject, PermissionName... perms) {
    return new AuthorizationService<>() {
      @Override public HasRoles rolesFor(String s) {
        return List::of;
      }

      @Override public HasPermissions permissionsFor(String s) {
        if (s.equals(subject)) {
          return () -> Set.of(perms);
        }
        return Set::of;
      }
    };
  }

  static final class RecordingAudit implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }
}
