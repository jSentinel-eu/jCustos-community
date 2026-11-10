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
package eu.jsentinel.jcustos.components;

import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SecuredVisibility")
class SecuredVisibilityTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final RoleName EDITOR = new RoleName("EDITOR");
  private static final PermissionName DOC_DELETE = new PermissionName("document:delete");
  private static final PermissionName DOC_READ = new PermissionName("document:read");

  private static SecuredVisibility.JCustosView view(Set<RoleName> roles, Set<PermissionName> perms) {
    HasRoles r = () -> List.copyOf(roles);
    HasPermissions p = () -> List.copyOf(perms);
    return new SecuredVisibility.JCustosView(r, p);
  }

  @Test
  @DisplayName("empty requirement → always allowed regardless of subject")
  void emptyRequirementAlwaysAllowed() {
    SecuredVisibility.Requirement req = new SecuredVisibility.Requirement(Set.of(), Set.of());
    assertTrue(SecuredVisibility.isAllowed(req, null, null));
    assertTrue(req.isEmpty());
  }

  @Test
  @DisplayName("required role: missing → denied, present → allowed")
  void roleRequirement() {
    SecuredVisibility.Requirement req = SecuredVisibility.Requirement.role(ADMIN);

    assertFalse(SecuredVisibility.isAllowed(req,
        view(Set.of(EDITOR), Set.of()).roles(), null));
    assertTrue(SecuredVisibility.isAllowed(req,
        view(Set.of(ADMIN, EDITOR), Set.of()).roles(), null));
  }

  @Test
  @DisplayName("required permission: missing → denied, present → allowed")
  void permissionRequirement() {
    SecuredVisibility.Requirement req = SecuredVisibility.Requirement.permission(DOC_DELETE);
    SecuredVisibility.JCustosView v = view(Set.of(), Set.of(DOC_READ));
    assertFalse(SecuredVisibility.isAllowed(req, v.roles(), v.permissions()));

    SecuredVisibility.JCustosView v2 = view(Set.of(), Set.of(DOC_READ, DOC_DELETE));
    assertTrue(SecuredVisibility.isAllowed(req, v2.roles(), v2.permissions()));
  }

  @Test
  @DisplayName("AND semantics: missing one constraint denies even when the other matches")
  void andSemantics() {
    SecuredVisibility.Requirement req = new SecuredVisibility.Requirement(
        Set.of(ADMIN), Set.of(DOC_DELETE));
    SecuredVisibility.JCustosView roleOnly = view(Set.of(ADMIN), Set.of());
    SecuredVisibility.JCustosView permOnly = view(Set.of(), Set.of(DOC_DELETE));
    SecuredVisibility.JCustosView both = view(Set.of(ADMIN), Set.of(DOC_DELETE));

    assertFalse(SecuredVisibility.isAllowed(req, roleOnly.roles(), roleOnly.permissions()));
    assertFalse(SecuredVisibility.isAllowed(req, permOnly.roles(), permOnly.permissions()));
    assertTrue(SecuredVisibility.isAllowed(req, both.roles(), both.permissions()));
  }

  @Test
  @DisplayName("apply: HIDE on denial sets visible=false; enabled is actively set to true (kills the 'removed setEnabled' mutation)")
  void hideOnDenial() {
    RecordingTarget t = new RecordingTarget();
    // Pre-flip both flags away from the expected end state so that
    // each setter call has an observable effect — removing either
    // call leaves the wrong flag value and fails the assertion.
    t.visible = true;
    t.enabled = false;
    SecuredVisibility.apply(t,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> Optional.of(view(Set.of(EDITOR), Set.of())));
    assertFalse(t.visible, "HIDE on denial must call setVisible(false)");
    assertTrue(t.enabled, "HIDE on denial must call setEnabled(true)");
  }

  @Test
  @DisplayName("apply: DISABLE on denial sets enabled=false; visible is actively set to true (kills the 'removed setVisible' mutation)")
  void disableOnDenial() {
    RecordingTarget t = new RecordingTarget();
    t.visible = false;
    t.enabled = true;
    SecuredVisibility.apply(t,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.DISABLE,
        () -> Optional.of(view(Set.of(EDITOR), Set.of())));
    assertTrue(t.visible, "DISABLE on denial must call setVisible(true)");
    assertFalse(t.enabled, "DISABLE on denial must call setEnabled(false)");
  }

  @Test
  @DisplayName("apply: admitted subject restores visible+enabled even after a previous denial")
  void admittedRestoresBothFlags() {
    RecordingTarget t = new RecordingTarget();
    t.visible = false;
    t.enabled = false;
    SecuredVisibility.apply(t,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> Optional.of(view(Set.of(ADMIN), Set.of())));
    assertTrue(t.visible);
    assertTrue(t.enabled);
  }

  @Test
  @DisplayName("apply: missing security view → a non-empty requirement is denied")
  void missingViewDeniesNonEmpty() {
    RecordingTarget t = new RecordingTarget();
    SecuredVisibility.apply(t,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        Optional::empty);
    assertFalse(t.visible);
  }

  @Test
  @DisplayName("JS-SEC-135: missing security view → an empty requirement is denied too (HIDE)")
  void missingViewDeniesEmptyRequirement_hide() {
    RecordingTarget t = new RecordingTarget();
    SecuredVisibility.apply(t,
        new SecuredVisibility.Requirement(Set.of(), Set.of()),
        SecuredVisibilityMode.HIDE,
        Optional::empty);
    assertFalse(t.visible,
        "an empty requirement must not mean 'everyone, including anonymous visitors'");
  }

  @Test
  @DisplayName("JS-SEC-135: missing security view → an empty requirement is denied too (DISABLE)")
  void missingViewDeniesEmptyRequirement_disable() {
    RecordingTarget t = new RecordingTarget();
    SecuredVisibility.apply(t,
        SecuredVisibility.Requirement.none(),
        SecuredVisibilityMode.DISABLE,
        Optional::empty);
    assertTrue(t.visible);
    assertFalse(t.enabled,
        "an anonymous visitor must not get an enabled affordance from an empty requirement");
  }

  @Test
  @DisplayName("JS-SEC-135: an empty requirement admits an authenticated subject")
  void emptyRequirementAdmitsAuthenticatedSubject() {
    RecordingTarget t = new RecordingTarget();
    t.visible = false;
    t.enabled = false;
    SecuredVisibility.apply(t,
        SecuredVisibility.Requirement.none(),
        SecuredVisibilityMode.HIDE,
        () -> Optional.of(view(Set.of(), Set.of())));
    assertTrue(t.visible, "empty requirement = any authenticated subject");
    assertTrue(t.enabled);
  }

  @Test
  @DisplayName("JS-SEC-153: HIDE on denial calls setVisible(false) last")
  void hideOnDenial_setVisibleFalseComesLast() {
    java.util.List<String> calls = new java.util.ArrayList<>();
    SecuredVisibility.Target ordered = new SecuredVisibility.Target() {
      @Override public void setVisible(boolean v) { calls.add("visible=" + v); }
      @Override public boolean isVisible() { return false; }
      @Override public void setEnabled(boolean e) { calls.add("enabled=" + e); }
      @Override public boolean isEnabled() { return true; }
    };

    SecuredVisibility.apply(ordered,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> Optional.of(view(Set.of(EDITOR), Set.of())));

    assertEquals(List.of("enabled=true", "visible=false"), calls,
        "a target that backs 'enabled' with visibility must not be able to undo the hiding");
  }

  @Test
  @DisplayName("JS-SEC-153: HIDE on denial keeps a target hidden whose enabled-state is backed by visibility")
  void hideOnDenial_visibilityBackedTargetStaysHidden() {
    // The shape of the pre-fix ComponentTarget for a component without HasEnabled.
    boolean[] visible = {true};
    SecuredVisibility.Target visibilityBacked = new SecuredVisibility.Target() {
      @Override public void setVisible(boolean v) { visible[0] = v; }
      @Override public boolean isVisible() { return visible[0]; }
      @Override public void setEnabled(boolean e) { visible[0] = e; }
      @Override public boolean isEnabled() { return visible[0]; }
    };

    SecuredVisibility.apply(visibilityBacked,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        Optional::empty);

    assertFalse(visible[0]);
  }

  @Test
  @DisplayName("Requirement constructor records (null becomes empty set, sets are defensively copied)")
  void requirementInvariants() {
    SecuredVisibility.Requirement req = new SecuredVisibility.Requirement(null, null);
    assertTrue(req.requiredRoles().isEmpty());
    assertTrue(req.requiredPermissions().isEmpty());
    assertTrue(req.isEmpty());

    java.util.Set<RoleName> mutable = new java.util.HashSet<>();
    mutable.add(ADMIN);
    SecuredVisibility.Requirement copied = new SecuredVisibility.Requirement(mutable, null);
    mutable.add(EDITOR);
    assertEquals(Set.of(ADMIN), copied.requiredRoles(),
        "Requirement must defensively copy the roles set");
  }

  @Test
  @DisplayName("null arguments are rejected")
  void rejectNulls() {
    assertThrows(NullPointerException.class,
        () -> SecuredVisibility.isAllowed(null, null, null));
    assertThrows(NullPointerException.class,
        () -> SecuredVisibility.apply(null,
            SecuredVisibility.Requirement.role(ADMIN), SecuredVisibilityMode.HIDE));
    RecordingTarget t = new RecordingTarget();
    assertThrows(NullPointerException.class,
        () -> SecuredVisibility.apply(t, null, SecuredVisibilityMode.HIDE));
    assertThrows(NullPointerException.class,
        () -> SecuredVisibility.apply(t,
            SecuredVisibility.Requirement.role(ADMIN), null));
    assertThrows(NullPointerException.class,
        () -> SecuredVisibility.apply(t,
            SecuredVisibility.Requirement.role(ADMIN), SecuredVisibilityMode.HIDE, null));
  }

  static final class RecordingTarget implements SecuredVisibility.Target {
    boolean visible = true;
    boolean enabled = true;
    @Override public void setVisible(boolean v) { this.visible = v; }
    @Override public boolean isVisible() { return visible; }
    @Override public void setEnabled(boolean e) { this.enabled = e; }
    @Override public boolean isEnabled() { return enabled; }
  }
}
