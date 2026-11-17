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

import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.PermissionGuard;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import com.vaadin.flow.component.UI;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * Shared decision point for the Phase-8b secured Vaadin components
 * ({@code SecuredButton}, {@code SecuredRouterLink},
 * {@code SecuredMenuItem}).
 * <p>
 * The component declares a {@link Requirement} (zero or more
 * required roles + zero or more required permissions) and a
 * {@link SecuredVisibilityMode}. On every {@link #apply apply(...)}
 * call this helper:
 * <ol>
 *   <li>Resolves the current typed subject through {@link CurrentSubject}
 *       - the {@code SubjectStore} keyed on the registered
 *       {@code AuthenticationService.subjectType()}.</li>
 *   <li>Asks the registered {@code AuthorizationService} for the
 *       subject's roles + permissions (the AuthorizationService is
 *       the authoritative source — the SubjectStore alone may carry
 *       a typed user without the role view).</li>
 *   <li>Computes admission via {@link #isAllowed(Requirement, HasRoles, HasPermissions)}.</li>
 *   <li>Toggles {@code visible} / {@code enabled} on the supplied
 *       component target.</li>
 * </ol>
 *
 * <p>Admission semantics — a request is admitted when:
 * <ul>
 *   <li>All required permissions are present (AND across
 *       permissions), AND</li>
 *   <li>All required roles are present (AND across roles).</li>
 * </ul>
 * An empty {@link Requirement} admits every <em>authenticated</em>
 * subject and nobody else — apps that need
 * "any of these roles" semantics compose the affordance with a
 * narrower wrapper or use one of the dedicated
 * {@code @RequiresAnyPermission}-style annotations on a
 * higher-level guard.
 *
 * <p>If no subject is bound or the security SPIs are not wired,
 * the helper denies the affordance - whatever the requirement, an
 * empty one included (JS-SEC-135, CWE-636, CWE-863). UI components
 * must never grant by default when authentication is unknown. Until
 * 00.84.00 an empty requirement was shown to anonymous visitors; an
 * affordance that is meant for everyone needs no secured component.
 */
@ExperimentalJCustosApi
public final class SecuredVisibility {

  private SecuredVisibility() {
    // utility
  }

  /**
   * What a secured component requires to be enabled / visible.
   *
   * @param requiredRoles       roles that must all be present;
   *                            empty means "no role constraint"
   * @param requiredPermissions permissions that must all be present;
   *                            empty means "no permission constraint"
   */
  public record Requirement(
      Set<RoleName> requiredRoles,
      Set<PermissionName> requiredPermissions
  ) {
    /** Validates the components — null becomes empty, sets are defensively copied. */
    public Requirement {
      requiredRoles = requiredRoles == null ? Set.of() : Set.copyOf(requiredRoles);
      requiredPermissions = requiredPermissions == null ? Set.of() : Set.copyOf(requiredPermissions);
    }

    /** Single-role convenience. */
    public static Requirement role(RoleName role) {
      requireNonNull(role, "role must not be null");
      return new Requirement(Set.of(role), Set.of());
    }

    /** Single-permission convenience. */
    public static Requirement permission(PermissionName permission) {
      requireNonNull(permission, "permission must not be null");
      return new Requirement(Set.of(), Set.of(permission));
    }

    /**
     * The empty requirement: no role and no permission constraint.
     * {@link SecuredVisibility#apply apply(...)} admits any authenticated
     * subject for it and denies a visitor without a subject (JS-SEC-135).
     *
     * @return a requirement that {@link #isEmpty()} reports as empty
     * @since 00.84.00
     */
    public static Requirement none() {
      return new Requirement(Set.of(), Set.of());
    }

    /** @return true when the requirement carries no constraints */
    public boolean isEmpty() {
      return requiredRoles.isEmpty() && requiredPermissions.isEmpty();
    }
  }

  /** Target a SecuredVisibility helper toggles. */
  public interface Target {
    /** Set component visibility (Vaadin {@code Component.setVisible}). */
    void setVisible(boolean visible);

    /** Read component visibility. */
    boolean isVisible();

    /** Set component enabled-state (Vaadin {@code Component.setEnabled}). */
    void setEnabled(boolean enabled);

    /** Read component enabled-state. */
    boolean isEnabled();
  }

  /**
   * Computes admission from the requirement against the supplied
   * role and permission views. Both arguments may be {@code null}
   * (treated as empty).
   * <p>
   * This is the comparison for a subject the caller has already
   * resolved: an empty requirement compares as admitted. Whether a
   * subject is bound at all is decided by {@link #apply apply(...)},
   * which denies every requirement without one (JS-SEC-135).
   *
   * @param requirement non-null
   * @param roles       caller's role view; may be {@code null}
   * @param permissions caller's permission view; may be {@code null}
   * @return {@code true} when every required role and permission is present
   */
  public static boolean isAllowed(Requirement requirement,
                                  HasRoles roles,
                                  HasPermissions permissions) {
    requireNonNull(requirement, "requirement must not be null");
    if (requirement.isEmpty()) {
      return true;
    }
    Set<RoleName> have = roles == null ? Set.of() : new HashSet<>(roles.roleNames());
    if (!have.containsAll(requirement.requiredRoles())) {
      return false;
    }
    for (PermissionName needed : requirement.requiredPermissions()) {
      if (!PermissionGuard.hasPermission(permissions, needed)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Resolves the current subject and applies the requirement to
   * {@code target} according to {@code mode}. Without a resolvable
   * subject the requirement is denied, an empty one included.
   *
   * @param target      Vaadin component to toggle; non-null
   * @param requirement what the component requires; non-null
   * @param mode        hide-vs-disable on denial; non-null
   */
  public static void apply(Target target, Requirement requirement, SecuredVisibilityMode mode) {
    requireNonNull(target, "target must not be null");
    requireNonNull(requirement, "requirement must not be null");
    requireNonNull(mode, "mode must not be null");
    apply(target, requirement, mode, () -> currentJCustosView());
  }

  /**
   * Test-friendly variant: the caller supplies the security view
   * directly rather than going through the SPI lookup.
   *
   * @param target       non-null
   * @param requirement  non-null
   * @param mode         non-null
   * @param viewSupplier supplies the current (roles, permissions)
   *                     tuple; non-null
   */
  public static void apply(Target target,
                           Requirement requirement,
                           SecuredVisibilityMode mode,
                           Supplier<Optional<JCustosView>> viewSupplier) {
    requireNonNull(target, "target must not be null");
    requireNonNull(requirement, "requirement must not be null");
    requireNonNull(mode, "mode must not be null");
    requireNonNull(viewSupplier, "viewSupplier must not be null");
    Optional<JCustosView> view = viewSupplier.get();
    // JS-SEC-135 (CWE-636, CWE-863): without a security view - no subject bound, or the
    // SPIs not wired - every requirement is denied. `.orElse(requirement.isEmpty())` used
    // to show an affordance with an empty requirement (e.g. an empty role array read from
    // configuration) to anonymous visitors.
    boolean allowed = view.map(v -> isAllowed(requirement, v.roles(), v.permissions()))
        .orElse(false);
    if (allowed) {
      target.setVisible(true);
      target.setEnabled(true);
      return;
    }
    switch (mode) {
      case HIDE -> {
        // JS-SEC-153 (CWE-636, CWE-200): setVisible(false) comes last. A target whose
        // enabled-state is backed by visibility must not be able to undo the hiding.
        target.setEnabled(true);
        target.setVisible(false);
      }
      case DISABLE -> {
        target.setVisible(true);
        target.setEnabled(false);
      }
      default -> throw new IllegalStateException("unreachable: " + mode);
    }
  }

  /**
   * Evaluates every secured binding of {@code ui} again against the current subject (R8,
   * JS-SEC-167, CWE-613): the {@link SecuredButton}s, {@link SecuredRouterLink}s and
   * {@link SecuredMenuItem}s of the UI and the components the starter's {@code SecuredUi}
   * builders bound. Until 00.84.00 an open view kept the controls of the subject's old roles
   * until the next navigation, unless the application called {@code refresh()} on each of them.
   * <p>
   * Call it after a change of the subject's roles or permissions that does not end the session
   * - a role granted, an impersonation started - with the session lock of {@code ui} held, for
   * example inside {@code ui.access(...)} from the code that made the change. A change of the
   * security version ends the session instead, through the per-request check and, with an
   * {@code ObservableJCustosVersionStore}, through {@code VaadinJCustosVersionChangeBridge} at
   * once. Components that were garbage-collected are dropped; see
   * {@link SecuredBindingRegistry}.
   * <p>
   * The bindings decide on the subject of {@code ui}'s session: the method binds {@code ui} as
   * current while it runs, so an administrator's request that refreshes another user's UI
   * does not evaluate that UI's controls against the administrator's roles (exit review RF19).
   * Several bindings on one component combine with AND (RF18).
   *
   * @param ui the UI whose bindings are refreshed; non-null
   * @return the number of components that were refreshed
   * @throws IllegalStateException when the calling thread does not hold the session lock of
   *                               {@code ui}
   * @since 00.84.00
   */
  public static int refreshAll(UI ui) {
    return SecuredBindingRegistry.refreshAll(ui);
  }

  /**
   * The slice of the current subject the components consult.
   *
   * @param roles       caller's role view; non-null
   * @param permissions caller's permission view; non-null
   */
  public record JCustosView(HasRoles roles, HasPermissions permissions) {
    /** Validates the components. */
    public JCustosView {
      requireNonNull(roles, "roles must not be null");
      requireNonNull(permissions, "permissions must not be null");
    }
  }

  /**
   * SPI lookup through {@link CurrentSubject#currentRolesAndPermissions()}: typed user via the
   * {@code SubjectStore}, roles and permissions via the registered
   * {@code AuthorizationService}. Returns empty when any prerequisite is missing (no SPI
   * wiring, no current subject, ...) or a lookup fails - the caller treats absence as
   * denial.
   * <p>
   * JS-SEC-097 (CWE-1041): the components decide on the subject of the shared facade - the
   * one the navigation listener and the policy-backed {@code SecuredUi} components see. The
   * roles and permissions are resolved before the view is returned; a failure there denies
   * instead of escaping from {@link #apply apply(...)}. Exit review RF17 (CWE-400): the view
   * carries no subject id, since no requirement reads one, so a page with many secured
   * components does not resolve the id once per component.
   *
   * @return current security view, if resolvable
   */
  public static Optional<JCustosView> currentJCustosView() {
    return CurrentSubject.currentRolesAndPermissions()
        .map(granted -> new JCustosView(granted, granted));
  }
}
