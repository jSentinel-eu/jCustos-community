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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.PermissionGuard;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;

import java.util.HashSet;
import java.util.List;
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
 *   <li>Resolves the current typed subject via
 *       {@link SubjectStores#subjectStore()} and the registered
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
 * An empty {@link Requirement} is always admitted — apps that need
 * "any of these roles" semantics compose the affordance with a
 * narrower wrapper or use one of the dedicated
 * {@code @RequiresAnyPermission}-style annotations on a
 * higher-level guard.
 *
 * <p>If no subject is bound or the security SPIs are not wired,
 * the helper denies the affordance. UI components must never grant
 * by default when authentication is unknown.
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
   * {@code target} according to {@code mode}.
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
    boolean allowed = view.map(v -> isAllowed(requirement, v.roles(), v.permissions()))
        .orElse(requirement.isEmpty());
    if (allowed) {
      target.setVisible(true);
      target.setEnabled(true);
      return;
    }
    switch (mode) {
      case HIDE -> {
        target.setVisible(false);
        target.setEnabled(true);
      }
      case DISABLE -> {
        target.setVisible(true);
        target.setEnabled(false);
      }
      default -> throw new IllegalStateException("unreachable: " + mode);
    }
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
   * SPI lookup: typed user via SubjectStore → roles + permissions
   * via the registered {@code AuthorizationService}. Returns empty
   * when any prerequisite is missing (no SPI wiring, no current
   * subject, …) — the caller treats absence as denial.
   *
   * @return current security view, if resolvable
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  public static Optional<JCustosView> currentJCustosView() {
    try {
      Class subjectType = JCustosServiceResolver
          .<Object, Object>findAuthenticationService()
          .map(s -> (Class) s.subjectType())
          .orElse(null);
      if (subjectType == null) {
        return Optional.empty();
      }
      Optional<Object> subjectOpt = SubjectStores.findSubjectStore()
          .flatMap(store -> store.currentSubject(subjectType));
      if (subjectOpt.isEmpty()) {
        return Optional.empty();
      }
      Object subject = subjectOpt.get();
      Optional<AuthorizationService<Object>> authzOpt =
          JCustosServiceResolver.findAuthorizationService();
      if (authzOpt.isEmpty()) {
        return Optional.empty();
      }
      AuthorizationService<Object> authz = authzOpt.get();
      HasRoles roles = () -> List.copyOf(authz.rolesFor(subject).roleNames());
      HasPermissions permissions = () -> List.copyOf(authz.permissionsFor(subject).permissionNames());
      return Optional.of(new JCustosView(roles, permissions));
    } catch (RuntimeException ignored) {
      return Optional.empty();
    }
  }
}
