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
package eu.jsentinel.jcustos.starter.ui;

import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.components.ComponentTarget;
import eu.jsentinel.jcustos.components.SecuredButton;
import eu.jsentinel.jcustos.components.SecuredMenuItem;
import eu.jsentinel.jcustos.components.SecuredRouterLink;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.components.SecuredVisibilityMode;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.ComponentEventListener;
import com.vaadin.flow.component.ClickEvent;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.contextmenu.MenuItem;
import com.vaadin.flow.component.menubar.MenuBar;
import com.vaadin.flow.router.RouterLink;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Declarative fluent builders over the V00.71 {@link SecuredButton},
 * {@link SecuredRouterLink} and {@link SecuredMenuItem} components.
 *
 * <p>Discipline:
 * <ul>
 *   <li>Exactly one of {@code requiresRole}, {@code requiresPermission}
 *       or {@code requiresPolicy} must be set before {@code build()}.</li>
 *   <li>{@code requiresRole} and {@code requiresPermission} need at least
 *       one name. An empty array - typically read from configuration -
 *       is rejected with {@link IllegalArgumentException} instead of
 *       meaning "everyone, including anonymous visitors" (JS-SEC-135).</li>
 *   <li>Exactly one of {@code hideWhenDenied()} or
 *       {@code disableWhenDenied()} may be set.</li>
 *   <li>Single-use: a second {@code build()} throws.</li>
 *   <li>{@code requiresPolicy(...)} evaluates the named policy through
 *       {@code PolicyRegistry} (V00.73). The component's visibility is
 *       set per the chosen {@code hideWhenDenied()} /
 *       {@code disableWhenDenied()} mode on every attach. See
 *       {@code PolicyVisibility} (package-private) for the differentiated
 *       log codes ({@code secured-ui/no-subject},
 *       {@code secured-ui/policy-denied},
 *       {@code secured-ui/unknown-policy},
 *       {@code secured-ui/step-up-required}).</li>
 * </ul>
 *
 * @since 00.72.00
 */
public final class SecuredUi {

  private SecuredUi() {
  }

  public static SecuredButtonBuilder button(String label) {
    return new SecuredButtonBuilder(label);
  }

  public static SecuredRouterLinkBuilder link() {
    return new SecuredRouterLinkBuilder();
  }

  public static SecuredMenuItemBuilder menuItem(MenuBar parent, String label) {
    return new SecuredMenuItemBuilder(parent, label);
  }

  /**
   * V00.74: generic builder that secures any Vaadin {@link Component}.
   * Use this for {@code FormLayout}, {@code Details}, {@code Tab},
   * {@code Dialog}, {@code Notification} or anything else with a
   * {@code setVisible} / {@code setEnabled} surface.
   *
   * <p>Returns the underlying component from {@code bind()} so the
   * builder fits cleanly into layout-construction chains:
   *
   * <pre>
   *   FormLayout form = new FormLayout();
   *   layout.add(SecuredUi.component(form).requiresRole("ADMIN").bind());
   * </pre>
   *
   * @param component non-null Vaadin component
   * @param <C>       concrete component type — preserved through bind()
   * @return secured-component builder
   * @since 00.74.00
   */
  public static <C extends Component> SecuredComponentBuilder<C> component(C component) {
    return new SecuredComponentBuilder<>(component);
  }


  /** Common configuration shared by the three builders. */
  abstract static class AbstractSecuredUiBuilder<B extends AbstractSecuredUiBuilder<B>> {
    Set<RoleName> roles;
    Set<PermissionName> permissions;
    String policyName;
    SecuredVisibilityMode mode;
    boolean used;

    @SuppressWarnings("unchecked")
    final B self() {
      return (B) this;
    }

    /**
     * Requires every listed role.
     *
     * @param roleNames at least one role name
     * @return this builder
     * @throws IllegalArgumentException if no role name is given (JS-SEC-135)
     */
    public B requiresRole(String... roleNames) {
      Objects.requireNonNull(roleNames, "roleNames");
      // JS-SEC-135 (CWE-636, CWE-863): an empty array used to yield an empty requirement,
      // which admitted every visitor - anonymous ones included.
      if (roleNames.length == 0) {
        throw new IllegalArgumentException(
            "requiresRole(...) needs at least one role; an empty requirement would not "
                + "restrict the component at all (JS-SEC-135)");
      }
      assertNoCheckYet();
      Set<RoleName> tmp = new LinkedHashSet<>();
      for (String r : roleNames) {
        tmp.add(new RoleName(Objects.requireNonNull(r, "role")));
      }
      this.roles = tmp;
      return self();
    }

    /**
     * Requires every listed permission.
     *
     * @param permissionNames at least one permission name
     * @return this builder
     * @throws IllegalArgumentException if no permission name is given (JS-SEC-135)
     */
    public B requiresPermission(String... permissionNames) {
      Objects.requireNonNull(permissionNames, "permissionNames");
      // JS-SEC-135 (CWE-636, CWE-863): see requiresRole.
      if (permissionNames.length == 0) {
        throw new IllegalArgumentException(
            "requiresPermission(...) needs at least one permission; an empty requirement "
                + "would not restrict the component at all (JS-SEC-135)");
      }
      assertNoCheckYet();
      Set<PermissionName> tmp = new LinkedHashSet<>();
      for (String p : permissionNames) {
        tmp.add(new PermissionName(Objects.requireNonNull(p, "permission")));
      }
      this.permissions = tmp;
      return self();
    }

    public B requiresPolicy(String policy) {
      Objects.requireNonNull(policy, "policy");
      assertNoCheckYet();
      this.policyName = policy;
      return self();
    }

    public B hideWhenDenied() {
      assertModeNotSet();
      this.mode = SecuredVisibilityMode.HIDE;
      return self();
    }

    public B disableWhenDenied() {
      assertModeNotSet();
      this.mode = SecuredVisibilityMode.DISABLE;
      return self();
    }

    final SecuredVisibility.Requirement requirement() {
      if (roles == null && permissions == null && policyName == null) {
        throw new IllegalStateException(
            "Exactly one of requiresRole / requiresPermission / requiresPolicy must be set");
      }
      // V00.73: policy path is handled by PolicyVisibility; only the
      // role/permission path uses SecuredVisibility.Requirement.
      SecuredVisibility.Requirement requirement = new SecuredVisibility.Requirement(roles, permissions);
      // JS-SEC-135 (CWE-636, CWE-863): the role/permission path never hands out an empty
      // requirement - the setters reject an empty array, this is the second line.
      if (!isPolicyMode() && requirement.isEmpty()) {
        throw new IllegalStateException(
            "requiresRole / requiresPermission must name at least one role or permission");
      }
      return requirement;
    }

    /** @return {@code true} when {@code requiresPolicy(...)} was set. */
    final boolean isPolicyMode() {
      return policyName != null;
    }

    final String policyName() {
      return policyName;
    }

    final SecuredVisibilityMode modeOrDefault(SecuredVisibilityMode defaultMode) {
      return mode == null ? defaultMode : mode;
    }

    final void markUsed() {
      if (used) {
        throw new IllegalStateException("build() may only be called once on the same builder");
      }
      used = true;
    }

    private void assertNoCheckYet() {
      if (roles != null || permissions != null || policyName != null) {
        throw new IllegalStateException(
            "Only one of requiresRole / requiresPermission / requiresPolicy may be set");
      }
    }

    private void assertModeNotSet() {
      if (mode != null) {
        throw new IllegalStateException(
            "Only one of hideWhenDenied() / disableWhenDenied() may be set");
      }
    }
  }

  // ---- Button -------------------------------------------------------------

  public static final class SecuredButtonBuilder
      extends AbstractSecuredUiBuilder<SecuredButtonBuilder> {
    private final String label;
    private ComponentEventListener<ClickEvent<Button>> clickListener;

    SecuredButtonBuilder(String label) {
      this.label = Objects.requireNonNull(label, "label");
    }

    public SecuredButtonBuilder onClick(ComponentEventListener<ClickEvent<Button>> listener) {
      this.clickListener = Objects.requireNonNull(listener, "listener");
      return this;
    }

    public Button build() {
      markUsed();
      if (isPolicyMode()) {
        Button b = new Button(label);
        if (clickListener != null) {
          b.addClickListener(clickListener);
        }
        PolicyVisibility.install(b, policyName(), modeOrDefault(SecuredVisibilityMode.DISABLE));
        return b;
      }
      SecuredButton b = new SecuredButton(label, requirement(), modeOrDefault(SecuredVisibilityMode.DISABLE));
      if (clickListener != null) {
        b.addClickListener(clickListener);
      }
      return b;
    }
  }

  // ---- RouterLink ---------------------------------------------------------

  public static final class SecuredRouterLinkBuilder
      extends AbstractSecuredUiBuilder<SecuredRouterLinkBuilder> {
    private String text;
    private Class<? extends Component> target;

    SecuredRouterLinkBuilder() {
    }

    public SecuredRouterLinkBuilder to(Class<? extends Component> route) {
      this.target = Objects.requireNonNull(route, "route");
      return this;
    }

    public SecuredRouterLinkBuilder text(String text) {
      this.text = Objects.requireNonNull(text, "text");
      return this;
    }

    public RouterLink build() {
      markUsed();
      if (target == null) {
        throw new IllegalStateException("SecuredUi.link() requires .to(<route>)");
      }
      String effectiveText = text == null ? target.getSimpleName() : text;
      if (isPolicyMode()) {
        RouterLink link = new RouterLink(effectiveText, target);
        PolicyVisibility.install(link, policyName(), modeOrDefault(SecuredVisibilityMode.HIDE));
        return link;
      }
      return new SecuredRouterLink(effectiveText, target, requirement(),
          modeOrDefault(SecuredVisibilityMode.HIDE));
    }
  }

  // ---- MenuItem -----------------------------------------------------------

  public static final class SecuredMenuItemBuilder
      extends AbstractSecuredUiBuilder<SecuredMenuItemBuilder> {
    private final MenuBar parent;
    private final String label;
    private ComponentEventListener<ClickEvent<MenuItem>> clickListener;

    SecuredMenuItemBuilder(MenuBar parent, String label) {
      this.parent = Objects.requireNonNull(parent, "parent");
      this.label = Objects.requireNonNull(label, "label");
    }

    public SecuredMenuItemBuilder onClick(ComponentEventListener<ClickEvent<MenuItem>> listener) {
      this.clickListener = Objects.requireNonNull(listener, "listener");
      return this;
    }

    public MenuItem build() {
      markUsed();
      MenuItem item = clickListener == null
          ? parent.addItem(label)
          : parent.addItem(label, clickListener);
      if (isPolicyMode()) {
        PolicyVisibility.install(item, policyName(), modeOrDefault(SecuredVisibilityMode.HIDE));
        return item;
      }
      SecuredMenuItem.bind(item, requirement(), modeOrDefault(SecuredVisibilityMode.HIDE));
      return item;
    }
  }

  // ---- Generic Component (V00.74) -----------------------------------------

  /**
   * Generic secured-component builder. Use for {@code FormLayout},
   * {@code Details}, {@code Tab}, {@code Dialog}, {@code Notification}
   * — any Vaadin {@link Component}. The component is returned from
   * {@link #bind()} so the builder fits into layout-construction
   * chains.
   *
   * <p>If the component implements {@link com.vaadin.flow.component.HasEnabled}
   * (most do), {@code disableWhenDenied()} flips
   * {@code setEnabled(false)}. Otherwise the disabled-mode falls back
   * to hide. A denied component without {@code HasEnabled} - a
   * {@code Composite}, a custom {@code @Tag} component, an {@code Icon} -
   * is hidden in both modes (JS-SEC-153).
   *
   * @param <C> concrete component type — preserved through {@code bind()}
   *
   * @since 00.74.00
   */
  public static final class SecuredComponentBuilder<C extends Component>
      extends AbstractSecuredUiBuilder<SecuredComponentBuilder<C>> {

    private final C component;

    SecuredComponentBuilder(C component) {
      this.component = Objects.requireNonNull(component, "component");
    }

    /**
     * Wires the visibility/enabled-state on this component and
     * returns the component back for chaining into layouts.
     */
    public C bind() {
      markUsed();
      if (isPolicyMode()) {
        PolicyVisibility.install(component, policyName(),
            modeOrDefault(SecuredVisibilityMode.HIDE));
        return component;
      }
      SecuredVisibility.Target target = new ComponentTarget(component);
      SecuredVisibility.apply(target, requirement(),
          modeOrDefault(SecuredVisibilityMode.HIDE));
      return component;
    }
  }
}
