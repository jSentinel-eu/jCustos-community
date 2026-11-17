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
import com.vaadin.flow.component.menubar.MenuBar;
import com.vaadin.flow.component.contextmenu.MenuItem;

import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * Permission-aware binding helper for Vaadin {@link MenuItem}s.
 * <p>
 * Unlike {@link SecuredButton} and {@link SecuredRouterLink} this
 * is not a subclass: {@link MenuItem} is created by the parent
 * {@code MenuBar.addItem(...)} call and cannot be instantiated
 * directly. The helper instead takes a freshly-added {@code MenuItem}
 * and a {@link SecuredVisibility.Requirement}, performs the check
 * when it binds and on every attach of the item, and exposes a
 * {@link #refresh()} method for re-checks after a permission change.
 * Since 00.84.00 the item is also re-checked, with every other secured
 * binding of its UI, by
 * {@link SecuredVisibility#refreshAll(com.vaadin.flow.component.UI)}
 * (R8, JS-SEC-167).
 *
 * <p>Defaults to {@link SecuredVisibilityMode#HIDE} — menu entries
 * the user can't trigger should not appear in the menu.
 *
 * <p>Typical usage:
 * <pre>{@code
 *   MenuBar menu = new MenuBar();
 *   MenuItem delete = menu.addItem("Delete", e -> svc.delete());
 *   SecuredMenuItem secured = SecuredMenuItem.bind(delete,
 *       SecuredVisibility.Requirement.permission(new PermissionName("document:delete")));
 *   // later, after a role change: secured.refresh();
 * }</pre>
 *
 * <p>This is a UI affordance only — the actual delete handler must
 * still server-side-guard the operation.
 */
@ExperimentalJCustosApi
public final class SecuredMenuItem {

  private final MenuItem menuItem;
  private final SecuredVisibility.Requirement requirement;
  private final SecuredVisibilityMode mode;
  private final Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier;

  private SecuredMenuItem(MenuItem menuItem,
                          SecuredVisibility.Requirement requirement,
                          SecuredVisibilityMode mode,
                          Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier) {
    this.menuItem = requireNonNull(menuItem, "menuItem must not be null");
    this.requirement = requireNonNull(requirement, "requirement must not be null");
    this.mode = requireNonNull(mode, "mode must not be null");
    this.viewSupplier = requireNonNull(viewSupplier, "viewSupplier must not be null");
    refresh();
    // R8 (JS-SEC-167): the item is checked again on every attach, as the secured button and
    // link are, and from refreshAll(UI) when the subject's roles change. The binding lives on
    // the item, so the caller need not keep this instance.
    menuItem.addAttachListener(attach -> refresh());
    SecuredBindingRegistry.register(menuItem, this::refresh);
  }

  /**
   * Binds {@code menuItem} to {@code requirement} with
   * {@link SecuredVisibilityMode#HIDE} and SPI-backed view lookup.
   *
   * @param menuItem    non-null (typically just returned from
   *                    {@link MenuBar#addItem(String)})
   * @param requirement non-null
   * @return binding instance for later {@link #refresh()} calls
   */
  public static SecuredMenuItem bind(MenuItem menuItem,
                                     SecuredVisibility.Requirement requirement) {
    return new SecuredMenuItem(menuItem, requirement, SecuredVisibilityMode.HIDE,
        SecuredVisibility::currentJCustosView);
  }

  /**
   * Binds with a custom mode and SPI-backed view lookup.
   *
   * @param menuItem    non-null
   * @param requirement non-null
   * @param mode        non-null
   * @return binding instance
   */
  public static SecuredMenuItem bind(MenuItem menuItem,
                                     SecuredVisibility.Requirement requirement,
                                     SecuredVisibilityMode mode) {
    return new SecuredMenuItem(menuItem, requirement, mode,
        SecuredVisibility::currentJCustosView);
  }

  /**
   * Test-friendly binding: caller supplies the security view directly.
   *
   * @param menuItem     non-null
   * @param requirement  non-null
   * @param mode         non-null
   * @param viewSupplier non-null
   * @return binding instance
   */
  public static SecuredMenuItem bind(MenuItem menuItem,
                                     SecuredVisibility.Requirement requirement,
                                     SecuredVisibilityMode mode,
                                     Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier) {
    return new SecuredMenuItem(menuItem, requirement, mode, viewSupplier);
  }

  /** Re-runs the visibility check against the current subject. */
  public void refresh() {
    SecuredVisibility.apply(new ComponentTarget(menuItem), requirement, mode, viewSupplier);
  }

  /** @return the bound MenuItem */
  public MenuItem menuItem() {
    return menuItem;
  }

  /** @return the requirement */
  public SecuredVisibility.Requirement requirement() {
    return requirement;
  }

  /** @return the visibility mode */
  public SecuredVisibilityMode mode() {
    return mode;
  }
}
