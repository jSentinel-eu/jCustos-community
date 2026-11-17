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
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.HasEnabled;

import static java.util.Objects.requireNonNull;

/**
 * Adapts any Vaadin {@link Component} to the {@link SecuredVisibility.Target} contract - the
 * one adapter of {@link SecuredButton}, {@link SecuredRouterLink}, {@link SecuredMenuItem}
 * and the starter's {@code SecuredUi} builders (JS-SEC-097, CWE-1041). Until 00.84.00 each
 * of them carried its own copy.
 * <p>
 * Visibility goes through {@code Component.setVisible}; the enabled-state goes through
 * {@link HasEnabled#setEnabled(boolean)} where the component supports it. A component
 * without {@code HasEnabled} - a {@code Composite}, a custom {@code @Tag} component, an
 * {@code Icon} - cannot be disabled, so disabling hides it, and enabling does nothing:
 * "enabled" must never make a hidden component visible again (JS-SEC-153, CWE-636,
 * CWE-200).
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class ComponentTarget implements SecuredVisibility.Target {

  private final Component component;

  /**
   * @param component the component to toggle; non-null
   */
  public ComponentTarget(Component component) {
    this.component = requireNonNull(component, "component must not be null");
  }

  @Override
  public void setVisible(boolean visible) {
    component.setVisible(visible);
  }

  @Override
  public boolean isVisible() {
    return component.isVisible();
  }

  @Override
  public void setEnabled(boolean enabled) {
    if (component instanceof HasEnabled hasEnabled) {
      hasEnabled.setEnabled(enabled);
    } else if (!enabled) {
      // JS-SEC-153 (CWE-636, CWE-200): the only way to "disable" a component without
      // HasEnabled is to hide it. setEnabled(true) is deliberately a no-op: it used to call
      // setVisible(true) and thereby undid the setVisible(false) of the HIDE mode, so a
      // denied Composite / @Tag component / Icon stayed visible to every visitor.
      component.setVisible(false);
    }
  }

  @Override
  public boolean isEnabled() {
    if (component instanceof HasEnabled hasEnabled) {
      return hasEnabled.isEnabled();
    }
    return component.isVisible();
  }
}
