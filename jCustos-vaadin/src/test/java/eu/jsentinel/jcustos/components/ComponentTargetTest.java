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

import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.HasEnabled;
import com.vaadin.flow.component.Tag;
import com.vaadin.flow.component.button.Button;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041): {@link ComponentTarget} is the one adapter of the secured components
 * and the starter's {@code SecuredUi}; it carries the JS-SEC-153 semantics (CWE-636, CWE-200)
 * that only {@code SecuredUi}'s private copy had.
 */
@DisplayName("JS-SEC-097 - ComponentTarget: one target adapter with the JS-SEC-153 semantics")
class ComponentTargetTest {

  @Tag("er30-widget")
  static final class Widget extends Component {
  }

  @Test
  @DisplayName("precondition: Button has HasEnabled, the custom @Tag component has not")
  void preconditions() {
    Component button = new Button();
    Component widget = new Widget();
    assertTrue(button instanceof HasEnabled);
    assertFalse(widget instanceof HasEnabled);
  }

  @Test
  @DisplayName("a HasEnabled component is enabled and disabled through HasEnabled; visibility is untouched")
  void hasEnabled_delegates() {
    Button button = new Button("Delete");
    ComponentTarget target = new ComponentTarget(button);

    target.setEnabled(false);
    assertFalse(button.isEnabled());
    assertFalse(target.isEnabled());
    assertTrue(button.isVisible());

    target.setEnabled(true);
    assertTrue(button.isEnabled());
    target.setVisible(false);
    assertFalse(target.isVisible());
  }

  @Test
  @DisplayName("JS-SEC-153: a component without HasEnabled is hidden when disabled, and enabling never shows it again")
  void withoutHasEnabled_disablingHides_enablingDoesNotShow() {
    Widget widget = new Widget();
    ComponentTarget target = new ComponentTarget(widget);

    target.setEnabled(false);
    assertFalse(widget.isVisible(), "the only way to disable it is to hide it");
    assertFalse(target.isEnabled());

    target.setEnabled(true);
    assertFalse(widget.isVisible(), "setEnabled(true) must not undo the hiding");
  }

  @Test
  @DisplayName("JS-SEC-153: HIDE on denial keeps a component without HasEnabled hidden")
  void hideMode_withoutHasEnabled_staysHidden() {
    Widget widget = new Widget();

    SecuredVisibility.apply(new ComponentTarget(widget),
        SecuredVisibility.Requirement.role(new RoleName("ADMIN")), SecuredVisibilityMode.HIDE,
        Optional::empty);

    assertFalse(widget.isVisible());
  }

  @Test
  @DisplayName("a null component is rejected")
  void nullRejected() {
    assertThrows(NullPointerException.class, () -> new ComponentTarget(null));
  }
}
