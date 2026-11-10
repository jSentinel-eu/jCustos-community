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
package eu.jsentinel.jcustos.starter.ui;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.HasEnabled;
import com.vaadin.flow.component.Tag;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * JS-SEC-153 (CWE-636, CWE-200): {@code SecuredUi.component(...)} left every component
 * without {@link HasEnabled} visible on denial. The HIDE branch called
 * {@code setVisible(false)} and then {@code setEnabled(true)}, and for such a component
 * "enabled" was mapped to {@code setVisible(true)} - a denied {@code Composite}, custom
 * {@code @Tag} component or {@code Icon} was sent to every visitor.
 * <p>
 * The tests run against the real SPI lookup: a registered authentication and authorisation
 * service and a subject store, no supplied security view.
 */
@DisplayName("JS-SEC-153 - SecuredUi.component hides a denied component without HasEnabled")
class SecuredUiComponentVisibilityTest {

  private InMemorySubjectStore subjects;

  @BeforeEach
  void wireSecurity() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    subjects = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjects);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(String.class));
    FakeAuthorizationService<String> authorization = new FakeAuthorizationService<>();
    authorization.putRoles("admin", Set.of(new RoleName("ADMIN")));
    authorization.putRoles("user", Set.of(new RoleName("USER")));
    JCustosServiceResolver.setAuthorizationService(authorization);
  }

  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  static Stream<Arguments> componentsWithoutHasEnabled() {
    return Stream.of(
        arguments("Composite", (Supplier<Component>) AdminPanel::new),
        arguments("custom @Tag component", (Supplier<Component>) CustomTagComponent::new),
        arguments("Icon", (Supplier<Component>) VaadinIcon.LOCK::create));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("precondition: the component has no HasEnabled")
  void precondition_noHasEnabled(String name, Supplier<Component> factory) {
    assertFalse(factory.get() instanceof HasEnabled,
        name + " must not implement HasEnabled, or this test pins nothing");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("anonymous visitor, default mode (HIDE): not visible")
  void anonymous_defaultMode_hidden(String name, Supplier<Component> factory) {
    Component bound = SecuredUi.component(factory.get()).requiresRole("ADMIN").bind();

    assertFalse(bound.isVisible(), name + " must be hidden from an anonymous visitor");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("anonymous visitor, hideWhenDenied(): not visible")
  void anonymous_hideWhenDenied_hidden(String name, Supplier<Component> factory) {
    Component bound = SecuredUi.component(factory.get())
        .requiresRole("ADMIN").hideWhenDenied().bind();

    assertFalse(bound.isVisible(), name + " must be hidden from an anonymous visitor");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("anonymous visitor, disableWhenDenied(): hidden, because the component cannot be disabled")
  void anonymous_disableWhenDenied_hidden(String name, Supplier<Component> factory) {
    Component bound = SecuredUi.component(factory.get())
        .requiresRole("ADMIN").disableWhenDenied().bind();

    assertFalse(bound.isVisible(), name + " cannot be disabled, so denial must hide it");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("authenticated subject without the role: not visible")
  void wrongRole_hidden(String name, Supplier<Component> factory) {
    subjects.setCurrentSubject("user", String.class);

    Component bound = SecuredUi.component(factory.get()).requiresRole("ADMIN").bind();

    assertFalse(bound.isVisible(), name + " must be hidden from a subject without the role");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("authorised subject: visible")
  void authorised_visible(String name, Supplier<Component> factory) {
    subjects.setCurrentSubject("admin", String.class);

    Component bound = SecuredUi.component(factory.get()).requiresRole("ADMIN").bind();

    assertTrue(bound.isVisible(), name + " must be shown to a subject with the role");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("componentsWithoutHasEnabled")
  @DisplayName("authorised subject, disableWhenDenied(): visible")
  void authorised_disableMode_visible(String name, Supplier<Component> factory) {
    subjects.setCurrentSubject("admin", String.class);

    Component bound = SecuredUi.component(factory.get())
        .requiresRole("ADMIN").disableWhenDenied().bind();

    assertTrue(bound.isVisible());
  }

  @Test
  @DisplayName("control: a component with HasEnabled is hidden in HIDE mode and disabled in DISABLE mode")
  void hasEnabledComponent_behavesAsBefore() {
    Div hidden = SecuredUi.component(new Div()).requiresRole("ADMIN").bind();
    assertFalse(hidden.isVisible());

    Div disabled = SecuredUi.component(new Div()).requiresRole("ADMIN").disableWhenDenied().bind();
    assertTrue(disabled.isVisible(), "DISABLE keeps a HasEnabled component visible");
    assertFalse(disabled.isEnabled());

    subjects.setCurrentSubject("admin", String.class);
    Div granted = SecuredUi.component(new Div()).requiresRole("ADMIN").disableWhenDenied().bind();
    assertTrue(granted.isVisible());
    assertTrue(granted.isEnabled());
  }

  // ── Fixtures ───────────────────────────────────────────────────

  /** A typical admin panel: a Composite has no HasEnabled of its own. */
  static final class AdminPanel extends Composite<Div> {
    AdminPanel() {
      getContent().add(new Span("SECRET-PANEL-CONTENT"));
    }
  }

  @Tag("custom-admin-widget")
  static final class CustomTagComponent extends Component {
  }
}
