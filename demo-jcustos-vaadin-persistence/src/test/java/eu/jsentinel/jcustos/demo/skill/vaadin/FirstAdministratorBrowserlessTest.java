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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.InMemoryUserDirectoryPersistence;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.PersistentUserDirectory;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.StoredUser;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.SetupView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.HasLabel;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationTester;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-134 (CWE-684): the first administrator created through the real
 * {@link SetupView} logs in through the real {@link MyLoginView}. The setup and the user
 * directory hash and verify with the same, configured service; before, the setup wrote a
 * {@code $pwh$} envelope the directory's legacy PBKDF2 hasher could not read, and the
 * administrator could never log in.
 */
@DisplayName("JS-SEC-134 — the first administrator created by the setup can log in")
class FirstAdministratorBrowserlessTest extends BrowserlessTest {

  private static final String STRONG = "Glacier-Lantern-Orbit-42";

  private InMemoryUserDirectoryPersistence persistence;

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() {
    SkillDemoTestSupport.runDemoBootstrap();
    persistence = new InMemoryUserDirectoryPersistence();
    UserDirectoryProvider.setDirectory(
        new PersistentUserDirectory(persistence, ConfiguredHashingService.INSTANCE));
    TestDirectories.writeKnownToken();
    TestDirectories.resetBootstrapWiring();
  }

  @AfterEach
  void tearDown() {
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    TestDirectories.resetBootstrapWiring();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the administrator the setup view creates logs in through the login view")
  void firstAdministratorLogsIn() {
    submitSetup(STRONG);

    assertNotification("Administrator 'admin' created");
    assertTrue(storedHash("admin").startsWith("$pwh$"),
        "the setup hashes with the configured credential pipeline");

    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(STRONG);
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    Optional<User> subject = SubjectStores.subjectStore().currentSubject(User.class);
    assertTrue(subject.isPresent(), "the administrator the setup created must be able to log in");
    assertTrue(subject.get().roles().contains(AuthorizationRole.ADMIN));
  }

  @Test
  @DisplayName("a first-administrator password below the minimum length is refused")
  void shortPasswordIsRefused() {
    submitSetup("Ab1-x");

    assertFalse(BootstrapWiring.instance().stateService().hasAdministrator());
  }

  // ── helpers ────────────────────────────────────────────────────

  private void submitSetup(String password) {
    navigate(SetupView.class);
    field(PasswordField.class, "Bootstrap token").setValue(TestDirectories.KNOWN_TOKEN);
    field(PasswordField.class, "New password").setValue(password);
    field(PasswordField.class, "Repeat password").setValue(password);
    test($view(Button.class).all().stream()
        .filter(b -> "Create administrator".equals(b.getText()))
        .findFirst().orElseThrow()).click();
  }

  private <F extends com.vaadin.flow.component.Component & HasLabel> F field(Class<F> type, String label) {
    return $view(type).all().stream()
        .filter(f -> label.equals(f.getLabel()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no field labelled '" + label + "'"));
  }

  private String storedHash(String username) {
    StoredUser stored = persistence.load().get(username);
    if (stored == null) {
      throw new AssertionError("no stored user '" + username + "'");
    }
    return stored.passwordHash();
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private void assertNotification(String expected) {
    List<String> texts = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .toList();
    assertTrue(texts.stream().anyMatch(t -> t.contains(expected)),
        "expected a notification containing '" + expected + "'; got " + texts);
  }
}
