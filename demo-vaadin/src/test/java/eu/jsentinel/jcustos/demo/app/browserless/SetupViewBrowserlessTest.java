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
package eu.jsentinel.jcustos.demo.app.browserless;

import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.Credentials;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectory;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.InMemoryDemoUserDirectory;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.demo.app.views.SetupView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationTester;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless tests for {@link SetupView}. The view's logic is a small
 * state machine over {@code InitialAdminCreationResult} plus the
 * BeforeEnter gate that redirects back to login once the system is
 * initialized. Every error branch produces a Notification with a
 * specific message — those messages are the test surface.
 * <p>
 * To make the success path deterministic, the test pre-writes a known
 * bootstrap token in {@code PERSISTENT_FILE} mode and forces
 * {@link BootstrapWiring} to rebuild against that file. After every test
 * the singleton is reset and the token file deleted.
 */
@DisplayName("SetupView — initial-admin creation form")
class SetupViewBrowserlessTest extends BrowserlessTest {

  // Must be in the generator's format (JS-SEC-130): five groups of four from
  // the alphabet without O, I, 0 and 1 - a token file with any other value is
  // not adopted by the store.
  private static final String KNOWN_TOKEN = "TEST-TKNS-2222-3333-AAAA";

  private Path tokenFile;

  @BeforeEach
  void setUp() throws Exception {
    tokenFile = Files.createTempFile("test-bootstrap-token", ".txt");
    Files.writeString(tokenFile,
        "token=" + KNOWN_TOKEN + System.lineSeparator()
            + "createdAt=" + Instant.now() + System.lineSeparator());

    System.setProperty("security.bootstrap.mode", "PERSISTENT_FILE");
    System.setProperty("security.bootstrap.token.file", tokenFile.toString());
    resetBootstrapWiringSingleton();

    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @AfterEach
  void tearDown() throws Exception {
    Files.deleteIfExists(tokenFile);
    System.clearProperty("security.bootstrap.token.file");
    System.clearProperty("security.bootstrap.mode");
    resetBootstrapWiringSingleton();
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  // ── Render ─────────────────────────────────────────────────────

  @Test
  @DisplayName("Form renders every field full-width with usernameField defaulting to 'admin'; submit is LUMO_PRIMARY")
  void formIsRendered() {
    navigate(SetupView.class);

    TextField username = byLabel(TextField.class, "Admin username");
    assertEquals("admin", username.getValue(),
        "usernameField must default to 'admin'");

    for (TextField f : List.of(username,
        byLabel(TextField.class, "Display name (optional)"),
        byLabel(TextField.class, "Email (optional)"))) {
      assertEquals("100%", f.getWidth(),
          "TextField '" + f.getLabel() + "' must be widthFull()");
    }
    for (PasswordField f : List.of(
        byLabel(PasswordField.class, "Bootstrap token"),
        byLabel(PasswordField.class, "New password"),
        byLabel(PasswordField.class, "Repeat password"))) {
      assertEquals("100%", f.getWidth(),
          "PasswordField '" + f.getLabel() + "' must be widthFull()");
    }

    VerticalLayout form = $view(VerticalLayout.class).first();
    assertEquals("520px", form.getMaxWidth(),
        "form must be capped at 520px");
    assertTrue(form.getClassNames().contains("setup-view"),
        "form must carry the 'setup-view' style hook; got: " + form.getClassNames());

    Button submit = findButton("Create administrator");
    assertTrue(submit.getThemeNames().contains("primary"),
        "submit must carry LUMO_PRIMARY; got: " + submit.getThemeNames());
  }

  // ── beforeEnter redirect ───────────────────────────────────────

  @Test
  @DisplayName("beforeEnter forwards to MyLoginView once an administrator exists")
  void beforeEnterForwardsWhenInitialized() {
    // BootstrapWiring's build() calls directory.enableBootstrapMode()
    // which would wipe any admin we seed *before* build. Trigger the
    // build first (no admins → no-op), then seed.
    BootstrapWiring.instance();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));

    // BrowserlessTest's navigate(...) validates the resolved class and
    // throws when the BeforeEnter forward redirects us to a different
    // route. That exception is the observable signal that the gate
    // fired.
    IllegalArgumentException failure = org.junit.jupiter.api.Assertions
        .assertThrows(IllegalArgumentException.class,
            () -> navigate(SetupView.class),
            "/setup must forward to /login once an administrator exists");
    assertTrue(failure.getMessage().contains(MyLoginView.class.getName()),
        "exception must mention the forward target MyLoginView; got: " + failure.getMessage());
  }

  // ── Validation branches ────────────────────────────────────────

  @Test
  @DisplayName("Submit with empty token/password warns about required fields")
  void requiredFieldsWarn() {
    navigate(SetupView.class);
    // username defaults to "admin", token + password are blank
    submit();

    assertNotification("Token, username and password are required.");
  }

  @Test
  @DisplayName("Submit with mismatching confirmation warns about non-matching passwords")
  void passwordMismatchWarns() {
    navigate(SetupView.class);
    setValue(PasswordField.class, "Bootstrap token", KNOWN_TOKEN);
    setValue(PasswordField.class, "New password", "p4ssw0rd!");
    setValue(PasswordField.class, "Repeat password", "different");
    submit();

    assertNotification("Passwords do not match.");
  }

  // ── BootstrapService result branches ───────────────────────────

  @Test
  @DisplayName("Wrong bootstrap token → 'Bootstrap token rejected.'")
  void invalidTokenRejected() {
    navigate(SetupView.class);
    setValue(PasswordField.class, "Bootstrap token", "WRONG-TOKN-9999-0000-ZZZZ");
    setValue(PasswordField.class, "New password", "p4ssw0rd!");
    setValue(PasswordField.class, "Repeat password", "p4ssw0rd!");
    submit();

    assertNotification("Bootstrap token rejected.");
  }

  @Test
  @DisplayName("Password shorter than the policy minimum → policy-rejection notification with the policy's reason")
  void passwordPolicyViolation() {
    navigate(SetupView.class);
    setValue(PasswordField.class, "Bootstrap token", KNOWN_TOKEN);
    setValue(PasswordField.class, "New password", "short");
    setValue(PasswordField.class, "Repeat password", "short");
    submit();

    // MinimumLengthPasswordPolicy(8) reports something like
    // "Password must be at least 8 characters."
    boolean ok = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .anyMatch(t -> t.toLowerCase().contains("password")
            || t.contains("at least"));
    assertTrue(ok,
        "password-policy rejection must surface a password-related notification; got: "
            + notificationTexts());
  }

  @Test
  @DisplayName("Invalid username characters → 'username must be 1-64 chars of [A-Za-z0-9._-]'")
  void invalidUsernameRejected() {
    navigate(SetupView.class);
    setValue(TextField.class, "Admin username", "not allowed!!");
    setValue(PasswordField.class, "Bootstrap token", KNOWN_TOKEN);
    setValue(PasswordField.class, "New password", "p4ssw0rd!");
    setValue(PasswordField.class, "Repeat password", "p4ssw0rd!");
    submit();

    assertNotification("username must be 1-64 chars");
  }

  @Test
  @DisplayName("Valid token + valid password creates the admin and surfaces the success notification")
  void createdSuccessPath() {
    SetupView view = navigate(SetupView.class);

    // Capture the SetupView's internal PasswordField references via the
    // private fields — after the submit handler runs, we want to verify
    // they were cleared even though the view is no longer the current
    // navigation target.
    PasswordField tokenField = privateField(view, "tokenField");
    PasswordField passwordField = privateField(view, "passwordField");
    PasswordField confirmField = privateField(view, "confirmField");

    setValue(PasswordField.class, "Bootstrap token", KNOWN_TOKEN);
    setValue(PasswordField.class, "New password", "p4ssw0rd!");
    setValue(PasswordField.class, "Repeat password", "p4ssw0rd!");
    setValue(TextField.class, "Display name (optional)", "Initial Admin");
    setValue(TextField.class, "Email (optional)", "admin@example.com");
    submit();

    assertNotification("Administrator 'admin' created. You can now log in.");

    assertEquals("", tokenField.getValue(),
        "token must be cleared from the form on success");
    assertEquals("", passwordField.getValue(),
        "password must be cleared from the form on success");
    assertEquals("", confirmField.getValue(),
        "confirm must be cleared from the form on success");

    assertTrue(BootstrapWiring.instance().stateService().hasAdministrator(),
        "after Created the AdministratorAccountStore must report an admin");
  }

  @Test
  @DisplayName("JS-SEC-134: the administrator the setup creates logs in through the login view")
  void setupAdministratorLogsIn() {
    navigate(SetupView.class);
    setValue(PasswordField.class, "Bootstrap token", KNOWN_TOKEN);
    setValue(PasswordField.class, "New password", "Adm1n-setup-pass");
    setValue(PasswordField.class, "Repeat password", "Adm1n-setup-pass");
    submit();
    assertNotification("Administrator 'admin' created. You can now log in.");

    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("Adm1n-setup-pass");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    MyUser admin = SubjectStores.subjectStore().currentSubject(MyUser.class)
        .orElseThrow(() -> new AssertionError(
            "the administrator created by the setup must be able to log in"));
    assertTrue(admin.roles().contains(AuthorizationRole.ADMIN), "roles: " + admin.roles());
  }

  @Test
  @DisplayName("JS-SEC-137: on the shipped directory, without demo accounts, the setup creates the only account")
  void setupCreatesTheOnlyAccountWithoutDemoAccounts() {
    assertFalse(InMemoryDemoUserDirectory.insecureDemoAccountsRequested());
    DemoUserDirectory directory = DemoUserDirectoryProvider.directory();
    assertEquals(0L, directory.all().count(), "the shipped directory starts without accounts");

    navigate(SetupView.class);
    setValue(PasswordField.class, "Bootstrap token", KNOWN_TOKEN);
    setValue(PasswordField.class, "New password", "Adm1n-setup-pass");
    setValue(PasswordField.class, "Repeat password", "Adm1n-setup-pass");
    submit();
    assertNotification("Administrator 'admin' created. You can now log in.");

    assertEquals(1L, directory.all().count(), "the administrator is the only account");
    MyUser admin = directory.findByCredentials(new Credentials("admin", "Adm1n-setup-pass"))
        .orElseThrow(() -> new AssertionError("the administrator must verify"));
    assertTrue(admin.roles().contains(AuthorizationRole.ADMIN), "roles: " + admin.roles());
    assertTrue(directory.findByCredentials(new Credentials("user", "user")).isEmpty());
    assertTrue(directory.findByCredentials(new Credentials("demo", "demo")).isEmpty());
  }

  @SuppressWarnings("unchecked")
  private static <T> T privateField(Object target, String name) {
    try {
      var f = target.getClass().getDeclaredField(name);
      f.setAccessible(true);
      return (T) f.get(target);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("could not read private field '" + name + "': " + e);
    }
  }

  // ── Helpers ────────────────────────────────────────────────────

  private void submit() {
    test(findButton("Create administrator")).click();
  }

  private Button findButton(String label) {
    return $view(Button.class).all().stream()
        .filter(b -> label.equals(b.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no button labelled '" + label + "'"));
  }

  @SuppressWarnings("unchecked")
  private <F> F byLabel(Class<F> type, String label) {
    if (type == TextField.class) {
      return (F) $view(TextField.class).all().stream()
          .filter(t -> label.equals(t.getLabel()))
          .findFirst()
          .orElseThrow(() -> new AssertionError(
              "no TextField labelled '" + label + "'"));
    }
    if (type == PasswordField.class) {
      return (F) $view(PasswordField.class).all().stream()
          .filter(p -> label.equals(p.getLabel()))
          .findFirst()
          .orElseThrow(() -> new AssertionError(
              "no PasswordField labelled '" + label + "'"));
    }
    throw new IllegalArgumentException("unsupported field type: " + type);
  }

  private void setValue(Class<?> type, String label, String value) {
    if (type == TextField.class) {
      byLabel(TextField.class, label).setValue(value);
    } else if (type == PasswordField.class) {
      byLabel(PasswordField.class, label).setValue(value);
    } else {
      throw new IllegalArgumentException("unsupported field type: " + type);
    }
  }

  private List<String> notificationTexts() {
    return $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .toList();
  }

  private void assertNotification(String expectedSubstring) {
    boolean found = notificationTexts().stream()
        .anyMatch(t -> t.contains(expectedSubstring));
    assertTrue(found,
        "expected a Notification containing '" + expectedSubstring
            + "'; got: " + notificationTexts());
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }
}
