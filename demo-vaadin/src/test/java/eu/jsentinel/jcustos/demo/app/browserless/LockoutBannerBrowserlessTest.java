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
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter test for the lockout banner in
 * {@link MyLoginView}. Since 00.84.00 the library {@link LoginView} runs the
 * {@link LoginAttemptPolicy} protocol itself (JS-SEC-124): a refused attempt
 * reaches the view through {@code reactOnLockedOut}, and after a failed
 * attempt the view looks at the policy with
 * {@link LoginAttemptPolicy#peek(LoginAttemptContext)}. In both cases a
 * {@link LoginAttemptDecision.LockedOut} surfaces as a red Notification with
 * the remaining lockout time and failure count instead of the generic
 * "Credentials not accepted" toast.
 */
@DisplayName("MyLoginView — lockout banner via BrowserlessTest")
class LockoutBannerBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void setUp() throws Exception {
    // The Vaadin demo's BootstrapWiring is a singleton that runs
    // enableBootstrapMode() (which wipes seeded admins) at first access.
    // For tests we want bootstrap OFF, so the LoginView renders without
    // forwarding to /setup. Two steps:
    //   (1) ask for DISABLED mode via system property, and
    //   (2) drop any cached singleton so the next instance() call
    //       picks up the new property.
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    // Seed an admin so the directory reports hasAnyAdministrator(), even
    // though with DISABLED mode the bootstrap flow no longer cares.
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    // Stub policy: always locked out for any attempt.
    JCustosServiceResolver.setLoginAttemptPolicy(new AlwaysLockedPolicy(
        Duration.ofMinutes(5), 7));
  }

  /** Resets the {@link BootstrapWiring#current} static singleton via reflection. */
  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("LockedOut decision surfaces in a Notification with seconds + failure count")
  void lockoutNotification() {
    navigate(MyLoginView.class);

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("admin");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    Notification notification = $(Notification.class).first();
    String message = test(notification).getText();
    assertTrue(message.contains("Account locked"),
        "Notification must announce the lockout: " + message);
    assertTrue(message.contains("7"),
        "Notification must include the failure count from the policy: " + message);
    assertTrue(message.contains("5 min"),
        "Notification must include the formatted remaining time: " + message);
  }

  private void submit(String username, String password) {
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue(username);
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(password);
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();
  }

  private long lockoutBanners() {
    return $(Notification.class).all().stream()
        .map(n -> test(n).getText())
        .filter(text -> text.contains("Account locked"))
        .count();
  }

  @Test
  @DisplayName("JS-SEC-124: with the demo's real policy the fifth wrong password locks - not the third - and the correct one is then refused")
  void realPolicyLocksAtTheConfiguredThresholdAndRefusesTheCorrectPassword() {
    // The policy the demo registers through META-INF/services: InMemoryLoginAttemptPolicy with
    // its default thresholds. View and service used to call it both; counted twice, the
    // lockout would set in after three failures.
    JCustosServiceResolver.setLoginAttemptPolicy(new InMemoryLoginAttemptPolicy());
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();
    navigate(MyLoginView.class);

    for (int i = 1; i < threshold; i++) {
      submit("admin", "wrong guess " + i);
      assertEquals(0, lockoutBanners(), "no lockout after " + i + " failed attempt(s)");
    }

    // The failure that reaches the threshold: the view records it and peeks afterwards.
    submit("admin", "wrong guess " + threshold);
    assertEquals(1, lockoutBanners(), "the attempt that completes the threshold shows the banner");

    // Locked: the correct password is not evaluated, the banner comes from reactOnLockedOut.
    submit("admin", "admin");
    assertEquals(2, lockoutBanners());
    assertTrue(SubjectStores.subjectStore().currentSubject(MyUser.class).isEmpty(),
        "the correct password must not log in while the account is locked");
  }

  @Test
  @DisplayName("JS-SEC-124: one failure short of the threshold the correct password still logs in")
  void belowTheThresholdTheCorrectPasswordLogsIn() {
    JCustosServiceResolver.setLoginAttemptPolicy(new InMemoryLoginAttemptPolicy());
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();
    navigate(MyLoginView.class);
    for (int i = 1; i < threshold; i++) {
      submit("admin", "wrong guess " + i);
    }

    submit("admin", "admin");

    assertTrue(SubjectStores.subjectStore().currentSubject(MyUser.class).isPresent());
    assertEquals(0, lockoutBanners());
  }

  private static final class AlwaysLockedPolicy implements LoginAttemptPolicy {
    private final Duration remaining;
    private final int failedAttempts;

    AlwaysLockedPolicy(Duration remaining, int failedAttempts) {
      this.remaining = remaining;
      this.failedAttempts = failedAttempts;
    }

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      return LoginAttemptDecision.lockedOut(remaining, failedAttempts);
    }

    @Override public void recordSuccess(LoginAttemptContext ctx) { }

    @Override public void recordFailure(LoginAttemptContext ctx) { }
  }
}
