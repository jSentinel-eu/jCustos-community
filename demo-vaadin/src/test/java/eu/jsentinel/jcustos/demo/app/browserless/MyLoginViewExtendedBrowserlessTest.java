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
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.demo.app.views.SetupView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationTester;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter tests for the {@link MyLoginView} branches not
 * covered by {@code LockoutBannerBrowserlessTest} and
 * {@code SessionRotationBrowserlessTest}: custom Select, generic
 * "Credentials not accepted" failure toast, beforeEnter forward to
 * {@code /setup}, full success path that binds the SubjectStore, and
 * the various {@code formatDuration} branches surfaced via the lockout
 * Notification text.
 */
@DisplayName("MyLoginView — extended branches (Select, beforeEnter, success, lockout durations)")
class MyLoginViewExtendedBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    System.clearProperty("security.bootstrap.token.file");
  }

  // ── Custom select customisation ────────────────────────────────

  @Test
  @DisplayName("Constructor wires the custom 'select group' Select with the right id, placeholder, and items")
  void customSelectIsRendered() {
    navigate(MyLoginView.class);

    @SuppressWarnings("unchecked")
    Select<String> select = (Select<String>) $view(Select.class)
        .id(MyLoginView.DEMO_GROUPS_ID);
    assertNotNull(select,
        "MyLoginView must add a Select with id '" + MyLoginView.DEMO_GROUPS_ID + "'");
    assertEquals("select group", select.getPlaceholder(),
        "Select must carry the 'select group' placeholder");

    Set<String> items = Set.copyOf(select.getListDataView().getItems().toList());
    assertEquals(Set.of("Option one", "Option two"), items,
        "Select must expose the two demo items; got: " + items);
  }

  @Test
  @DisplayName("Picking an item from the Select fires a Notification echoing the value")
  void selectFiresNotificationOnChange() {
    navigate(MyLoginView.class);

    @SuppressWarnings("unchecked")
    Select<String> select = (Select<String>) $view(Select.class)
        .id(MyLoginView.DEMO_GROUPS_ID);
    select.setValue("Option one");

    boolean ok = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .anyMatch(t -> t.contains("finally you made a choice.. Option one"));
    assertTrue(ok,
        "Select change must surface the 'finally you made a choice..' Notification");
  }

  // ── Failure toast (no policy / non-lockout decision) ───────────

  @Test
  @DisplayName("Wrong credentials with no lockout surface the generic 'Credentials not accepted..' toast")
  void wrongCredentialsShowGenericToast() {
    JCustosServiceResolver.setLoginAttemptPolicy(new NeverLocksPolicy());

    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("WRONG");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    boolean ok = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .anyMatch(t -> t.contains("Credentials not accepted"));
    assertTrue(ok,
        "non-lockout failed login must show the generic 'Credentials not accepted..' toast");
    // and crucially NOT a lockout banner
    assertTrue($(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .noneMatch(t -> t.contains("Account locked")),
        "no lockout banner must surface when the policy does not lock out");
  }

  @Test
  @DisplayName("A LoginAttemptPolicy that throws is swallowed — the failure toast still surfaces")
  void throwingPolicyIsSwallowed() {
    JCustosServiceResolver.setLoginAttemptPolicy(new ThrowingPolicy());

    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("WRONG");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    boolean ok = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .anyMatch(t -> t.contains("Credentials not accepted"));
    assertTrue(ok,
        "a throwing LoginAttemptPolicy must not propagate; the view must still show the generic toast");
  }

  // ── beforeEnter forward ────────────────────────────────────────

  @Test
  @DisplayName("beforeEnter forwards to /setup when bootstrap is required")
  void beforeEnterForwardsToSetup() throws Exception {
    // Switch to PERSISTENT_FILE with a pre-written token so build()
    // succeeds, then leave the directory without an admin so
    // bootstrapRequired() returns true.
    Path tokenFile = Files.createTempFile("test-bootstrap", ".txt");
    Files.writeString(tokenFile,
        "token=TEST-TKNS-9999-AAAA-BBBB" + System.lineSeparator()
            + "createdAt=" + Instant.now() + System.lineSeparator());
    System.setProperty("security.bootstrap.mode", "PERSISTENT_FILE");
    System.setProperty("security.bootstrap.token.file", tokenFile.toString());
    resetBootstrapWiringSingleton();
    DemoUserDirectoryProvider.reset(); // wipes the admin we seeded in setUp

    try {
      IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
          () -> navigate(MyLoginView.class),
          "/login must forward to /setup when no administrator exists");
      assertTrue(failure.getMessage().contains(SetupView.class.getName()),
          "exception must reference the SetupView forward target; got: "
              + failure.getMessage());
    } finally {
      Files.deleteIfExists(tokenFile);
    }
  }

  // ── checkCredentials success path ──────────────────────────────

  @Test
  @DisplayName("Valid credentials bind the SubjectStore via setCurrentSubject(...)")
  void successBindsSubjectStore() {
    JCustosServiceResolver.setLoginAttemptPolicy(new NeverLocksPolicy());

    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("admin");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    MyUser bound = SubjectStores.subjectStore()
        .currentSubject(MyUser.class)
        .orElseThrow(() -> new AssertionError(
            "valid credentials must bind a MyUser into the SubjectStore"));
    assertEquals(1L, bound.id(), "the bound subject must be the admin (id=1)");
    assertEquals("Admin", bound.name(),
        "the bound subject must carry the directory's displayName");
  }

  // ── formatDuration branches via lockout banner text ────────────

  @Test
  @DisplayName("Lockout banner — seconds branch (less than a minute): '45 s'")
  void lockoutBannerSecondsBranch() {
    triggerLockoutBanner(Duration.ofSeconds(45), 3);

    assertBannerContains("45 s");
  }

  @Test
  @DisplayName("Lockout banner — minutes branch with no remainder: '5 min'")
  void lockoutBannerMinutesNoRemainder() {
    triggerLockoutBanner(Duration.ofMinutes(5), 4);

    assertBannerContains("5 min");
    assertBannerDoesNotContain(" s");
  }

  @Test
  @DisplayName("Lockout banner — minutes branch with remainder: '2 min 5 s'")
  void lockoutBannerMinutesWithRemainder() {
    triggerLockoutBanner(Duration.ofMinutes(2).plusSeconds(5), 6);

    assertBannerContains("2 min 5 s");
  }

  @Test
  @DisplayName("Lockout banner — hours branch with no remainder: '3 h'")
  void lockoutBannerHoursNoRemainder() {
    triggerLockoutBanner(Duration.ofHours(3), 9);

    assertBannerContains("3 h");
    assertBannerDoesNotContain(" min");
  }

  @Test
  @DisplayName("Lockout banner — hours branch with remainder: '1 h 30 min'")
  void lockoutBannerHoursWithRemainder() {
    triggerLockoutBanner(Duration.ofMinutes(90), 10);

    assertBannerContains("1 h 30 min");
  }

  @Test
  @DisplayName("Lockout banner — sub-second duration clamps to '1 s'")
  void lockoutBannerSubSecondClampsToOne() {
    triggerLockoutBanner(Duration.ofMillis(200), 2);

    assertBannerContains("1 s");
  }

  @Test
  @DisplayName("Lockout banner carries the LUMO_ERROR theme variant")
  void lockoutBannerCarriesErrorTheme() {
    triggerLockoutBanner(Duration.ofMinutes(5), 7);

    Notification banner = $(Notification.class).all().stream()
        .filter(n -> ((NotificationTester) test(n)).getText().contains("Account locked"))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no lockout banner found"));
    assertTrue(banner.getThemeNames().contains("error"),
        "lockout banner must carry LUMO_ERROR ('error') theme; got: " + banner.getThemeNames());
  }

  // ── navigateToApp ──────────────────────────────────────────────

  @Test
  @DisplayName("navigateToApp() navigates to MainView (smoke check on the API)")
  void navigateToAppDelegatesToMain() {
    // MyLoginView.navigateToApp() is normally invoked by the LoginView
    // success path after checkCredentials returns true. Here we drive it
    // directly and assert that no exception is thrown. The actual
    // navigation target is a smoke check — the AppLayout requires a
    // bound subject (MainView @VisibleFor(USER)) so we bind one first
    // and check that the navigation lands on MainView.
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)),
        MyUser.class);

    MyLoginView view = (MyLoginView) getCurrentView();
    view.navigateToApp();

    assertSame(eu.jsentinel.jcustos.demo.app.views.MainView.class,
        getCurrentView().getClass(),
        "navigateToApp must land on MainView");
  }

  // ── Helpers ────────────────────────────────────────────────────

  private void triggerLockoutBanner(Duration remaining, int failedAttempts) {
    JCustosServiceResolver.setLoginAttemptPolicy(new AlwaysLockedPolicy(remaining, failedAttempts));
    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("WRONG");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();
  }

  private void assertBannerContains(String expectedSubstring) {
    List<String> texts = bannerTexts();
    assertTrue(texts.stream().anyMatch(t -> t.contains(expectedSubstring)),
        "expected lockout banner containing '" + expectedSubstring
            + "'; got: " + texts);
  }

  private void assertBannerDoesNotContain(String unexpectedSubstring) {
    List<String> texts = bannerTexts();
    assertTrue(texts.stream().noneMatch(t -> t.contains("Account locked") && t.contains(unexpectedSubstring)),
        "lockout banner must not contain '" + unexpectedSubstring
            + "'; got: " + texts);
  }

  private List<String> bannerTexts() {
    return $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .toList();
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static final class NeverLocksPolicy implements LoginAttemptPolicy {
    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      return LoginAttemptDecision.allowed();
    }
    @Override public void recordSuccess(LoginAttemptContext ctx) { }
    @Override public void recordFailure(LoginAttemptContext ctx) { }
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

  /**
   * Returns Allowed on the first {@code beforeAttempt} (so the
   * credential check itself runs and rejects the wrong password) and
   * throws on the second — i.e. the post-failure re-query performed by
   * {@code MyLoginView.currentLockoutDecision(...)}, whose catch-clause
   * we want to exercise.
   */
  private static final class ThrowingPolicy implements LoginAttemptPolicy {
    private int calls = 0;
    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      calls++;
      if (calls == 1) return LoginAttemptDecision.allowed();
      throw new RuntimeException("policy boom on re-query");
    }
    @Override public void recordSuccess(LoginAttemptContext ctx) { }
    @Override public void recordFailure(LoginAttemptContext ctx) { }
  }
}
