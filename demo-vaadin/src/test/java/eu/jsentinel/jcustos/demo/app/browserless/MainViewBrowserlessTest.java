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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.MainView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.demo.app.views.workspaces.AdminWorkspace;
import eu.jsentinel.jcustos.demo.app.views.workspaces.DemoUselessWorkspace;
import eu.jsentinel.jcustos.demo.app.views.workspaces.NerdWorkspace;
import eu.jsentinel.jcustos.demo.app.views.workspaces.PublicAllWorkspace;
import eu.jsentinel.jcustos.demo.app.views.workspaces.UserWorkspace;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.tabs.Tab;
import com.vaadin.flow.component.tabs.Tabs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless tests for {@link MainView}. The view's logic is essentially
 * a role-driven tab matrix plus a welcome card that renders the user's
 * roles as themed badges. Both parts are pure render-time decisions, so
 * we render the view with three different subjects and pin the resulting
 * tab list, badge set and content swap.
 */
@DisplayName("MainView — role-driven menu + welcome content")
class MainViewBrowserlessTest extends BrowserlessTest {

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
  }

  // ── Tab matrix ─────────────────────────────────────────────────

  @Test
  @DisplayName("ADMIN sees Home + Admin + User roles + Audit + Nerd + My Area + Public + Playground")
  void adminTabMatrix() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(MainView.class);

    List<String> labels = tabLabels();
    assertEquals(
        List.of("Home", "Admin", "User roles", "Audit log", "Nerd Zone", "My Area", "Public", "Playground"),
        labels,
        "ADMIN must see every role-gated tab in declaration order");
  }

  @Test
  @DisplayName("Plain USER sees only Home, My Area, Public, Playground")
  void userTabMatrix() {
    bind(new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER)));
    navigate(MainView.class);

    assertEquals(
        List.of("Home", "My Area", "Public", "Playground"),
        tabLabels(),
        "USER sees only the public + USER tabs");
  }

  @Test
  @DisplayName("NERD-only sees Home, Nerd Zone, Public, Playground")
  void nerdTabMatrix() {
    bind(new MyUser(3L, "Nerdy", EnumSet.of(AuthorizationRole.NERD)));
    navigate(MainView.class);

    assertEquals(
        List.of("Home", "Nerd Zone", "Public", "Playground"),
        tabLabels(),
        "NERD-only sees its role tab plus the open ones");
  }

  @Test
  @DisplayName("Q_ADMIN sees Home, User roles, Audit log, Public, Playground (no Admin, no Nerd, no My Area)")
  void qAdminTabMatrix() {
    bind(new MyUser(4L, "QualityBot", EnumSet.of(AuthorizationRole.Q_ADMIN)));
    navigate(MainView.class);

    assertEquals(
        List.of("Home", "User roles", "Audit log", "Public", "Playground"),
        tabLabels(),
        "Q_ADMIN sees the admin-roles + audit tabs but not the ADMIN-only nor USER-only tabs");
  }

  // ── Welcome content ────────────────────────────────────────────

  @Test
  @DisplayName("Welcome card greets the subject by displayName and renders a badge per role")
  void welcomeCardReflectsSubject() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(MainView.class);

    H2 greeting = $view(H2.class).first();
    assertEquals("Welcome, Admin", greeting.getText(),
        "H2 greeting must include the user's display name");

    List<String> badgeTexts = badgeSpans().stream()
        .map(Span::getText)
        .toList();
    assertTrue(badgeTexts.contains("ADMIN"),
        "an ADMIN subject must surface an ADMIN role badge; got: " + badgeTexts);
    assertTrue(badgeTexts.contains("USER"),
        "an ADMIN+USER subject must surface the USER role badge too; got: " + badgeTexts);

    // roleBadgeTheme is a switch — pin every branch we render here.
    assertBadgeTheme("ADMIN", "badge error");
    assertBadgeTheme("USER", "badge success");
  }

  @Test
  @DisplayName("roleBadgeTheme — NERD and Q_ADMIN branches")
  void roleBadgeThemeOtherBranches() {
    bind(new MyUser(5L, "Mix",
        EnumSet.of(AuthorizationRole.NERD, AuthorizationRole.Q_ADMIN)));
    navigate(MainView.class);

    assertBadgeTheme("NERD", "badge contrast");
    assertBadgeTheme("Q_ADMIN", "badge primary");
  }

  @Test
  @DisplayName("roleBadgeTheme — NOBODY falls into the default branch (no theme variant)")
  void roleBadgeThemeDefaultBranch() {
    bind(new MyUser(6L, "Nobody", EnumSet.of(AuthorizationRole.NOBODY)));
    navigate(MainView.class);

    Span badge = badgeSpans().stream()
        .filter(s -> "NOBODY".equals(s.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("NOBODY badge missing"));
    String themes = String.join(" ", badge.getElement().getThemeList());
    assertTrue(themes.startsWith("badge"),
        "NOBODY badge must carry the bare 'badge' theme (default switch branch)");
    assertFalse(themes.matches(".*badge\\s+(error|success|contrast|primary)\\b.*"),
        "NOBODY badge must NOT carry any role-specific theme variant; got: " + themes);
  }

  // ── Tab selection ──────────────────────────────────────────────

  @Test
  @DisplayName("Selecting the Admin tab swaps the AppLayout content to AdminWorkspace")
  void selectingAdminTabSwapsContent() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    MainView view = navigate(MainView.class);

    Tabs tabs = $view(Tabs.class).first();
    Tab adminTab = tabByLabel(tabs, "Admin");
    tabs.setSelectedTab(adminTab);

    assertNotNull(view.getContent(),
        "MainView must keep a content component after selecting a tab");
    assertEquals(AdminWorkspace.class, view.getContent().getClass(),
        "Admin tab must swap the content to the AdminWorkspace");
  }

  @Test
  @DisplayName("Tab-content map covers the five role workspaces for an admin subject")
  void allWorkspacesReachableByAdmin() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    MainView view = navigate(MainView.class);
    Tabs tabs = $view(Tabs.class).first();

    tabs.setSelectedTab(tabByLabel(tabs, "Admin"));
    assertEquals(AdminWorkspace.class, view.getContent().getClass());

    tabs.setSelectedTab(tabByLabel(tabs, "Nerd Zone"));
    assertEquals(NerdWorkspace.class, view.getContent().getClass());

    tabs.setSelectedTab(tabByLabel(tabs, "My Area"));
    assertEquals(UserWorkspace.class, view.getContent().getClass());

    tabs.setSelectedTab(tabByLabel(tabs, "Public"));
    assertEquals(PublicAllWorkspace.class, view.getContent().getClass());

    tabs.setSelectedTab(tabByLabel(tabs, "Playground"));
    assertEquals(DemoUselessWorkspace.class, view.getContent().getClass());
  }

  // ── Layout tuning (style hooks, theme variants, AppLayout state) ──

  @Test
  @DisplayName("Tabs is vertical-oriented and carries the 'nav-tabs' class hook")
  void tabsHaveExpectedHooks() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(MainView.class);

    Tabs tabs = $view(Tabs.class).first();
    assertEquals(Tabs.Orientation.VERTICAL, tabs.getOrientation(),
        "drawer Tabs must be vertical");
    assertTrue(tabs.getClassNames().contains("nav-tabs"),
        "drawer Tabs must carry the 'nav-tabs' class hook; got: " + tabs.getClassNames());
  }

  @Test
  @DisplayName("Navbar: app title and sign-out button carry their styling hooks")
  void navbarStylingHooks() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(MainView.class);

    Span appTitle = $view(Span.class).all().stream()
        .filter(s -> "Security Demo".equals(s.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no 'Security Demo' app title rendered"));
    assertTrue(appTitle.getClassNames().contains("app-title"),
        "app title must carry the 'app-title' class");

    Button signOut = $view(Button.class).all().stream()
        .filter(b -> "Sign out".equals(b.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no Sign out button rendered"));
    assertTrue(signOut.getClassNames().contains("navbar-btn"),
        "Sign-out button must carry the 'navbar-btn' class");
    java.util.Set<String> variants = signOut.getThemeNames();
    assertTrue(variants.contains("tertiary"),
        "Sign-out button must carry LUMO_TERTIARY (\"tertiary\"); got: " + variants);
    assertTrue(variants.contains("small"),
        "Sign-out button must carry LUMO_SMALL (\"small\"); got: " + variants);
  }

  @Test
  @DisplayName("Welcome content: 'welcome-view' wrapper centred, 'welcome-card' inside opted into spacing-s")
  void welcomeLayoutTuning() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(MainView.class);

    com.vaadin.flow.component.orderedlayout.VerticalLayout wrapper =
        $view(com.vaadin.flow.component.orderedlayout.VerticalLayout.class).all().stream()
            .filter(v -> v.getClassNames().contains("welcome-view"))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no 'welcome-view' VerticalLayout rendered"));
    assertEquals(com.vaadin.flow.component.orderedlayout.FlexComponent.Alignment.CENTER,
        wrapper.getAlignItems(),
        "welcome wrapper must call setAlignItems(CENTER)");
    assertEquals(com.vaadin.flow.component.orderedlayout.FlexComponent.JustifyContentMode.CENTER,
        wrapper.getJustifyContentMode(),
        "welcome wrapper must call setJustifyContentMode(CENTER)");
    assertEquals("100%", wrapper.getWidth(),
        "welcome wrapper must call setSizeFull() — sets width=100%");
    assertEquals("100%", wrapper.getHeight(),
        "welcome wrapper must call setSizeFull() — sets height=100%");

    com.vaadin.flow.component.orderedlayout.VerticalLayout card =
        $view(com.vaadin.flow.component.orderedlayout.VerticalLayout.class).all().stream()
            .filter(v -> v.getClassNames().contains("welcome-card"))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no 'welcome-card' VerticalLayout rendered"));
    assertFalse(card.isSpacing(),
        "welcome-card must call setSpacing(false)");
    assertTrue(card.getThemeNames().contains("spacing-s"),
        "welcome-card must opt into the 'spacing-s' theme variant");
    assertEquals(com.vaadin.flow.component.orderedlayout.FlexComponent.Alignment.START,
        card.getAlignItems(),
        "welcome-card must call setAlignItems(START)");
  }

  // ── Sign-out button ────────────────────────────────────────────

  @Test
  @DisplayName("Sign-out button clears the SubjectStore (LogoutService is wired)")
  void signOutClearsSubject() {
    bind(new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    navigate(MainView.class);

    assertTrue(SubjectStores.subjectStore().currentSubject(MyUser.class).isPresent(),
        "precondition: an admin subject is bound");

    Button signOut = $view(Button.class).all().stream()
        .filter(b -> "Sign out".equals(b.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no button labelled 'Sign out' rendered; got: "
                + $view(Button.class).all().stream().map(Button::getText).toList()));
    // Browserless 25.3 flushes server-initiated focus after a tester click and reaches
    // into the UI's session for it. The sign-out handler invalidates the HTTP session,
    // so there is no session left to flush against (a real browser never notices).
    // Assert usability the browserless way, then fire the click server-side.
    test(signOut).ensureComponentIsUsable();
    signOut.click();

    assertFalse(SubjectStores.subjectStore().currentSubject(MyUser.class).isPresent(),
        "Sign-out must remove the current subject from the store");
  }

  // ── Helpers ────────────────────────────────────────────────────

  /**
   * Binds the given subject after navigating to a public route, so the
   * {@code @VisibleFor(USER)} gate on MainView lets us in on the next
   * navigate(MainView.class) call.
   */
  private void bind(MyUser user) {
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(user, MyUser.class);
  }

  private List<String> tabLabels() {
    Tabs tabs = $view(Tabs.class).first();
    return tabs.getChildren()
        .filter(Tab.class::isInstance)
        .map(Tab.class::cast)
        .map(MainViewBrowserlessTest::labelOf)
        .collect(Collectors.toList());
  }

  private static String labelOf(Tab tab) {
    return tab.getChildren()
        .filter(Span.class::isInstance)
        .map(Span.class::cast)
        .map(Span::getText)
        .findFirst()
        .orElse("?");
  }

  private static Tab tabByLabel(Tabs tabs, String label) {
    return tabs.getChildren()
        .filter(Tab.class::isInstance)
        .map(Tab.class::cast)
        .filter(t -> label.equals(labelOf(t)))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no tab labelled '" + label + "'"));
  }

  /**
   * Returns the role badges from the welcome card — Spans whose theme
   * list starts with "badge". Excludes plain Spans like the app title.
   */
  private List<Span> badgeSpans() {
    return $view(Span.class).all().stream()
        .filter(s -> s.getElement().getThemeList().stream()
            .anyMatch(t -> t.startsWith("badge")))
        .toList();
  }

  private void assertBadgeTheme(String roleName, String expectedTheme) {
    Span badge = badgeSpans().stream()
        .filter(s -> roleName.equals(s.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no badge for role '" + roleName + "' — badges: "
                + badgeSpans().stream().map(Span::getText).toList()));
    String themes = String.join(" ", badge.getElement().getThemeList());
    assertEquals(expectedTheme, themes,
        "badge for " + roleName + " must carry theme '" + expectedTheme + "'");
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }
}
