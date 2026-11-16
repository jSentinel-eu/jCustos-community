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
package eu.jsentinel.jcustos.demo.app.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.components.PermissionDemoCard;
import eu.jsentinel.jcustos.demo.app.views.components.ViewNavigationCard;
import eu.jsentinel.jcustos.demo.app.views.workspaces.*;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.starter.routes.SecureRoute;
import eu.jsentinel.jcustos.starter.ui.SecuredUi;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.tabs.Tab;
import com.vaadin.flow.component.tabs.Tabs;
import com.vaadin.flow.router.Route;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static eu.jsentinel.jcustos.demo.app.MySessionAccessor.isCurrentUserAuthorizedFor;
import static eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole.*;

/**
 * Home of every signed-in subject: the drawer shows the tabs the subject's roles open, the
 * welcome card the subject's role badges.
 * <p>
 * {@code @SecureRoute()} without constraints admits any authenticated subject and sends an
 * anonymous visitor to the login route. The view used to carry {@code @VisibleFor(USER)}, and
 * {@code MyRoleAccessEvaluator} answered every other subject with a forward to this very
 * view. Vaadin skips a forward to the navigation in progress, so the view rendered anyway -
 * the demo depended on a fail-open (JS-SEC-158). The forward of the evaluator now lands here
 * because this view admits those subjects, and a denial that points to the denied view
 * itself ends in the error view.
 */
@Route(MainView.NAV)
@SecureRoute()
public class MainView
    extends AppLayout
    implements HasLogger {

  public static final String NAV = "";

  private final Map<Tab, Component> tab2Workspace = new HashMap<>();

  public MainView() {
    // ── Navbar ────────────────────────────────────────────────────
    Span appTitle = new Span("Security Demo");
    appTitle.addClassName("app-title");

    Button logoutBtn = new Button("Sign out", VaadinIcon.SIGN_OUT.create(), e -> logout());
    logoutBtn.addThemeVariants(ButtonVariant.LUMO_TERTIARY, ButtonVariant.LUMO_SMALL);
    logoutBtn.addClassName("navbar-btn");

    addToNavbar(new DrawerToggle(), appTitle);
    addToNavbar(true, logoutBtn);

    // ── Drawer ────────────────────────────────────────────────────
    addToDrawer(createMainMenu());
    // V00.72 starter showcase: a SecuredUi.link(...) shortcut block sits
    // below the Tabs. The tabs above use manual isCurrentUserAuthorizedFor
    // checks; the entries below use the declarative SecuredUi builder so
    // drawer items disappear automatically when the subject lacks the
    // requirement. Visual demonstration that SecuredUi extends past page
    // content into the navigation surface.
    addToDrawer(createSecuredQuickLinks());

    // ── Default content ───────────────────────────────────────────
    setContent(createWelcomeContent());
  }

  private Tabs createMainMenu() {
    final Tabs tabs = new Tabs();
    tabs.setOrientation(Tabs.Orientation.VERTICAL);
    tabs.addClassName("nav-tabs");

    tabs.add(welcomeHomeTab());
    if (isCurrentUserAuthorizedFor(ADMIN)) tabs.add(adminTab());
    if (isCurrentUserAuthorizedFor(ADMIN, Q_ADMIN)) tabs.add(rolesAdminTab());
    if (isCurrentUserAuthorizedFor(ADMIN, Q_ADMIN)) tabs.add(auditTab());
    if (isCurrentUserAuthorizedFor(ADMIN, NERD)) tabs.add(nerdTab());
    if (isCurrentUserAuthorizedFor(USER)) tabs.add(userTab());
    tabs.add(publicAllTab());
    if (isCurrentUserAuthorizedFor(null)) tabs.add(demoUselessTab());

    tabs.addSelectedChangeListener(event -> setContent(tab2Workspace.get(event.getSelectedTab())));
    return tabs;
  }

  // ── Tab factory helpers ────────────────────────────────────────

  private Tab adminTab() {
    Tab tab = new Tab(VaadinIcon.COG.create(), new Span("Admin"));
    tab2Workspace.put(tab, new AdminWorkspace());
    return tab;
  }

  private Tab rolesAdminTab() {
    Tab tab = new Tab(VaadinIcon.USER_CARD.create(), new Span("User roles"));
    tab2Workspace.put(tab, new AdminRolesView());
    return tab;
  }

  private Tab auditTab() {
    Tab tab = new Tab(VaadinIcon.CLIPBOARD_TEXT.create(), new Span("Audit log"));
    tab2Workspace.put(tab, new AuditView());
    return tab;
  }

  private Tab nerdTab() {
    Tab tab = new Tab(VaadinIcon.CODE.create(), new Span("Nerd Zone"));
    tab2Workspace.put(tab, new NerdWorkspace());
    return tab;
  }

  private Tab userTab() {
    Tab tab = new Tab(VaadinIcon.USER.create(), new Span("My Area"));
    tab2Workspace.put(tab, new UserWorkspace());
    return tab;
  }

  private Tab publicAllTab() {
    Tab tab = new Tab(VaadinIcon.GLOBE.create(), new Span("Public"));
    tab2Workspace.put(tab, new PublicAllWorkspace());
    return tab;
  }

  private Tab demoUselessTab() {
    Tab tab = new Tab(VaadinIcon.FLASK.create(), new Span("Playground"));
    tab2Workspace.put(tab, new DemoUselessWorkspace());
    return tab;
  }

  private Tab welcomeHomeTab() {
    Tab tab = new Tab(VaadinIcon.HOME.create(), new Span("Home"));
    tab2Workspace.put(tab, createWelcomeContent());
    return tab;
  }

  // ── V00.72 SecuredUi-based drawer shortcuts ────────────────────

  private VerticalLayout createSecuredQuickLinks() {
    VerticalLayout block = new VerticalLayout();
    block.setSpacing(false);
    block.getThemeList().add("spacing-xs");
    block.addClassName("nav-secured-quicklinks");
    block.add(new Span("Direct routes (SecuredUi)"));
    block.add(SecuredUi.link()
        .to(AdminRolesView.class)
        .text("/admin/roles")
        .requiresPermission("admin:roles")
        .hideWhenDenied()
        .build());
    block.add(SecuredUi.link()
        .to(AdminSessionsView.class)
        .text("/admin/sessions")
        .requiresPermission("admin:sessions")
        .hideWhenDenied()
        .build());
    block.add(SecuredUi.link()
        .to(AuditView.class)
        .text("/audit")
        .requiresPermission("audit:read")
        .hideWhenDenied()
        .build());
    block.add(SecuredUi.link()
        .to(SecureRouteDemoView.class)
        .text("/secure-route-demo")
        .requiresRole("ADMIN", "NERD")
        .hideWhenDenied()
        .build());
    return block;
  }


  // ── Welcome screen ─────────────────────────────────────────────

  private Component createWelcomeContent() {
    Optional<MyUser> result = SubjectStores.subjectStore().currentSubject(MyUser.class);
    String displayName = result.isPresent() ? result.get().name() : "Guest";
    Set<AuthorizationRole> roles = result.isPresent() ? result.get().roles() : Set.of();

    H2 greeting = new H2("Welcome, " + displayName);

    HorizontalLayout badgeRow = new HorizontalLayout();
    badgeRow.setSpacing(true);
    for (AuthorizationRole role : roles) {
      Span badge = new Span(role.name());
      badge.getElement().getThemeList().add("badge " + roleBadgeTheme(role));
      badgeRow.add(badge);
    }

    Paragraph hint = new Paragraph(
        "Use the side navigation to explore sections you have access to. "
            + "Each section is protected by a role-based access evaluator. "
            + "Both demo cards below behave consistently across every "
            + "workspace and standalone view.");

    VerticalLayout card = new VerticalLayout(
        greeting,
        badgeRow,
        hint,
        new PermissionDemoCard(),
        new ViewNavigationCard());
    card.addClassName("welcome-card");
    card.setAlignItems(FlexComponent.Alignment.START);
    card.setSpacing(false);
    card.getThemeList().add("spacing-s");

    VerticalLayout wrapper = new VerticalLayout(card);
    wrapper.addClassName("welcome-view");
    wrapper.setSizeFull();
    wrapper.setAlignItems(FlexComponent.Alignment.CENTER);
    wrapper.setJustifyContentMode(FlexComponent.JustifyContentMode.CENTER);
    return wrapper;
  }

  private String roleBadgeTheme(AuthorizationRole role) {
    return switch (role) {
      case ADMIN -> "error";
      case NERD -> "contrast";
      case USER -> "success";
      case Q_ADMIN -> "primary";
      default -> "";
    };
  }

  // ── Logout ─────────────────────────────────────────────────────

  private static final eu.jsentinel.jcustos.logout.LogoutService LOGOUT_SERVICE =
      new eu.jsentinel.jcustos.logout.vaadin.VaadinLogoutService<>(
          SubjectStores.subjectStore(), MyUser.class,
          new eu.jsentinel.jcustos.logout.vaadin.DefaultVaadinLogoutGateway(),
          "/" + MyLoginView.NAV,
          /* closeVaadinSession= */ true,
          /* invalidateHttpSession= */ true);

  private void logout() {
    SubjectId subjectId =
        SubjectStores.subjectStore().currentSubject(MyUser.class)
            .map(u -> SubjectId.of(
                String.valueOf(u.id())))
            .orElse(SubjectId.of("anonymous"));
    LOGOUT_SERVICE.logout(subjectId,
        eu.jsentinel.jcustos.logout.LogoutScope.CurrentSession);
  }
}