package eu.jsentinel.jcustos.demo.skill.vaadin.views;

import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.VisibleFor;

import java.util.Optional;
import java.util.Set;

import static eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole.*;

/**
 * Post-login landing page. Rendered inside {@link MainLayout}.
 *
 * <p>{@code @VisibleFor(USER)} — any authenticated user can land
 * here. {@code RoleAccessEvaluator} sends unauthenticated visitors to
 * the login view and subjects without {@code USER} to the public home,
 * never back to this view: a denial that points to the denied view ends
 * in the error view (JS-SEC-158).
 *
 * <p>The drawer in {@link MainLayout} filters its own entries via
 * {@code SecuredUi.link().hideWhenDenied()} — audit / sessions /
 * roles disappear for non-ADMIN subjects, the public Home stays
 * visible to everyone.
 */
@Route(value = DashboardView.NAV, layout = MainLayout.class)
@VisibleFor(USER)
public class DashboardView extends Composite<VerticalLayout> {

  public static final String NAV = "dashboard";

  public DashboardView() {
    Optional<User> result = SubjectStores.subjectStore()
        .currentSubject(User.class);
    String displayName = result.map(User::name).orElse("Guest");
    Set<AuthorizationRole> roles = result.map(User::roles).orElse(Set.of());

    H2 greeting = new H2("Welcome, " + displayName);

    HorizontalLayout badges = new HorizontalLayout();
    badges.setSpacing(true);
    for (AuthorizationRole role : roles) {
      Span badge = new Span(role.name());
      badge.getElement().getThemeList().add("badge " + (role == ADMIN ? "error" : "success"));
      badges.add(badge);
    }

    Paragraph hint = new Paragraph(
        "Drawer entries appear based on the permissions your roles grant. "
            + "Try logging in as the regular user — the audit, sessions and "
            + "roles entries disappear automatically.");

    VerticalLayout content = getContent();
    content.add(greeting, badges, hint);
    content.setAlignItems(FlexComponent.Alignment.START);
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");
  }
}
