package eu.jsentinel.jcustos.demo.skill.vaadin.views;

import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;

/**
 * Public landing page — visible to <strong>everyone</strong>,
 * including anonymous visitors.
 *
 * <p>No {@code @VisibleFor} and no {@code @RequiresPermission}, but
 * {@code @PublicRoute}: the bootstrap runs with
 * {@code denyByDefault(true)}, which denies every route without a
 * security annotation unless it is declared public (JS-SEC-085). The
 * {@code LoginListener} lets the navigation through without
 * authentication. {@code MainLayout} carries no restriction - a public
 * view must not live in a restricted layout (JS-SEC-154).
 *
 * <p>This page is the marketing / overview surface — the rest of the
 * app (dashboard, admin views) is reachable only via the drawer
 * entries that {@code SecuredUi.link().hideWhenDenied()} reveals
 * after login.
 *
 * <p>For logged-in users a "Go to dashboard" button shortcuts to
 * {@link DashboardView}; for anonymous visitors a "Sign in" button
 * leads to {@code MyLoginView}.
 */
@PublicRoute
@Route(value = PublicHomeView.NAV, layout = MainLayout.class)
public class PublicHomeView extends Composite<VerticalLayout> {

  public static final String NAV = "";

  public PublicHomeView() {
    VerticalLayout content = getContent();
    content.setSpacing(false);
    content.getThemeList().add("spacing-s");
    content.setAlignItems(FlexComponent.Alignment.START);

    content.add(new H1("jCustos Vaadin Demo"));
    content.add(new Paragraph(
        "Welcome. This page is reachable without an account — "
            + "it carries no @VisibleFor / @RequiresPermission, so "
            + "the jCustos scanner treats it as unrestricted. "
            + "After signing in, the drawer reveals the dashboard "
            + "and any admin areas your role grants."));

    boolean loggedIn = SubjectStores.subjectStore()
        .currentSubject(User.class).isPresent();
    if (loggedIn) {
      Button toDashboard = new Button("Go to dashboard",
          VaadinIcon.ARROW_RIGHT.create(),
          e -> UI.getCurrent().navigate(DashboardView.class));
      toDashboard.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
      content.add(toDashboard);
    } else {
      Button signIn = new Button("Sign in",
          VaadinIcon.SIGN_IN.create(),
          e -> UI.getCurrent().navigate(MyLoginView.class));
      signIn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
      content.add(signIn);
    }
  }
}
