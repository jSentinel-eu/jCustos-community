package eu.jsentinel.jcustos.demo.skill.vaadin.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;

@PublicRoute
@Route(MyLoginView.NAV)
public class MyLoginView extends LoginView implements HasLogger {
  public static final String NAV = "login";

  @Override
  public boolean checkCredentials() {
    Credentials credentials = new Credentials(username(), password());
    AuthenticationService<Credentials, User> authn =
        JCustosServiceResolver.authenticationService();
    boolean ok = authn.checkCredentials(credentials);
    if (ok) {
      User user = authn.loadSubject(credentials);
      if (user != null) {
        SubjectStores.subjectStore().setCurrentSubject(user, User.class);
      }
    }
    return ok;
  }

  @Override
  public void reactOnFailedLogin() {
    Notification.show("Credentials not accepted.");
  }

  @Override
  public void navigateToApp() {
    UI.getCurrent().navigate(DashboardView.class);
  }
}
