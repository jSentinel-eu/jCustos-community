package eu.jsentinel.jcustos.demo.skill.vaadin.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.SessionStoreProvider;

import java.time.Clock;
import java.time.Instant;

import static eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView.NAV;

/**
 * Login route. Extends the framework's pre-built form
 * ({@code username / password / remember-me / sign-in}); the four
 * overrides wire credential validation, post-login navigation, and
 * failure handling.
 */
@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger {

  public static final String NAV = "login";

  private final AuthenticationService<Credentials, User> authenticationService
      = JCustosServiceResolver.authenticationService();

  @Override
  public boolean checkCredentials() {
    Credentials credentials = new Credentials(username(), password());
    boolean ok = authenticationService.checkCredentials(credentials);
    if (ok) {
      UserDirectoryProvider.directory().findByCredentials(credentials).ifPresent(user -> {
        SubjectStores.subjectStore().setCurrentSubject(user, User.class);
      });
    }
    return ok;
  }

  @Override
  public void reactOnFailedLogin() {
    logger().info("Login rejected — invalid credentials");
    Notification.show("Credentials not accepted.");
  }

  @Override
  public void navigateToApp() {
    UI.getCurrent().navigate(DashboardView.class);
  }


  /**
   * JS-SEC-060 (CWE-384): the session is recorded only after the HTTP session
   * id rotated, so the inventory row carries the id that lives on. Recording
   * inside {@link #checkCredentials()} would persist the retired id.
   */
  @Override
  protected void onSessionRotated(String previousSessionId, String currentSessionId) {
    SubjectStores.subjectStore().currentSubject(User.class).ifPresent(MyLoginView::recordSession);
  }

  /**
   * Records a {@link SessionRecord} so the {@code /admin/sessions} view
   * has something to render. Best-effort: missing Vaadin session,
   * missing session id, or any failure is swallowed — session
   * bookkeeping must not block login.
   */
  private static void recordSession(User user) {
    try {
      VaadinSession vaadin = VaadinSession.getCurrent();
      if (vaadin == null) return;
      WrappedSession wrapped = vaadin.getSession();
      String sessionId = wrapped == null ? null : wrapped.getId();
      if (sessionId == null) return;
      Instant now = Instant.now(Clock.systemUTC());
      SessionStoreProvider.sessionStore().save(new SessionRecord(
          SessionId.of(sessionId),
          SubjectId.of(user.id().toString()),
          TenantId.DEFAULT,
          now, now,
          JCustosVersion.INITIAL,
          SessionStatus.ACTIVE));
    } catch (RuntimeException ignored) {
      // session bookkeeping must not block login
    }
  }
}
