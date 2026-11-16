package eu.jsentinel.jcustos.demo.skill.vaadin.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.SessionRef;
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
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.SessionStoreProvider;

import java.time.Clock;
import java.time.Instant;

import static eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView.NAV;

/**
 * Replacement for the {@code vaadin-jcustos} login view —
 * additionally forwards to {@link SetupView} when no administrator
 * exists yet ({@link BootstrapWiring#stateService bootstrapRequired}).
 */
@PublicRoute
@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger, BeforeEnterObserver {

  public static final String NAV = "login";

  private final AuthenticationService<Credentials, User> authenticationService
      = JCustosServiceResolver.authenticationService();

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    if (BootstrapWiring.instance().stateService().bootstrapRequired()) {
      event.forwardTo(SetupView.class);
    }
  }

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
    SubjectStores.subjectStore().currentSubject(User.class)
        .ifPresent(user -> recordSession(user, currentSessionId));
  }

  /**
   * Records a {@link SessionRecord} so the {@code /admin/sessions} view
   * has something to render. The record is keyed by the reference of the
   * session id, never by the id itself: the id is the session cookie, and
   * whoever reads the inventory must not be able to take the session over
   * (JS-SEC-117, CWE-522). The per-request revocation check and
   * {@code VaadinSessionRevocation.revoke} look the live session up by the
   * same reference. Best-effort: any failure is swallowed — session
   * bookkeeping must not block login.
   */
  private static void recordSession(User user, String sessionId) {
    if (sessionId == null || sessionId.isBlank()) return;
    try {
      Instant now = Instant.now(Clock.systemUTC());
      SessionStoreProvider.sessionStore().save(new SessionRecord(
          SessionId.of(SessionRef.of(sessionId)),
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
