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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.services.DemoSessionStoreProvider;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import eu.jsentinel.jcustos.demo.app.security.model.Credentials;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;

import java.time.Clock;
import java.time.Instant;

import static eu.jsentinel.jcustos.demo.app.views.MyLoginView.NAV;

@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger, BeforeEnterObserver {

  public static final String NAV = "login";

  public static final String DEMO_GROUPS_ID = "my-login-view-demo-groups";

  //TODO demo for customizing the LoginView
  private final Select<String> select = new Select<>() {{
    setId(DEMO_GROUPS_ID);
    setItems("Option one", "Option two");
    setPlaceholder("select group");
//    setLabel("GroupSelector");
    addValueChangeListener(event -> Notification.show("finally you made a choice.. " + event.getValue()));
  }};


  private final AuthenticationService<Credentials, MyUser> authenticationService
      = JCustosServiceResolver.authenticationService();

  public MyLoginView() {
    super();
    //adding custom element to LoginView
    setCustomElements(select);
  }

  @Override
  public void reactOnFailedLogin() {
    logger().info("Ohhh no, Wrong Credentials..");
    LoginAttemptDecision decision = currentLockoutDecision(username());
    if (decision instanceof LoginAttemptDecision.LockedOut lockout) {
      showLockoutBanner(lockout);
      return;
    }
    Notification.show("Credentials not accepted..");
  }

  /**
   * Asks the configured {@link LoginAttemptPolicy} whether the username
   * is currently throttled. The decision returned by the policy reflects
   * the state <em>after</em> {@code MyAuthenticationService.checkCredentials}
   * has recorded the failure — so a lockout produced by the just-rejected
   * attempt surfaces here.
   */
  private static LoginAttemptDecision currentLockoutDecision(String username) {
    if (username == null || username.isBlank()) {
      return LoginAttemptDecision.allowed();
    }
    try {
      LoginAttemptPolicy policy = JCustosServiceResolver.loginAttemptPolicy();
      return policy.beforeAttempt(
          LoginAttemptContext.now(username, currentClientAddress(), null));
    } catch (RuntimeException ignored) {
      return LoginAttemptDecision.allowed();
    }
  }

  /** JS-SEC-061: resolved through the registered ClientAddressResolver, never getRemoteAddr() directly. */
  private static String currentClientAddress() {
    return VaadinClientAddress.current().orElse(null);
  }

  private static void showLockoutBanner(LoginAttemptDecision.LockedOut lockout) {
    long seconds = Math.max(1L, lockout.remaining().toSeconds());
    String message = "Account locked — " + lockout.failedAttempts()
        + " failed attempts. Try again in " + formatDuration(seconds) + ".";
    Notification notification = Notification.show(
        message, 6000, Notification.Position.TOP_CENTER);
    notification.addThemeVariants(NotificationVariant.LUMO_ERROR);
  }

  private static String formatDuration(long seconds) {
    if (seconds < 60) {
      return seconds + " s";
    }
    long minutes = seconds / 60;
    long rest = seconds % 60;
    if (minutes < 60) {
      return rest == 0 ? minutes + " min" : minutes + " min " + rest + " s";
    }
    long hours = minutes / 60;
    long restMin = minutes % 60;
    return restMin == 0 ? hours + " h" : hours + " h " + restMin + " min";
  }

  @Override
  public void navigateToApp() {
    //TODO redundant definition - see MyLoginListener
    UI.getCurrent()
      .navigate(MainView.class);
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    if (BootstrapWiring.instance().stateService().bootstrapRequired()) {
      event.forwardTo(SetupView.class);
    }
  }

  @Override
  public boolean checkCredentials() {
    final String username = username();
    final String password = password();
    logger().info("checkCredentials - username {}", username);
    final Credentials credentials = new Credentials(username, password);
    final boolean permitted = authenticationService.checkCredentials(credentials);
    if (permitted) {
      DemoUserDirectoryProvider.directory().findByCredentials(credentials)
          .ifPresent(user -> {
            SubjectStores.subjectStore().setCurrentSubject(user, MyUser.class);
            recordSession(user);
          });
    }
    return permitted;
  }

  /**
   * Persists a {@link SessionRecord} for {@code user} into the demo's
   * {@link DemoSessionStoreProvider#sessionStore() SessionStore} so the
   * Phase-8a {@code SessionManagementView} renders a real inventory
   * row. Best-effort: missing Vaadin session, missing session id, or
   * any other failure is swallowed — recording sessions for the
   * admin UI must never block the login flow.
   */
  private static void recordSession(MyUser user) {
    try {
      VaadinSession vaadin = VaadinSession.getCurrent();
      if (vaadin == null) {
        return;
      }
      WrappedSession wrapped = vaadin.getSession();
      String sessionId = wrapped == null ? null : wrapped.getId();
      if (sessionId == null) {
        return;
      }
      Instant now = Instant.now(Clock.systemUTC());
      DemoSessionStoreProvider.sessionStore().save(new SessionRecord(
          SessionId.of(sessionId),
          SubjectId.of(user.id().toString()),
          TenantId.DEFAULT,
          now,
          now,
          JCustosVersion.INITIAL,
          SessionStatus.ACTIVE));
    } catch (RuntimeException ignored) {
      // session bookkeeping must not block login
    }
  }
}
