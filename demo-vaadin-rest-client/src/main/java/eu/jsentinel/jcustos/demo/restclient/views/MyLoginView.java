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
package eu.jsentinel.jcustos.demo.restclient.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.restclient.backend.BackendClientProvider;
import eu.jsentinel.jcustos.demo.restclient.backend.Credentials;
import eu.jsentinel.jcustos.demo.restclient.backend.RemoteUser;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;

@Route(MyLoginView.NAV)
public class MyLoginView extends LoginView implements HasLogger, BeforeEnterObserver {

  public static final String NAV = "login";

  private final AuthenticationService<Credentials, RemoteUser> authenticationService =
      JCustosServiceResolver.authenticationService();

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    // If the backend has not yet been initialised, redirect to /setup.
    try {
      if (BackendClientProvider.client().bootstrapStatus().bootstrapRequired()) {
        event.forwardTo(SetupView.class);
      }
    } catch (RuntimeException ex) {
      // Backend unreachable — let the user try to log in; the form will
      // surface the transport error on submit.
    }
  }

  @Override
  public boolean checkCredentials() {
    Credentials credentials = new Credentials(username(), password());
    boolean ok = authenticationService.checkCredentials(credentials);
    if (!ok) return false;
    // RestBackedAuthenticationService already cached the RemoteUser via
    // ClientJCustosContext / SubjectStore, so no extra step here.
    return true;
  }

  @Override
  public void reactOnFailedLogin() {
    logger().info("Login failed for user {}", username());
    LoginAttemptDecision decision = currentLockoutDecision(username());
    if (decision instanceof LoginAttemptDecision.LockedOut lockout) {
      showLockoutBanner(lockout);
      return;
    }
    Notification.show("Credentials not accepted.");
  }

  @Override
  public void navigateToApp() {
    UI.getCurrent().navigate(MainView.class);
  }

  /**
   * Queries the locally configured {@link LoginAttemptPolicy} for the
   * username. {@code RestBackedAuthenticationService} consults the same
   * policy <em>before</em> hitting the backend, so a lockout produced
   * here is the local-side throttle (defeats brute-force loops at the
   * Vaadin layer regardless of what the backend does).
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
}
