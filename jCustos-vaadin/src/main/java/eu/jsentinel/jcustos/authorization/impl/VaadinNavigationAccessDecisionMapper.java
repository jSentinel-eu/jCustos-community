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
package eu.jsentinel.jcustos.authorization.impl;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecision;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.util.function.Supplier;

/**
 * Maps authentication-phase navigation decisions to Vaadin navigation operations.
 * <p>
 * <strong>Fail closed (JS-SEC-152, CWE-636, CWE-285):</strong> {@code LoginRequired} and
 * {@code AccessDenied} never leave the event without a usable target. A route name that is
 * not registered, or a login view that is not a registered route, is answered with
 * {@link BeforeEnterEvent#rerouteToError} for {@link SecurityException} - Vaadin would
 * otherwise go on and render the navigation target.
 */
public final class VaadinNavigationAccessDecisionMapper implements HasLogger {

  /** Creates a new mapper. */
  public VaadinNavigationAccessDecisionMapper() {
  }

  /**
   * Applies a navigation access decision to a Vaadin before-enter event.
   *
   * @param decision      the authentication-phase decision
   * @param event         the Vaadin event
   * @param loginTarget   supplies the login target class
   * @param defaultTarget supplies the default target class for already authenticated users
   */
  public void apply(NavigationAccessDecision decision,
                    BeforeEnterEvent event,
                    Supplier<Class<? extends LoginView>> loginTarget,
                    Supplier<Class<? extends Component>> defaultTarget) {
    switch (decision) {
      case NavigationAccessDecision.Allowed() -> { /* nothing to do */ }
      case NavigationAccessDecision.LoginRequired() -> {
        // JS-SEC-152 (CWE-636): a login target that is null or not a registered route must
        // not end the denial. forwardTo(Class) accepts any class and fails only while the
        // forward is carried out, so the target is checked first.
        Class<? extends LoginView> login = loginTarget.get();
        if (VaadinAccessDecisionMapper.isRegistered(event, login)) {
          event.forwardTo(login);
        } else {
          logger().warn("Login is required, but the login view {} is not a registered route "
              + "- rerouting to the error view instead", login == null ? null : login.getName());
          VaadinAccessDecisionMapper.failClosed(event);
        }
      }
      case NavigationAccessDecision.AlreadyLoggedIn() -> event.forwardTo(defaultTarget.get());
      case NavigationAccessDecision.AccessDenied(String route, boolean asForward) -> {
        // JS-SEC-152 (CWE-636, CWE-285): resolve the target first, as in
        // VaadinAccessDecisionMapper - an unknown route is a no-op for Vaadin.
        if (!VaadinAccessDecisionMapper.resolves(event, route)) {
          logger().warn("Access was denied, but the route '{}' the decision points to is not "
              + "registered - rerouting to the error view instead", route);
          VaadinAccessDecisionMapper.failClosed(event);
        } else if (asForward) {
          event.forwardTo(route);
        } else {
          event.rerouteTo(route);
        }
      }
    }
  }
}
