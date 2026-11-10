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
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEvent;
import com.vaadin.flow.router.Location;

/**
 * Maps core access decisions to Vaadin navigation operations.
 * <p>
 * <strong>Fail closed (JS-SEC-152, CWE-636, CWE-285):</strong> a decision that sends the
 * visitor to a route by name is applied only when that name resolves to a registered
 * server-side route. Vaadin treats {@code rerouteTo(String)} and {@code forwardTo(String)}
 * with an unknown route as "nothing to do" and goes on to render the navigation target, so
 * an unresolvable name is answered with {@link BeforeEnterEvent#rerouteToError} instead.
 * Since 00.84.00 a denial applied by this mapper therefore never leaves the event without
 * a target; {@link AuthorizationListener} enforces the same as a post-condition.
 */
public final class VaadinAccessDecisionMapper implements HasLogger {

  /** User-facing message of the fail-closed fallback - generic on purpose (R018). */
  static final String ACCESS_DENIED_MESSAGE = "Access denied";

  /** Creates a new mapper. */
  public VaadinAccessDecisionMapper() {
  }

  /**
   * Applies an access decision to a Vaadin before-enter event.
   * <p>
   * Every decision other than {@link AccessDecision.Granted} leaves the event with a
   * reroute or forward target. If the route a decision names is not registered, or the
   * reroute cannot be built, the event is rerouted to the error view for
   * {@link SecurityException}.
   *
   * @param decision the core decision
   * @param event    the Vaadin event
   */
  public void apply(AccessDecision decision, BeforeEnterEvent event) {
    switch (decision) {
      case AccessDecision.Granted() -> { /* nothing to do */ }
      case AccessDecision.Reroute(String route, boolean asForward) -> {
        // JS-SEC-152 (CWE-636, CWE-285): resolve the target first. rerouteTo(String) and
        // forwardTo(String) only record an "unknown" route when the name is not registered,
        // and the protected view is rendered.
        if (!resolves(event, route)) {
          logger().warn("Access was denied, but the route '{}' the decision points to is not "
              + "registered - rerouting to the error view instead", route);
          failClosed(event);
        } else if (asForward) {
          event.forwardTo(route);
        } else {
          event.rerouteTo(route);
        }
      }
      case AccessDecision.RerouteToError(Class<? extends Exception> errorType, String msg) -> {
        if (msg != null) {
          try {
            event.rerouteToError(errorType.getDeclaredConstructor().newInstance(), msg);
          } catch (ReflectiveOperationException e) {
            event.rerouteToError(new RuntimeException("Access denied", e), msg);
          }
        } else {
          event.rerouteToError(errorType);
        }
      }
      case AccessDecision.RerouteWithParameter<?> reroute -> {
        try {
          event.rerouteTo(reroute.target(), reroute.parameter());
        } catch (RuntimeException unresolvable) {
          // JS-SEC-152: no route accepts the parameter - same answer as an unknown route.
          logger().warn("Access was denied, but the route '{}' does not accept the reroute "
              + "parameter - rerouting to the error view instead", reroute.target());
          failClosed(event);
        }
      }
      case AccessDecision.RerouteWithParameters<?> reroute -> {
        try {
          event.rerouteTo(reroute.target(), reroute.parameters());
        } catch (RuntimeException unresolvable) {
          // JS-SEC-152: see RerouteWithParameter.
          logger().warn("Access was denied, but the route '{}' does not accept the reroute "
              + "parameters - rerouting to the error view instead", reroute.target());
          failClosed(event);
        }
      }
    }
  }

  /**
   * JS-SEC-152 (CWE-636): tells whether {@code route} names a registered server-side route,
   * the same way {@link BeforeEvent#rerouteTo(String)} resolves it. A name the router cannot
   * even parse counts as unresolved.
   *
   * @param event the navigation event whose router is asked
   * @param route the route name of the decision; may be {@code null}
   * @return {@code true} when a reroute or forward to {@code route} would set a target
   */
  static boolean resolves(BeforeEvent event, String route) {
    if (route == null) {
      return false;
    }
    try {
      return event.getSource().resolveNavigationTarget(new Location(route)).isPresent();
    } catch (RuntimeException invalidLocation) {
      return false;
    }
  }

  /**
   * JS-SEC-152 (CWE-636): tells whether {@code target} is registered as a route.
   * {@code BeforeEvent.forwardTo(Class)} accepts any class and fails only later, while
   * the forward is carried out.
   *
   * @param event  the navigation event whose router is asked
   * @param target the navigation target class; may be {@code null}
   * @return {@code true} when a route is registered for {@code target}
   */
  static boolean isRegistered(BeforeEvent event, Class<? extends Component> target) {
    if (target == null) {
      return false;
    }
    try {
      return event.getSource().getRegistry().getTemplate(target).isPresent();
    } catch (RuntimeException unreadable) {
      return false;
    }
  }

  /**
   * JS-SEC-152 (CWE-636): tells whether the event carries a target that makes Vaadin leave
   * the requested navigation target.
   *
   * @param event the navigation event
   * @return {@code true} when a reroute target, a forward target or an external forward is set
   */
  static boolean hasTarget(BeforeEvent event) {
    return event.hasRerouteTarget() || event.hasForwardTarget() || event.hasExternalForwardUrl();
  }

  /**
   * JS-SEC-152 (CWE-636): the fallback of every denial that could not be applied as
   * decided - reroute to the error view for {@link SecurityException} with a generic message.
   *
   * @param event the navigation event
   */
  static void failClosed(BeforeEvent event) {
    event.rerouteToError(new SecurityException(ACCESS_DENIED_MESSAGE), ACCESS_DENIED_MESSAGE);
  }
}
