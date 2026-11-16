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
import com.vaadin.flow.router.NavigationHandler;
import com.vaadin.flow.router.NavigationState;
import com.vaadin.flow.router.RouteParameters;

import java.util.Optional;

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
 * <p>
 * <strong>No denial to the denied view itself (JS-SEC-158, CWE-636, CWE-285):</strong> Vaadin
 * carries out a reroute or forward only when its target differs from the navigation in
 * progress. A target with the class and the route parameters of the navigation target is
 * skipped, and the navigation target is rendered - the view the decision denied. Such a
 * target therefore counts as no target: the mapper answers it with the error view, and
 * {@link #hasTarget(BeforeEvent)} does not count it. A reroute to a <em>different</em> route
 * is carried out and evaluated again on its own navigation, so a denial that points into the
 * same restricted layout ends in the error view one navigation later.
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
   * reroute or forward target. If the route a decision names is not registered, resolves to
   * the navigation target itself, or the reroute cannot be built, the event is rerouted to
   * the error view for {@link SecurityException}.
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
        Optional<NavigationState> target = resolve(event, route);
        if (target.isEmpty()) {
          logger().warn("Access was denied, but the route '{}' the decision points to is not "
              + "registered - rerouting to the error view instead", route);
          failClosed(event);
        } else if (isNavigationTarget(event, target.get())) {
          // JS-SEC-158 (CWE-636, CWE-285): Vaadin skips a reroute or forward to the navigation
          // in progress and renders the view that was just denied.
          logSelfTarget(route);
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
        failClosedIfRoutedToItself(event, reroute.target());
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
        failClosedIfRoutedToItself(event, reroute.target());
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
    return resolve(event, route).isPresent();
  }

  /**
   * Resolves {@code route} to the navigation state a reroute or forward to it would set,
   * the same way {@link BeforeEvent#rerouteTo(String)} does.
   *
   * @param event the navigation event whose router is asked
   * @param route the route name of the decision; may be {@code null}
   * @return the target state; empty when the name is {@code null}, unparsable or unknown
   */
  static Optional<NavigationState> resolve(BeforeEvent event, String route) {
    if (route == null) {
      return Optional.empty();
    }
    try {
      return event.getSource().resolveNavigationTarget(new Location(route));
    } catch (RuntimeException invalidLocation) {
      return Optional.empty();
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
   * <p>
   * JS-SEC-158 (CWE-636, CWE-285): a reroute or forward target with the class and the route
   * parameters of the navigation target does not count. Vaadin's navigation skips it
   * ({@code AbstractNavigationStateRenderer.handleTriggeredBeforeEvent}) and renders the
   * navigation target, so for a denial it is as good as no target at all.
   *
   * @param event the navigation event
   * @return {@code true} when an external forward, or a reroute or forward target other than
   *     the navigation target itself, is set
   */
  static boolean hasTarget(BeforeEvent event) {
    return event.hasExternalForwardUrl()
        || (event.hasForwardTarget() && !isNavigationTarget(event,
            event.getForwardTargetType(), event.getForwardTargetRouteParameters()))
        || (event.hasRerouteTarget() && !isNavigationTarget(event,
            event.getRerouteTargetType(), event.getRerouteTargetRouteParameters()));
  }

  /**
   * JS-SEC-158 (CWE-636, CWE-285): tells whether a navigation state is the navigation target
   * of {@code event} itself.
   *
   * @param event the navigation event
   * @param state the state a reroute or forward would set
   * @return {@code true} when Vaadin would skip a reroute or forward to {@code state}
   */
  static boolean isNavigationTarget(BeforeEvent event, NavigationState state) {
    return isNavigationTarget(event, state.getNavigationTarget(), state.getRouteParameters());
  }

  /**
   * JS-SEC-158 (CWE-636, CWE-285): tells whether a target class with its route parameters is
   * the navigation target of {@code event} itself - the comparison Vaadin makes before it
   * carries out a reroute or forward. A missing parameter set counts as empty.
   *
   * @param event      the navigation event
   * @param target     the class of the reroute or forward target; may be {@code null}
   * @param parameters the route parameters of that target; may be {@code null}
   * @return {@code true} when the target is the navigation in progress
   */
  static boolean isNavigationTarget(BeforeEvent event, Class<? extends Component> target,
                                    RouteParameters parameters) {
    if (target == null || !target.equals(event.getNavigationTarget())) {
      return false;
    }
    RouteParameters own = event.getRouteParameters() == null
        ? RouteParameters.empty() : event.getRouteParameters();
    return (parameters == null ? RouteParameters.empty() : parameters).equals(own);
  }

  /**
   * JS-SEC-158: answers a reroute that a parameterised decision set to the navigation target
   * itself with the error view.
   */
  private void failClosedIfRoutedToItself(BeforeEvent event, String route) {
    if (event.hasRerouteTarget() && isNavigationTarget(event,
        event.getRerouteTargetType(), event.getRerouteTargetRouteParameters())) {
      logSelfTarget(route);
      failClosed(event);
    }
  }

  private void logSelfTarget(String route) {
    logger().warn("Access was denied, but the route '{}' the decision points to is the denied "
        + "view itself - rerouting to the error view instead", route);
  }

  /**
   * JS-SEC-152 (CWE-636): the fallback of every denial that could not be applied as
   * decided - reroute to the error view for {@link SecurityException} with a generic message.
   * A forward target set before is cleared (JS-SEC-158): Vaadin refuses an event that carries
   * a forward and a reroute target at the same time.
   *
   * @param event the navigation event
   */
  static void failClosed(BeforeEvent event) {
    if (event.hasForwardTarget()) {
      event.forwardTo((NavigationHandler) null, (NavigationState) null);
    }
    event.rerouteToError(new SecurityException(ACCESS_DENIED_MESSAGE), ACCESS_DENIED_MESSAGE);
  }
}
