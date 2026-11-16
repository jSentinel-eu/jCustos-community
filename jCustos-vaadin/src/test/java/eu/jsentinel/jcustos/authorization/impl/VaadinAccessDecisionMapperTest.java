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

import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.router.NavigationTrigger;
import com.vaadin.flow.router.Router;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("VaadinAccessDecisionMapper")
class VaadinAccessDecisionMapperTest {

  private final VaadinAccessDecisionMapper mapper = new VaadinAccessDecisionMapper();

  @Test
  @DisplayName("Granted: no navigation operation is invoked")
  void granted() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.Granted(), event);

    assertNull(event.forwardRoute);
    assertNull(event.rerouteRoute);
    assertNull(event.errorType);
    assertNull(event.errorInstance);
  }

  @Test
  @DisplayName("Reroute(asForward = true) calls forwardTo(String)")
  void rerouteAsForward() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.Reroute("admin", true), event);

    assertEquals("admin", event.forwardRoute);
    assertNull(event.rerouteRoute);
  }

  @Test
  @DisplayName("Reroute(asForward = false) calls rerouteTo(String)")
  void rerouteAsReroute() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.Reroute("login", false), event);

    assertEquals("login", event.rerouteRoute);
    assertNull(event.forwardRoute);
  }

  @Test
  @DisplayName("JS-SEC-152: Reroute to a route that is not registered ends in rerouteToError(SecurityException)")
  void rerouteToUnregisteredRoute_failsClosed() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.Reroute("not-registered", false), event);

    assertNull(event.rerouteRoute,
        "rerouteTo(String) with an unknown route is a no-op in Vaadin and must not be relied on");
    assertNull(event.forwardRoute);
    assertInstanceOf(SecurityException.class, event.errorInstance,
        "an unresolvable reroute target must fall back to the error view");
    assertEquals("Access denied", event.errorMessage,
        "the user-facing message stays generic");
  }

  @Test
  @DisplayName("JS-SEC-152: Reroute(asForward = true) to a route that is not registered ends in rerouteToError")
  void forwardToUnregisteredRoute_failsClosed() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.Reroute("not-registered", true), event);

    assertNull(event.forwardRoute,
        "forwardTo(String) with an unknown route only records a client-side forward");
    assertInstanceOf(SecurityException.class, event.errorInstance);
  }

  @Test
  @DisplayName("JS-SEC-152: a route name the router cannot parse counts as not registered")
  void rerouteToInvalidLocation_failsClosed() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.Reroute("/../login", false), event);

    assertNull(event.rerouteRoute);
    assertInstanceOf(SecurityException.class, event.errorInstance);
  }

  @Test
  @DisplayName("JS-SEC-152: RerouteWithParameter that cannot be built ends in rerouteToError")
  void rerouteWithParameterFailure_failsClosed() {
    RecordingEvent event = new RecordingEvent();
    event.failParameterReroute = true;

    mapper.apply(new AccessDecision.RerouteWithParameter<>("docs", 42), event);

    assertInstanceOf(SecurityException.class, event.errorInstance,
        "an IllegalArgumentException from rerouteTo(route, parameter) must not end the denial");
  }

  @Test
  @DisplayName("JS-SEC-152: RerouteWithParameters that cannot be built ends in rerouteToError")
  void rerouteWithParametersFailure_failsClosed() {
    RecordingEvent event = new RecordingEvent();
    event.failParameterReroute = true;

    mapper.apply(new AccessDecision.RerouteWithParameters<>("docs", List.of("a", "b")), event);

    assertInstanceOf(SecurityException.class, event.errorInstance);
  }

  @Test
  @DisplayName("RerouteToError without message calls rerouteToError(Class)")
  void rerouteToErrorByType() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.RerouteToError(IllegalAccessException.class, null), event);

    assertSame(IllegalAccessException.class, event.errorType);
    assertNull(event.errorInstance);
    assertNull(event.errorMessage);
  }

  @Test
  @DisplayName("RerouteToError with message instantiates the exception and forwards the message")
  void rerouteToErrorWithMessage() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.RerouteToError(RuntimeException.class, "no access"), event);

    assertTrue(event.errorInstance instanceof RuntimeException,
        "exception class must be reflectively instantiated");
    assertEquals("no access", event.errorMessage);
  }

  @Test
  @DisplayName("RerouteToError with message: instantiation failure falls back to RuntimeException wrapper")
  void rerouteToErrorInstantiationFallback() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.RerouteToError(NoNoArgException.class, "boom"), event);

    assertTrue(event.errorInstance instanceof RuntimeException,
        "fallback path must still surface a RuntimeException");
    assertEquals("Access denied",
        ((Throwable) event.errorInstance).getMessage(),
        "fallback exception message must be 'Access denied'");
    assertEquals("boom", event.errorMessage);
  }

  @Test
  @DisplayName("RerouteWithParameter forwards the single parameter to rerouteTo")
  void rerouteWithParameter() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.RerouteWithParameter<>("docs", 42), event);

    assertEquals("docs", event.rerouteRoute);
    assertEquals(42, event.singleParameter);
  }

  @Test
  @DisplayName("RerouteWithParameters forwards the parameter list to rerouteTo")
  void rerouteWithParameters() {
    RecordingEvent event = new RecordingEvent();

    mapper.apply(new AccessDecision.RerouteWithParameters<>("docs", List.of("a", "b")), event);

    assertEquals("docs", event.rerouteRoute);
    assertEquals(List.of("a", "b"), event.parameters);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  /** Exception with no public no-arg constructor — drives the reflection-failure path. */
  static final class NoNoArgException extends Exception {
    @SuppressWarnings("unused")
    public NoNoArgException(String required) {
      super(required);
    }
  }

  private static final class RecordingEvent extends BeforeEnterEvent {

    String forwardRoute;
    String rerouteRoute;
    Class<? extends Exception> errorType;
    Object errorInstance;
    String errorMessage;
    Object singleParameter;
    List<?> parameters;
    boolean failParameterReroute;

    private RecordingEvent() {
      super(
          new Router(new TestRouteRegistry()),
          NavigationTrigger.PROGRAMMATIC,
          new Location(""),
          DummyTarget.class,
          new UI(),
          List.of());
    }

    @Override public void forwardTo(String location) { this.forwardRoute = location; }
    @Override public void rerouteTo(String route)    { this.rerouteRoute = route; }
    @Override public <T> void rerouteTo(String route, T parameter) {
      failIfRequested(route);
      this.rerouteRoute = route;
      this.singleParameter = parameter;
    }
    @Override public <T> void rerouteTo(String route, List<T> parameters) {
      failIfRequested(route);
      this.rerouteRoute = route;
      this.parameters = parameters;
    }
    /** Vaadin's own answer when no route accepts the parameters. */
    private void failIfRequested(String route) {
      if (failParameterReroute) {
        throw new IllegalArgumentException(
            "No route '" + route + "' accepting the parameters was found.");
      }
    }
    @Override public void rerouteToError(Class<? extends Exception> type) {
      this.errorType = type;
    }
    @Override public void rerouteToError(Exception exception, String message) {
      this.errorInstance = exception;
      this.errorMessage = message;
    }
  }

  /**
   * A real registry holding the two routes the reroute tests point to. Since JS-SEC-152
   * the mapper resolves the route before it reroutes, so an empty registry would turn
   * every named reroute into the fail-closed fallback. Since JS-SEC-158 a route of the
   * navigation target itself ({@link DummyTarget}) is answered with the error view, so the
   * routes belong to classes of their own.
   */
  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    TestRouteRegistry() {
      setRoute("admin", AdminTarget.class, List.of());
      setRoute("login", LoginTarget.class, List.of());
    }

    @Override public VaadinContext getContext() { return null; }
  }

  /** The navigation target of every recorded event. */
  static class DummyTarget extends Component {
  }

  static class AdminTarget extends Component {
  }

  static class LoginTarget extends Component {
  }
}
