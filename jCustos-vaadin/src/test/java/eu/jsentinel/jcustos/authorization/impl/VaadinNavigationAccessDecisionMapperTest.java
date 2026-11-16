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

import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecision;
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
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

@DisplayName("VaadinNavigationAccessDecisionMapper")
class VaadinNavigationAccessDecisionMapperTest {

  private final VaadinNavigationAccessDecisionMapper mapper =
      new VaadinNavigationAccessDecisionMapper();

  @Test
  @DisplayName("allowed does not change navigation")
  void allowed_doesNothing() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.allowed(),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertNull(event.forwardTarget);
    assertNull(event.forwardRoute);
    assertNull(event.rerouteRoute);
  }

  @Test
  @DisplayName("login required forwards to login target")
  void loginRequired_forwardsToLoginTarget() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.loginRequired(),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertEquals(TestLoginView.class, event.forwardTarget);
  }

  @Test
  @DisplayName("already logged in forwards to default target")
  void alreadyLoggedIn_forwardsToDefaultTarget() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.alreadyLoggedIn(),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertEquals(TestDefaultView.class, event.forwardTarget);
  }

  @Test
  @DisplayName("access denied with forward forwards to route")
  void accessDeniedAsForward_forwardsToRoute() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.accessDenied("login", true),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertEquals("login", event.forwardRoute);
  }

  @Test
  @DisplayName("access denied with reroute reroutes to route")
  void accessDeniedAsReroute_reroutesToRoute() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.accessDenied("login", false),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertEquals("login", event.rerouteRoute);
  }

  @Test
  @DisplayName("JS-SEC-152: access denied with a route that is not registered ends in rerouteToError")
  void accessDeniedToUnregisteredRoute_failsClosed() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.accessDenied("not-registered", false),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertNull(event.rerouteRoute,
        "rerouteTo(String) with an unknown route is a no-op in Vaadin and must not be relied on");
    assertInstanceOf(SecurityException.class, event.error);
  }

  @Test
  @DisplayName("JS-SEC-152: access denied as forward to a route that is not registered ends in rerouteToError")
  void accessDeniedAsForwardToUnregisteredRoute_failsClosed() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.accessDenied("not-registered", true),
        event,
        () -> TestLoginView.class,
        () -> TestDefaultView.class);

    assertNull(event.forwardRoute);
    assertInstanceOf(SecurityException.class, event.error);
  }

  @Test
  @DisplayName("JS-SEC-152: login required with a login view that is not a registered route ends in rerouteToError")
  void loginRequiredWithUnroutedLoginView_failsClosed() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.loginRequired(),
        event,
        () -> UnroutedLoginView.class,
        () -> TestDefaultView.class);

    assertNull(event.forwardTarget,
        "forwardTo(Class) accepts any class and only fails while the forward is carried out");
    assertInstanceOf(SecurityException.class, event.error);
  }

  @Test
  @DisplayName("JS-SEC-152: login required without a login view ends in rerouteToError")
  void loginRequiredWithoutLoginView_failsClosed() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();

    mapper.apply(
        NavigationAccessDecision.loginRequired(),
        event,
        () -> null,
        () -> TestDefaultView.class);

    assertNull(event.forwardTarget);
    assertInstanceOf(SecurityException.class, event.error);
  }

  @Test
  @DisplayName("allowed does not resolve navigation targets")
  void allowed_doesNotResolveTargets() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();
    AtomicInteger loginCalls = new AtomicInteger();
    AtomicInteger defaultCalls = new AtomicInteger();

    mapper.apply(
        NavigationAccessDecision.allowed(),
        event,
        () -> {
          loginCalls.incrementAndGet();
          return TestLoginView.class;
        },
        () -> {
          defaultCalls.incrementAndGet();
          return TestDefaultView.class;
        });

    assertEquals(0, loginCalls.get());
    assertEquals(0, defaultCalls.get());
  }

  @Test
  @DisplayName("login required only resolves login target")
  void loginRequired_onlyResolvesLoginTarget() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();
    AtomicInteger loginCalls = new AtomicInteger();
    AtomicInteger defaultCalls = new AtomicInteger();

    mapper.apply(
        NavigationAccessDecision.loginRequired(),
        event,
        () -> {
          loginCalls.incrementAndGet();
          return TestLoginView.class;
        },
        () -> {
          defaultCalls.incrementAndGet();
          return TestDefaultView.class;
        });

    assertEquals(1, loginCalls.get());
    assertEquals(0, defaultCalls.get());
  }

  @Test
  @DisplayName("already logged in only resolves default target")
  void alreadyLoggedIn_onlyResolvesDefaultTarget() {
    RecordingBeforeEnterEvent event = new RecordingBeforeEnterEvent();
    AtomicInteger loginCalls = new AtomicInteger();
    AtomicInteger defaultCalls = new AtomicInteger();

    mapper.apply(
        NavigationAccessDecision.alreadyLoggedIn(),
        event,
        () -> {
          loginCalls.incrementAndGet();
          return TestLoginView.class;
        },
        () -> {
          defaultCalls.incrementAndGet();
          return TestDefaultView.class;
        });

    assertEquals(0, loginCalls.get());
    assertEquals(1, defaultCalls.get());
  }

  private static final class RecordingBeforeEnterEvent extends BeforeEnterEvent {

    private Class<? extends Component> forwardTarget;
    private String forwardRoute;
    private String rerouteRoute;
    private Exception error;

    private RecordingBeforeEnterEvent() {
      super(
          new Router(new TestRouteRegistry()),
          NavigationTrigger.PROGRAMMATIC,
          new Location(""),
          TestDefaultView.class,
          new UI(),
          List.of());
    }

    @Override
    public void forwardTo(Class<? extends Component> navigationTarget) {
      this.forwardTarget = navigationTarget;
    }

    @Override
    public void rerouteToError(Exception exception, String customMessage) {
      this.error = exception;
    }

    @Override
    public void forwardTo(String location) {
      this.forwardRoute = location;
    }

    @Override
    public void rerouteTo(String route) {
      this.rerouteRoute = route;
    }
  }

  private static final class TestLoginView extends LoginView {

    @Override
    public void reactOnFailedLogin() {
    }

    @Override
    public void navigateToApp() {
    }

    @Override
    public boolean checkCredentials() {
      return false;
    }
  }

  /** A login view no route is registered for. */
  private static final class UnroutedLoginView extends LoginView {

    @Override
    public void reactOnFailedLogin() {
    }

    @Override
    public void navigateToApp() {
    }

    @Override
    public boolean checkCredentials() {
      return false;
    }
  }

  private static final class TestDefaultView extends Component {
  }

  /** The view an access-denied test sends the visitor to; not the navigation target. */
  private static final class TestDeniedView extends Component {
  }

  /**
   * A real registry holding the route the access-denied tests point to. Since JS-SEC-152
   * the mapper resolves the route before it reroutes; since JS-SEC-158 a route of the
   * navigation target itself ({@link TestDefaultView}) ends in the error view.
   */
  private static final class TestRouteRegistry extends AbstractRouteRegistry {

    TestRouteRegistry() {
      setRoute("login", TestDeniedView.class, List.of());
      setRoute("signin", TestLoginView.class, List.of());
    }

    @Override
    public VaadinContext getContext() {
      return null;
    }
  }
}
