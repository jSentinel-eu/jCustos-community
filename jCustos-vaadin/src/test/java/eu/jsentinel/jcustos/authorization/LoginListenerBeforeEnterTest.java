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
package eu.jsentinel.jcustos.authorization;

import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.router.NavigationTrigger;
import com.vaadin.flow.router.Router;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Pins the branch matrix of {@link LoginListener#beforeEnter}: the
 * (isRestricted × subjectAvailable × isLoginView) combinations plus the
 * "not a restricted target" callback. The decisionMapper outcome
 * (forward / no-op) is captured through a {@link RecordingEvent}.
 */
@DisplayName("LoginListener — beforeEnter branch matrix")
class LoginListenerBeforeEnterTest {

  private final InMemorySubjectStore store = new InMemorySubjectStore();
  private final TestLoginListener listener = new TestLoginListener();

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(store);
    // SPI provides StubAuthenticationService (registered for tests),
    // so subjectType() resolves to String.class.
    CurrentInstance.clearAll();
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    CurrentInstance.clearAll();
  }

  // ── Restricted target ──────────────────────────────────────────

  @Test
  @DisplayName("restricted target without a subject is forwarded to the login view")
  void restrictedNoSubject_forwardsToLogin() {
    RecordingEvent event = new RecordingEvent(RestrictedTarget.class);

    listener.beforeEnter(event);

    assertSame(StubLoginView.class, event.forwardTarget,
        "restricted target + no subject must forward to the login view");
    assertNull(listener.lastUnrestrictedTarget,
        "notARestrictedTarget must NOT be invoked for an annotated target");
  }

  @Test
  @DisplayName("restricted target with a subject is allowed (no forward)")
  void restrictedWithSubject_allowed() {
    store.setCurrentSubject("alice", String.class);
    RecordingEvent event = new RecordingEvent(RestrictedTarget.class);

    listener.beforeEnter(event);

    assertNull(event.forwardTarget,
        "an authenticated subject hitting a restricted target must not be forwarded");
    assertNull(listener.lastUnrestrictedTarget,
        "notARestrictedTarget must NOT be invoked when the target IS restricted");
  }

  // ── Unrestricted target ────────────────────────────────────────

  @Test
  @DisplayName("unrestricted target invokes the notARestrictedTarget callback")
  void unrestrictedTarget_invokesCallback() {
    RecordingEvent event = new RecordingEvent(UnrestrictedTarget.class);

    listener.beforeEnter(event);

    assertSame(UnrestrictedTarget.class, listener.lastUnrestrictedTarget,
        "notARestrictedTarget must be invoked with the target class for unannotated targets");
    assertNull(event.forwardTarget,
        "unrestricted target must not be forwarded");
  }

  @Test
  @DisplayName("login view target itself: no forwardTo even without a subject")
  void loginViewTarget_doesNotForwardToItself() {
    RecordingEvent event = new RecordingEvent(StubLoginView.class);

    listener.beforeEnter(event);

    assertNull(event.forwardTarget,
        "navigating to the login view itself must not produce a forward to the login view");
  }

  // ── Repeat with subject to pin the boolean isRestrictedTarget paths ──

  @Test
  @DisplayName("unrestricted target with a subject still invokes notARestrictedTarget")
  void unrestrictedTargetWithSubject_invokesCallback() {
    store.setCurrentSubject("alice", String.class);
    RecordingEvent event = new RecordingEvent(UnrestrictedTarget.class);

    listener.beforeEnter(event);

    assertSame(UnrestrictedTarget.class, listener.lastUnrestrictedTarget,
        "callback must fire even when the subject is present, as long as the target is unannotated");
    assertNull(event.forwardTarget,
        "unrestricted target must not be forwarded even with a subject");
  }

  // ── Fixtures ──────────────────────────────────────────────────

  @RequiresRole("ROLE_ADMIN")
  static class RestrictedTarget extends Component { }

  static class UnrestrictedTarget extends Component { }

  static class StubLoginView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { /* noop */ }
    @Override public void reactOnFailedLogin() { /* noop */ }
  }

  private static final class TestLoginListener extends LoginListener<String> {
    Class<?> lastUnrestrictedTarget;
    @Override public void notARestrictedTarget(Class<?> navigationTarget) {
      this.lastUnrestrictedTarget = navigationTarget;
    }
    @Override public Class<? extends LoginView> loginNavigationTarget() {
      return StubLoginView.class;
    }
    @Override public Class<? extends Component> defaultNavigationTarget() {
      return UnrestrictedTarget.class;
    }
  }

  private static final class RecordingEvent extends BeforeEnterEvent {
    Class<? extends Component> forwardTarget;
    Class<?> rerouteTarget;

    RecordingEvent(Class<? extends Component> navigationTarget) {
      super(
          new Router(new TestRouteRegistry()),
          NavigationTrigger.PROGRAMMATIC,
          new Location(""),
          navigationTarget,
          new UI(),
          List.of());
    }

    @Override public void forwardTo(Class<? extends Component> navigationTarget) {
      this.forwardTarget = navigationTarget;
    }

    @Override public void rerouteTo(Class<? extends Component> navigationTarget) {
      this.rerouteTarget = navigationTarget;
    }
  }

  /**
   * A real registry that knows the login view. Since JS-SEC-152 the decision mapper
   * forwards to the login view only when it is a registered route.
   */
  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    TestRouteRegistry() {
      setRoute("login", StubLoginView.class, List.of());
    }

    @Override public VaadinContext getContext() { return null; }
  }

  @SuppressWarnings("unused")
  private static void assertEqualsHint() {
    // keep assertEquals import in case future assertions want it
    assertEquals(1, 1);
  }
}
