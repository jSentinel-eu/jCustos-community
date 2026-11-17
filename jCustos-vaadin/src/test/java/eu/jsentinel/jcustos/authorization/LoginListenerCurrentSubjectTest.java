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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041), addition to ER30: {@link LoginListener} reads the current subject
 * through {@link CurrentSubject}. With and without a {@code SubjectIdResolver} it decides as
 * the facade sees the subject; a subject store or authentication service that fails reads as
 * "no subject", so a restricted target goes to the login view - until 00.84.00 the lookup
 * threw out of the navigation.
 */
@DisplayName("JS-SEC-097 - LoginListener asks CurrentSubject; an unreadable subject is no subject")
class LoginListenerCurrentSubjectTest {

  private static final String SECRET = "pw-SECRET-4711";

  /** An application user whose toString() carries a credential - the leak shape. */
  record PiiUser(String email, String password) {
    @Override
    public String toString() {
      return "PiiUser[email=" + email + ", password=" + password + "]";
    }
  }

  private final PiiUser alice = new PiiUser("alice@example.test", SECRET);
  private final InMemorySubjectStore subjects = new InMemorySubjectStore();
  private final FixtureLoginListener listener = new FixtureLoginListener();

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    CurrentInstance.clearAll();
    SubjectStores.setSubjectStore(subjects);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(PiiUser.class));
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    CurrentInstance.clearAll();
  }

  @ParameterizedTest(name = "resolver registered: {0}")
  @ValueSource(booleans = {true, false})
  @DisplayName("a bound subject passes a restricted target; an anonymous visitor is forwarded to the login view")
  void decidesAsTheFacadeSeesTheSubject(boolean withResolver) {
    if (withResolver) {
      JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
    }

    RecordingEvent anonymous = new RecordingEvent(RestrictedTarget.class);
    listener.beforeEnter(anonymous);
    assertSame(SigninView.class, anonymous.forwardTarget);

    subjects.setCurrentSubject(alice, PiiUser.class);
    assertTrue(CurrentSubject.current().isPresent(), "precondition: the facade sees the subject");
    RecordingEvent bound = new RecordingEvent(RestrictedTarget.class);
    listener.beforeEnter(bound);
    assertNull(bound.forwardTarget, "the bound subject is let through");
  }

  @Test
  @DisplayName("a subject store that cannot be read: forwarded to the login view, never past it")
  void unreadableSubjectStore_forwardsToTheLoginView() {
    SubjectStores.setSubjectStore(new UnreadableSubjectStore());
    RecordingEvent event = new RecordingEvent(RestrictedTarget.class);

    assertDoesNotThrow(() -> listener.beforeEnter(event),
        "until 00.84.00 the store failure escaped the navigation");

    assertSame(SigninView.class, event.forwardTarget);
  }

  @Test
  @DisplayName("an authentication service that cannot name the subject type: forwarded to the login view")
  void failingAuthenticationService_forwardsToTheLoginView() {
    JCustosServiceResolver.setAuthenticationService(new FailingAuthenticationService());
    RecordingEvent event = new RecordingEvent(RestrictedTarget.class);

    assertDoesNotThrow(() -> listener.beforeEnter(event));

    assertSame(SigninView.class, event.forwardTarget);
  }

  // ── fixtures ───────────────────────────────────────────────────

  @RequiresRole("ROLE_ADMIN")
  static class RestrictedTarget extends Component { }

  static class HomeTarget extends Component { }

  static class SigninView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { /* noop */ }
    @Override public void reactOnFailedLogin() { /* noop */ }
  }

  private static final class FixtureLoginListener extends LoginListener<PiiUser> {
    @Override public void notARestrictedTarget(Class<?> navigationTarget) { /* not used */ }
    @Override public Class<? extends LoginView> loginNavigationTarget() { return SigninView.class; }
    @Override public Class<? extends Component> defaultNavigationTarget() { return HomeTarget.class; }
  }

  /** A subject store whose backend is down. */
  private static final class UnreadableSubjectStore implements SubjectStore {
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      throw new IllegalStateException("subject store unavailable");
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      throw new IllegalStateException("subject store unavailable");
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      throw new IllegalStateException("subject store unavailable");
    }
  }

  /** An authentication service whose backend is down. */
  private static final class FailingAuthenticationService implements AuthenticationService<String, PiiUser> {
    @Override public boolean checkCredentials(String credentials) { return false; }
    @Override public PiiUser loadSubject(String credentials) { return null; }
    @Override public Class<PiiUser> subjectType() {
      throw new IllegalStateException("authentication backend unavailable");
    }
  }

  private static final class RecordingEvent extends BeforeEnterEvent {
    Class<? extends Component> forwardTarget;

    RecordingEvent(Class<? extends Component> navigationTarget) {
      super(new Router(new TestRouteRegistry()), NavigationTrigger.PROGRAMMATIC, new Location(""),
          navigationTarget, new UI(), List.of());
    }

    @Override public void forwardTo(Class<? extends Component> navigationTarget) {
      this.forwardTarget = navigationTarget;
    }
  }

  /** A registry that knows the login view: the decision mapper forwards only to a route. */
  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    TestRouteRegistry() {
      setRoute("signin", SigninView.class, List.of());
    }

    @Override public VaadinContext getContext() { return null; }
  }
}
