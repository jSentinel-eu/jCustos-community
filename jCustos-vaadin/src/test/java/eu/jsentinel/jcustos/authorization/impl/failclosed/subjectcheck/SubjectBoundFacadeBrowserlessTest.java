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
package eu.jsentinel.jcustos.authorization.impl.failclosed.subjectcheck;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.impl.AuthorizationListener;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041), addition to ER30: the subject check with which the authorisation
 * listener decides whether it may forward a denied visitor to the {@link LoginListener}'s
 * login view (JS-SEC-152) goes through {@link CurrentSubject}, and keeps its meaning -
 * "cannot tell" counts as bound, so a visitor whose state is unknown ends in the error view
 * instead of being sent to a login form.
 * <p>
 * The navigation cases run through {@code UI.navigate} over the router and the route
 * registry of this package; the evaluator of {@link DemandsLogin} denies every visitor with
 * a reroute to the login route, which is not registered, so the listener's subject check
 * decides. The failure cases ask the check itself: on a navigation the session-lifetime
 * listener reads the subject store first and fails the request on its own (exit review
 * XR05), which would hide what the authorisation listener decides.
 */
@DisplayName("JS-SEC-097 - the LoginListener fallback asks CurrentSubject; \"cannot tell\" still counts as bound")
@ViewPackages
class SubjectBoundFacadeBrowserlessTest extends BrowserlessTest {

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
  private final FixtureLoginListener loginListener = new FixtureLoginListener();

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(subjects);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(PiiUser.class));
    LoginListeners.setLoginListener(loginListener);
    ProtectedView.INSTANCES.set(0);
    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    LoginListeners.reset();
  }

  // ── navigation: the same decision with and without a resolver ──

  @ParameterizedTest(name = "resolver registered: {0}")
  @ValueSource(booleans = {true, false})
  @DisplayName("a bound subject is not sent to the login view: error view, the protected view is never created")
  void boundSubject_endsInTheErrorView(boolean withResolver) {
    if (withResolver) {
      JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
    }
    subjects.setCurrentSubject(alice, PiiUser.class);
    assertTrue(CurrentSubject.current().isPresent(), "precondition: the facade sees the subject");

    UI.getCurrent().navigate("fc-subjectcheck/protected");

    assertEquals(0, ProtectedView.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeView());
  }

  @ParameterizedTest(name = "resolver registered: {0}")
  @ValueSource(booleans = {true, false})
  @DisplayName("an anonymous visitor is forwarded to the LoginListener's login view")
  void anonymous_isForwardedToTheLoginView(boolean withResolver) {
    if (withResolver) {
      JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
    }

    UI.getCurrent().navigate("fc-subjectcheck/protected");

    assertEquals(0, ProtectedView.INSTANCES.get());
    assertInstanceOf(SigninView.class, activeView());
  }

  // ── the check itself: what "cannot tell" means ─────────────────

  @Test
  @DisplayName("bound and anonymous: the check agrees with CurrentSubject")
  void subjectCheck_agreesWithTheFacade() throws Exception {
    assertFalse(subjectBound(), "nobody bound");
    subjects.setCurrentSubject(alice, PiiUser.class);
    assertTrue(subjectBound(), "alice bound");
  }

  @Test
  @DisplayName("a subject store that cannot be read counts as bound")
  void unreadableSubjectStore_countsAsBound() throws Exception {
    SubjectStores.setSubjectStore(new UnreadableSubjectStore());
    assertTrue(CurrentSubject.current().isEmpty(),
        "precondition: the lenient read reports \"no subject\" - the reading this check must not use");

    assertTrue(subjectBound(), "a store failure must not send the visitor to the login view");
  }

  @Test
  @DisplayName("an authentication service that cannot name the subject type counts as bound")
  void unknownSubjectType_countsAsBound() throws Exception {
    JCustosServiceResolver.setAuthenticationService(new FailingAuthenticationService());
    assertTrue(subjectBound(), "a failing authentication service");

    JCustosServiceResolver.setAuthenticationService(new UntypedAuthenticationService());
    assertTrue(subjectBound(), "an authentication service without a subject type");
  }

  // ── helpers ────────────────────────────────────────────────────

  private static HasElement activeView() {
    List<HasElement> chain = UI.getCurrent().getInternals().getActiveRouterTargetsChain();
    assertFalse(chain.isEmpty(), "a view must be active after the navigation");
    return chain.get(0);
  }

  private static boolean subjectBound() throws Exception {
    Method check = AuthorizationListener.class.getDeclaredMethod("subjectBound");
    check.setAccessible(true);
    return (boolean) check.invoke(null);
  }

  // ── fixtures ───────────────────────────────────────────────────

  /** Denies every visitor with a reroute to the login route. */
  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @JCustosAnnotation(DemandsLoginEvaluator.class)
  public @interface DemandsLogin {
  }

  /** Evaluator of {@link DemandsLogin}; instantiated by Vaadin's instantiator. */
  public static class DemandsLoginEvaluator implements AccessEvaluator<DemandsLogin> {
    @Override
    public AccessDecision evaluate(AccessContext context, DemandsLogin annotation) {
      return AccessDecision.denied(JCustosServiceResolver.loginRouteName(), false);
    }
  }

  @Route("fc-subjectcheck/protected")
  @DemandsLogin
  public static class ProtectedView extends Div {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public ProtectedView() {
      INSTANCES.incrementAndGet();
    }
  }

  /** The application's login view, registered under a name the resolver does not know. */
  @Route("fc-subjectcheck/signin")
  public static class SigninView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { /* not used */ }
    @Override public void reactOnFailedLogin() { /* not used */ }
  }

  @Route("fc-subjectcheck/home")
  public static class HomeView extends Div {
  }

  private static final class FixtureLoginListener extends LoginListener<PiiUser> {
    @Override public void notARestrictedTarget(Class<?> navigationTarget) { /* not used */ }
    @Override public Class<? extends LoginView> loginNavigationTarget() { return SigninView.class; }
    @Override public Class<? extends Component> defaultNavigationTarget() { return HomeView.class; }
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

  /** An authentication service that names no subject type. */
  private static final class UntypedAuthenticationService implements AuthenticationService<String, PiiUser> {
    @Override public boolean checkCredentials(String credentials) { return false; }
    @Override public PiiUser loadSubject(String credentials) { return null; }
    @Override public Class<PiiUser> subjectType() { return null; }
  }
}
