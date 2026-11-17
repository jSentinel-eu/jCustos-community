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
package eu.jsentinel.jcustos.identity.oidc.vaadin;

import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockService;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.ServiceException;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.URI;
import java.time.Clock;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041, CWE-778), addition to ER30: the OIDC logout route audits
 * {@code LogoutPerformed} with the subject id of {@link CurrentSubject#subjectIdOf(Object)} -
 * the resolver's value, else the identity handle - the same id the session policy's
 * {@code SessionInvalidated} of the same logout carries. Until 00.84.00 the view derived the
 * id itself and wrote an empty one without a working resolver. The subject's
 * {@code toString()} never appears.
 */
@DisplayName("JS-SEC-097 - the OIDC logout audits the facade's subject id, never empty, never toString()")
class OidcLogoutSubjectIdParityTest {

  private static final String SECRET = "pw-SECRET-4711";

  /** An application user whose toString() carries a credential - the leak shape. */
  record PiiUser(String email, String password) {
    @Override
    public String toString() {
      return "PiiUser[email=" + email + ", password=" + password + "]";
    }
  }

  /** What the application registered as {@code SubjectIdResolver}. */
  enum ResolverSetup { RESOLVER, NONE, FAILING, NO_ID }

  private final PiiUser alice = new PiiUser("alice@example.test", SECRET);
  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final VaadinSessionSubjectStore subjects = new VaadinSessionSubjectStore();
  /** Strong references: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private UI ui;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(PiiUser.class));
    JCustosServiceResolver.setSessionPolicy(
        new TimeoutSessionPolicy<>(TimeoutSessionPolicy.Config.defaults(), Clock.systemUTC(), audit));
    SubjectStores.setSubjectStore(subjects);

    Routes routes = new Routes();
    routes.getRoutes().add(LogoutView.class);
    MockVaadin.setup(MockedUI::new, new PlainSessionServlet(routes));
    session = VaadinSession.getCurrent();
    ui = UI.getCurrent();
    subjects.setCurrentSubject(alice, PiiUser.class);
    audit.clear();
  }

  @AfterEach
  void stop() {
    try {
      MockVaadin.tearDown();
    } finally {
      JCustosServiceResolver.resetAll();
      SubjectStores.reset();
    }
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(ResolverSetup.class)
  @DisplayName("LogoutPerformed carries the facade's id - the same as the policy's SessionInvalidated")
  void logoutAuditsTheFacadesSubjectId(ResolverSetup setup) {
    switch (setup) {
      case RESOLVER -> JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
      case FAILING -> JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> {
        throw new IllegalStateException("directory unavailable for " + user);
      });
      case NO_ID -> JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> null);
      case NONE -> { /* the identity handle */ }
      default -> throw new IllegalArgumentException(setup.name());
    }
    String expected = setup == ResolverSetup.RESOLVER
        ? "user-7"
        : PiiUser.class.getSimpleName() + "@" + Integer.toHexString(System.identityHashCode(alice));
    assertEquals(expected, CurrentSubject.subjectIdOf(alice), "precondition: the facade's rule");

    ui.navigate(AbstractOidcLogoutView.logoutLocation(LogoutView.class));

    String logoutId = audit.single(LogoutPerformed.class).subjectId();
    assertEquals(expected, logoutId);
    assertEquals(logoutId, audit.single(SessionInvalidated.class).subjectId(),
        "one logout, one subject id: the view and the session policy agree");
    assertFalse(logoutId.contains(SECRET), logoutId);
    assertFalse(logoutId.contains("alice@example.test"), logoutId);
    assertNull(session.getAttribute(PiiUser.class), "the subject is removed");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the session is closed");
  }

  @Test
  @DisplayName("a subject store that cannot be read: no subject to audit, the session still ends")
  void unreadableSubjectStore_stillEndsTheSession() {
    // entered while the store works - a navigation with a failing store is stopped by the
    // session-lifetime check (XR05) - and confirmed after it failed
    ui.navigate(LogoutView.class);
    Button confirm = confirmButton();
    SubjectStores.setSubjectStore(new UnreadableSubjectStore());

    confirm.click();

    assertTrue(audit.events().stream().noneMatch(LogoutPerformed.class::isInstance),
        "without a readable subject there is nobody to name in LogoutPerformed");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the session is closed regardless");
  }

  private Button confirmButton() {
    return ui.getInternals().getActiveRouterTargetsChain().get(0).getElement().getChildren()
        .map(element -> element.getComponent().orElse(null))
        .filter(Button.class::isInstance)
        .map(Button.class::cast)
        .filter(button -> AbstractOidcLogoutView.CONFIRM_BUTTON_ID.equals(button.getId().orElse(null)))
        .findFirst()
        .orElseThrow();
  }

  // ── fixtures ───────────────────────────────────────────────────

  @Route("er30/logout")
  public static class LogoutView extends AbstractOidcLogoutView {
    @Override protected URI endSessionEndpoint() {
      return URI.create("https://idp.example/oidc/logout");
    }

    @Override protected LogoutRequest logoutRequest() {
      return new LogoutRequest("ID-TOKEN", Optional.empty(), Optional.empty());
    }
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

  /** The real servlet service, creating plain sessions instead of self-recreating ones. */
  private static final class PlainSessionServlet extends MockVaadinServlet {
    PlainSessionServlet(Routes routes) {
      super(routes, MockedUI::new);
    }

    @Override
    protected VaadinServletService createServletService(DeploymentConfiguration configuration) {
      VaadinServletService service = new MockService(this, configuration, MockedUI::new) {
        @Override
        protected VaadinSession createVaadinSession(VaadinRequest request) {
          return new VaadinSession(this);
        }
      };
      try {
        service.init();
      } catch (ServiceException e) {
        throw new IllegalStateException(e);
      }
      getRoutes().register((VaadinServletContext) service.getContext());
      return service;
    }
  }
}
