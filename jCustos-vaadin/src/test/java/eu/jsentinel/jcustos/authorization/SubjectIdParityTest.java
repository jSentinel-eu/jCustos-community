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

import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.impl.VaadinAccessContextFactory;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimeListener;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.router.NavigationTrigger;
import com.vaadin.flow.router.Router;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * JS-SEC-097 (CWE-1041, CWE-532), acceptance of ER30: the same subject yields the same
 * subject id in the navigation context of the authorisation listener, in
 * {@link SecuredVisibility}, in the {@link SessionLifetimeListener} (the metadata its policy
 * evaluates and the {@code SessionExpired} event) and in the audit of the session rotation
 * after a login - with a registered {@code SubjectIdResolver} the resolver value, without
 * one the identity handle. None of them carries the subject's {@code toString()}.
 * <p>
 * Until 00.84.00 the navigation and the lifetime listener fell back to the identity handle,
 * the login rotation to an empty string. The policy context of the starter's
 * {@code SecuredUi} is compared with the navigation context and {@code SecuredVisibility} in
 * the starter's {@code SubjectIdParityTest}.
 */
@DisplayName("JS-SEC-097 - one subject id in navigation, secured components, session lifetime and login rotation")
class SubjectIdParityTest {

  private static final String SECRET = "pw-SECRET-4711";
  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");

  /** An application user whose toString() carries a credential - the leak shape. */
  record PiiUser(String email, String password) {
    @Override
    public String toString() {
      return "PiiUser[email=" + email + ", password=" + password + "]";
    }
  }

  private final PiiUser alice = new PiiUser("alice@example.test", SECRET);
  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final List<String> sessionMetadataIds = new ArrayList<>();

  /** Strong reference: Vaadin's CurrentInstance holds the session weakly. */
  private InMemoryVaadinSession boundSession;

  @BeforeEach
  void wireSecurity() {
    JCustosServiceResolver.resetAll();
    CurrentInstance.clearAll();
    InMemorySubjectStore subjects = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjects);
    subjects.setCurrentSubject(alice, PiiUser.class);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(PiiUser.class));
    FakeAuthorizationService<PiiUser> authorization = new FakeAuthorizationService<>();
    authorization.putRoles(alice, Set.of(new RoleName("ADMIN")));
    JCustosServiceResolver.setAuthorizationService(authorization);
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setSessionPolicy(new IdleTimeoutRecordingPolicy());
  }

  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
    CurrentInstance.clearAll();
    boundSession = null;
  }

  @ParameterizedTest(name = "resolver registered: {0}")
  @ValueSource(booleans = {true, false})
  @DisplayName("navigation, SecuredVisibility, session lifetime and login rotation derive the same subject id")
  void sameSubjectIdEverywhere(boolean withResolver) {
    if (withResolver) {
      JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
    }
    String expected = withResolver
        ? "user-7"
        : PiiUser.class.getSimpleName() + "@" + Integer.toHexString(System.identityHashCode(alice));

    Map<String, String> ids = new LinkedHashMap<>();

    // 1. the context the AuthorizationListener hands every evaluator
    JCustosSubject navigation = new VaadinAccessContextFactory()
        .create(navigationEvent()).subject().orElseThrow();
    ids.put("navigation", navigation.subjectId());
    ids.put("navigation/displayName", navigation.displayName());

    // 2. the view SecuredButton / SecuredRouterLink / SecuredMenuItem decide on
    SecuredVisibility.JCustosView view = SecuredVisibility.currentJCustosView().orElseThrow();
    JCustosSubject secured = assertInstanceOf(JCustosSubject.class, view.roles(),
        "the components decide on the facade's subject");
    ids.put("SecuredVisibility", secured.subjectId());

    // 3. the audit id of the session rotation after a login (LoginView, OAuth2 callback)
    ids.put("LoginSessionRotation", LoginView.subjectIdOf(new SessionContext<>(
        alice, "rotated-session", T0, T0, "127.0.0.1", Map.of())));

    // 4. the session-lifetime check: the metadata its policy evaluates and the audit event
    bindSession(T0);
    new SessionLifetimeListener(Clock.fixed(T0.plusSeconds(60), ZoneOffset.UTC))
        .beforeEnter(navigationEvent());
    ids.put("SessionLifetimeListener/metadata", sessionMetadataIds.getFirst());
    ids.put("SessionLifetimeListener/SessionExpired", audit.single(SessionExpired.class).subjectId());

    ids.forEach((site, id) -> assertEquals(expected, id, site + " derived a different subject id"));
    assertEquals(expected, CurrentSubject.subjectIdOf(alice));
    for (JCustosSubject subject : List.of(navigation, secured)) {
      assertFalse(subject.toString().contains(SECRET), "the credential in toString() leaked: " + subject);
      assertFalse(subject.toString().contains("alice@example.test"), "the e-mail leaked: " + subject);
    }
  }

  // ── fixtures ───────────────────────────────────────────────────

  private void bindSession(Instant createdAt) {
    boundSession = new InMemoryVaadinSession(createdAt);
    VaadinSession.setCurrent(boundSession);
  }

  private static BeforeEnterEvent navigationEvent() {
    return new BeforeEnterEvent(
        new Router(new TestRouteRegistry()),
        NavigationTrigger.PROGRAMMATIC,
        new Location("admin"),
        AdminView.class,
        new UI(),
        List.of());
  }

  /** Records the subject id the lifetime check hands the policy, and expires the session. */
  private final class IdleTimeoutRecordingPolicy implements SessionPolicy<Object> {
    @Override
    public SessionDecision beforeNavigation(SessionContext<Object> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override
    public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      sessionMetadataIds.add(metadata.subjectId());
      return SessionPolicyDecision.idleTimeout();
    }
  }

  private static final class InMemoryVaadinSession extends VaadinSession {
    private final Map<Object, Object> attributes = new HashMap<>();
    private final WrappedSession wrappedSession;

    InMemoryVaadinSession(Instant createdAt) {
      super(null);
      this.wrappedSession = new StubWrappedSession(createdAt);
    }

    @Override public WrappedSession getSession() {
      return wrappedSession;
    }

    @Override public void setAttribute(String name, Object value) {
      if (value == null) {
        attributes.remove(name);
      } else {
        attributes.put(name, value);
      }
    }

    @Override public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) {
        attributes.remove(type);
      } else {
        attributes.put(type, value);
      }
    }

    @Override public Object getAttribute(String name) {
      return attributes.get(name);
    }

    @Override public <T> T getAttribute(Class<T> type) {
      return type.cast(attributes.get(type));
    }
  }

  private static final class StubWrappedSession implements WrappedSession {
    private final long creationTimeMillis;

    StubWrappedSession(Instant created) {
      this.creationTimeMillis = created.toEpochMilli();
    }

    @Override public int getMaxInactiveInterval() { return 0; }
    @Override public Object getAttribute(String name) { return null; }
    @Override public Set<String> getAttributeNames() { return Set.of(); }
    @Override public void invalidate() { }
    @Override public String getId() { return "parity-session"; }
    @Override public long getCreationTime() { return creationTimeMillis; }
    @Override public long getLastAccessedTime() { return creationTimeMillis; }
    @Override public boolean isNew() { return false; }
    @Override public void removeAttribute(String name) { }
    @Override public void setAttribute(String name, Object value) { }
    @Override public void setMaxInactiveInterval(int interval) { }
  }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override public VaadinContext getContext() {
      return null;
    }
  }

  static class AdminView extends Component {
  }
}
