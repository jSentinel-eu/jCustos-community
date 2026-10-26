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
package eu.jsentinel.jcustos.session.vaadin;

import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
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
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SessionLifetimeListener")
class SessionLifetimeListenerTest {

  private static final Instant T0 = Instant.parse("2026-05-10T10:00:00Z");

  private final RecordingAuditSink audit = new RecordingAuditSink();

  /**
   * Strong reference to the session bound by {@link #bindSession(Instant)}.
   * {@code CurrentInstance} only holds a {@code WeakReference}; without this
   * field a GC pause between binding and {@code beforeEnter} made
   * {@code VaadinSession.getCurrent()} return {@code null} intermittently.
   */
  private InMemoryVaadinSession boundSession;

  @BeforeEach
  void resetState() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    CurrentInstance.clearAll();
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    CurrentInstance.clearAll();
    boundSession = null;
  }

  @Test
  @DisplayName("no current VaadinSession → listener is a safe no-op")
  void noSession_noop() {
    SessionLifetimeListener listener = new SessionLifetimeListener(
        Clock.fixed(T0, ZoneOffset.UTC));
    RecordingEvent event = new RecordingEvent();

    listener.beforeEnter(event);

    assertNull(event.forwardTarget);
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("active session writes the current time back as the new lastActivity")
  void activeSession_advancesLastActivity() {
    InMemoryVaadinSession session = bindSession(T0);
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    JCustosServiceResolver.setSessionPolicy(new AlwaysActive<String>());

    Instant later = T0.plusSeconds(30);
    SessionLifetimeListener listener = new SessionLifetimeListener(
        Clock.fixed(later, ZoneOffset.UTC));
    RecordingEvent event = new RecordingEvent();

    listener.beforeEnter(event);

    assertEquals(later, session.getAttribute(SessionLifetimeListener.LAST_ACTIVITY_ATTRIBUTE));
    assertNull(event.forwardTarget);
    assertTrue(audit.events().isEmpty(), "active sessions must not emit SESSION_EXPIRED");
  }

  @Test
  @DisplayName("JS-SEC-065: with no registered policy the secure default expires an idle session")
  void defaultPolicy_idleTimeout_expires() {
    // The secure default runs on the system clock, so the session must be created relative to it:
    // 31 minutes of inactivity trips the 30-minute idle timeout, well inside the 12-hour cap.
    bindSession(Instant.now().minus(java.time.Duration.ofMinutes(31)));
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    LoginListeners.setLoginListener(new TestLoginListener());
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("resolved-" + s));
    // no setSessionPolicy(...) — the resolver default must enforce the 30-minute idle timeout
    SessionLifetimeListener listener = new SessionLifetimeListener(Clock.systemUTC());
    RecordingEvent event = new RecordingEvent();
    listener.beforeEnter(event);
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty(),
        "the secure default must end the idle session");
    assertSame(StubLoginView.class, event.forwardTarget);
    assertTrue(audit.events().stream().anyMatch(e -> e instanceof SessionExpired ex
        && "IdleTimeout".equals(ex.reason()) && "resolved-alice".equals(ex.subjectId())),
        "SessionExpired(IdleTimeout) must be audited; got " + audit.events());
  }

  @Test
  @DisplayName("JS-SEC-065: with no registered policy a fresh session stays active")
  void defaultPolicy_freshSession_active() {
    bindSession(Instant.now().minusSeconds(60));
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    SessionLifetimeListener listener = new SessionLifetimeListener(Clock.systemUTC());
    RecordingEvent event = new RecordingEvent();
    listener.beforeEnter(event);
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isPresent());
    assertNull(event.forwardTarget);
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("idle-timeout drops the subject, emits SESSION_EXPIRED, forwards to login")
  void idleTimeout_clearsSubjectAndForwards() {
    bindSession(T0);
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    LoginListeners.setLoginListener(new TestLoginListener());
    JCustosServiceResolver.setSessionPolicy(
        new AlwaysDecide<String>(SessionPolicyDecision.idleTimeout()));
    // JS-SEC-004: the audit subjectId must come from the resolver, not toString().
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("resolved-" + s));

    SessionLifetimeListener listener = new SessionLifetimeListener(
        Clock.fixed(T0.plusSeconds(60), ZoneOffset.UTC));
    RecordingEvent event = new RecordingEvent();

    listener.beforeEnter(event);

    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty(),
        "subject must be removed on expiry");
    assertSame(StubLoginView.class, event.forwardTarget,
        "expired sessions must be forwarded to the configured login view");
    assertEquals(1, audit.events().size());
    SessionExpired ev = (SessionExpired) audit.events().get(0);
    assertEquals("IdleTimeout", ev.reason());
    assertEquals("resolved-alice", ev.subjectId(),
        "audit subjectId must be the resolver value, never subject.toString()");
  }

  @Test
  @DisplayName("JS-SEC-004: no resolver → audit subjectId is a non-PII handle, never subject.toString()")
  void noResolver_subjectIdFallsBackToNonPiiHandle() {
    bindSession(T0);
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    LoginListeners.setLoginListener(new TestLoginListener());
    JCustosServiceResolver.setSessionPolicy(
        new AlwaysDecide<String>(SessionPolicyDecision.idleTimeout()));
    // No SubjectIdResolver registered — SessionMetadata rejects a blank id, so
    // the listener must fall back to a non-blank, non-PII identity handle.

    SessionLifetimeListener listener = new SessionLifetimeListener(
        Clock.fixed(T0.plusSeconds(60), ZoneOffset.UTC));

    listener.beforeEnter(new RecordingEvent());

    SessionExpired ev = (SessionExpired) audit.events().get(0);
    assertNotEquals("alice", ev.subjectId(),
        "must never fall back to subject.toString() (JS-SEC-004)");
    assertTrue(ev.subjectId().startsWith("String@"),
        "fallback is a class@identityHashCode handle; got " + ev.subjectId());
  }

  @Test
  @DisplayName("absolute-lifetime expiry uses the ABSOLUTE_LIFETIME audit label")
  void absoluteLifetime_label() {
    bindSession(T0);
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    LoginListeners.setLoginListener(new TestLoginListener());
    JCustosServiceResolver.setSessionPolicy(
        new AlwaysDecide<String>(SessionPolicyDecision.absoluteLifetimeExceeded()));

    SessionLifetimeListener listener = new SessionLifetimeListener(
        Clock.fixed(T0.plusSeconds(60), ZoneOffset.UTC));

    listener.beforeEnter(new RecordingEvent());

    assertEquals(1, audit.events().size());
    assertEquals("AbsoluteLifetimeExceeded",
        ((SessionExpired) audit.events().get(0)).reason());
  }

  @Test
  @DisplayName("no current subject → listener does not advance last-activity and does not audit")
  void noSubject_noop() {
    bindSession(T0);
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    // no setCurrentSubject

    SessionLifetimeListener listener = new SessionLifetimeListener(
        Clock.fixed(T0.plusSeconds(60), ZoneOffset.UTC));
    RecordingEvent event = new RecordingEvent();

    listener.beforeEnter(event);

    assertNull(event.forwardTarget);
    assertTrue(audit.events().isEmpty());
  }

  // ── Helpers ───────────────────────────────────────────────────

  private InMemoryVaadinSession bindSession(Instant createdAt) {
    InMemoryVaadinSession session = new InMemoryVaadinSession(createdAt);
    boundSession = session;
    VaadinSession.setCurrent(session);
    return session;
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
      if (value == null) attributes.remove(name);
      else attributes.put(name, value);
    }

    @Override public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) attributes.remove(type);
      else attributes.put(type, value);
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
    @Override public java.util.Set<String> getAttributeNames() { return java.util.Set.of(); }
    @Override public void invalidate() { }
    @Override public String getId() { return "stub-id"; }
    @Override public long getCreationTime() { return creationTimeMillis; }
    @Override public long getLastAccessedTime() { return creationTimeMillis; }
    @Override public boolean isNew() { return false; }
    @Override public void removeAttribute(String name) { }
    @Override public void setAttribute(String name, Object value) { }
    @Override public void setMaxInactiveInterval(int interval) { }
  }

  /** A SessionPolicy that always returns Active. */
  static final class AlwaysActive<U> implements SessionPolicy<U> {
    @Override public SessionDecision beforeNavigation(SessionContext<U> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return SessionPolicyDecision.active();
    }
  }

  /** A SessionPolicy that always returns the decision passed in. */
  static final class AlwaysDecide<U> implements SessionPolicy<U> {
    private final SessionPolicyDecision decision;

    AlwaysDecide(SessionPolicyDecision decision) {
      this.decision = decision;
    }

    @Override public SessionDecision beforeNavigation(SessionContext<U> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return decision;
    }
  }

  /** Recording BeforeEnterEvent — captures forwardTo target. */
  private static final class RecordingEvent extends BeforeEnterEvent {

    Class<? extends Component> forwardTarget;

    RecordingEvent() {
      super(
          new Router(new TestRouteRegistry()),
          NavigationTrigger.PROGRAMMATIC,
          new Location(""),
          PlaceholderTarget.class,
          new UI(),
          List.of());
    }

    @Override
    public void forwardTo(Class<? extends Component> navigationTarget) {
      this.forwardTarget = navigationTarget;
    }
  }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override public VaadinContext getContext() { return null; }
  }

  static class PlaceholderTarget extends Component { }

  static class StubLoginView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { }
    @Override public void reactOnFailedLogin() { }
  }

  static final class TestLoginListener extends LoginListener<String> {
    @Override public void notARestrictedTarget(Class<?> navigationTarget) { }
    @Override public Class<? extends LoginView> loginNavigationTarget() {
      return StubLoginView.class;
    }
    @Override public Class<? extends Component> defaultNavigationTarget() {
      return PlaceholderTarget.class;
    }
  }
}
