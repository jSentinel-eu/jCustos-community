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

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
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
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosVersionEnforcerListener")
class JCustosVersionEnforcerListenerTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY =
      new JCustosVersionKey(TenantId.DEFAULT, ALICE);

  private InMemoryJCustosVersionStore versionStore;
  private CollectingAuditService audit;
  private JCustosVersionEnforcerListener listener;

  @BeforeEach
  void setUp() {
    CurrentInstance.clearAll();
    SubjectStores.reset();
    versionStore = new InMemoryJCustosVersionStore();
    audit = new CollectingAuditService();
    listener = new JCustosVersionEnforcerListener(
        new JCustosVersionEnforcer(versionStore, audit),
        DummyLoginView.class);
  }

  @AfterEach
  void teardown() {
    CurrentInstance.clearAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("no snapshot recorded → listener is a no-op")
  void noSnapshotIsNoop() {
    InMemoryVaadinSession session = bindSession();
    RecordingEvent event = new RecordingEvent();
    VaadinSession.setCurrent(session);
    listener.beforeEnter(event);

    assertNull(event.rerouteTarget);
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("snapshot matches store → request continues, no reroute, no audit")
  void matchingSnapshotContinues() {
    InMemoryVaadinSession session = bindSession();
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT,
        JCustosVersion.INITIAL, "sid-1");

    RecordingEvent event = new RecordingEvent();
    // Re-bind in case the BeforeEnterEvent constructor wiped CurrentInstance
    VaadinSession.setCurrent(session);
    listener.beforeEnter(event);

    assertNull(event.rerouteTarget);
    assertTrue(audit.published.isEmpty());
    // Snapshot is left intact for the next request
    assertTrue(VaadinJCustosVersionContext.current(session).isPresent());
  }

  @Test
  @DisplayName("snapshot drifted → reroute to login view, snapshot cleared, audit emitted")
  void driftedSnapshotReroutes() {
    InMemoryVaadinSession session = bindSession();
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT,
        JCustosVersion.INITIAL, "sid-7");
    versionStore.increment(ALICE_KEY); // current → 1
    versionStore.increment(ALICE_KEY); // current → 2

    RecordingEvent event = new RecordingEvent();
    VaadinSession.setCurrent(session);
    listener.beforeEnter(event);

    assertSame(DummyLoginView.class, event.rerouteTarget);
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(),
        "drifted snapshot must be cleared so subsequent requests don't keep flagging");
    assertEquals(1, audit.published.size());
    SessionStale published = (SessionStale) audit.published.get(0);
    assertEquals("alice", published.subjectId());
    assertEquals(SessionRef.of("sid-7"), published.sessionId(),
        "SessionStale carries the reference, also for a snapshot recorded with the raw id (JS-SEC-117)");
    assertEquals(DummyTarget.class.getName(), published.route());
    assertEquals(0L, published.snapshotVersion());
    assertEquals(2L, published.currentVersion());
  }

  @Test
  @DisplayName("JS-SEC-002: drift drops the cached subject so the next navigation is unauthenticated")
  void driftDropsCachedSubject() {
    InMemoryVaadinSession session = bindSession();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT,
        JCustosVersion.INITIAL, "sid-9");
    versionStore.increment(ALICE_KEY);
    versionStore.increment(ALICE_KEY);

    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isPresent(),
        "precondition: a subject is cached before drift");

    RecordingEvent event = new RecordingEvent();
    VaadinSession.setCurrent(session);
    listener.beforeEnter(event);

    // The user is rerouted AND the stale subject is gone, so the very next
    // navigation is evaluated without a subject — revocation is enforced, not
    // just deflected once.
    assertSame(DummyLoginView.class, event.rerouteTarget);
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isEmpty(),
        "drift must drop the cached subject (JS-SEC-002)");
  }

  @Test
  @DisplayName("constructor rejects null arguments")
  void constructorRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new JCustosVersionEnforcerListener(null, DummyLoginView.class));
    assertThrows(NullPointerException.class,
        () -> new JCustosVersionEnforcerListener(
            new JCustosVersionEnforcer(versionStore, audit), null));
  }

  private static InMemoryVaadinSession bindSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    VaadinSession.setCurrent(session);
    return session;
  }

  /** Vaadin session stub mirroring {@link VaadinSessionSubjectStoreTest}. */
  static final class InMemoryVaadinSession extends VaadinSession {
    private final Map<Object, Object> attributes = new HashMap<>();

    InMemoryVaadinSession() {
      super(null);
    }

    @Override public void setAttribute(String name, Object value) {
      if (value == null) attributes.remove(name); else attributes.put(name, value);
    }
    @Override public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) attributes.remove(type); else attributes.put(type, value);
    }
    @Override public Object getAttribute(String name) {
      return attributes.get(name);
    }
    @Override public <T> T getAttribute(Class<T> type) {
      return type.cast(attributes.get(type));
    }
  }

  /** {@link BeforeEnterEvent} stub that records reroute targets. */
  private static final class RecordingEvent extends BeforeEnterEvent {
    Class<? extends Component> rerouteTarget;

    RecordingEvent() {
      super(
          new Router(new TestRouteRegistry()),
          NavigationTrigger.PROGRAMMATIC,
          new Location(""),
          DummyTarget.class,
          new UI(),
          List.of());
    }

    @Override
    public void rerouteTo(Class<? extends Component> target) {
      this.rerouteTarget = target;
    }
  }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override public VaadinContext getContext() { return null; }
  }

  /** Stand-in target component referenced by the BeforeEnterEvent. */
  static class DummyTarget extends Component {
  }

  /** Stand-in login view used as the reroute target. */
  static final class DummyLoginView extends Component {
  }

  private static final class CollectingAuditService implements JCustosAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
