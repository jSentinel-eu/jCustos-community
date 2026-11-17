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
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.authorization.impl.StubAuthorizationService;
import eu.jsentinel.jcustos.components.SecuredButton;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.Exchange;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimePipelineTest.LockRecordingSubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.internal.PendingJavaScriptInvocation;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteParameters;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.communication.PushConnection;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.shared.communication.PushMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R8 (JS-SEC-167, CWE-613): a change of the security version reaches the open UIs of the
 * subject at once - not with their next request. A real {@code VaadinServletService}, the
 * application's wiring ({@link JCustosVersionEnforcerListener#register} next to
 * {@link VaadinJCustosVersionChangeBridge#register}), a session with Vaadin's strict lock check,
 * and the version change made on a thread that holds no session lock - as an administrator's
 * request of another session does.
 */
@DisplayName("R8 - a security-version change ends the subject's open session without a request")
class VaadinJCustosVersionChangeBridgePipelineTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY = new JCustosVersionKey(TenantId.DEFAULT, ALICE);
  private static final JCustosVersionKey BOB_KEY =
      new JCustosVersionKey(TenantId.DEFAULT, new SubjectId("bob"));
  private static final RoleName ADMIN = new RoleName("ADMIN");

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final LockRecordingSubjectStore subjects = new LockRecordingSubjectStore();
  private ObservableJCustosVersionStore versionStore;

  private RequestPipeline pipeline;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private UI ui;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    StubAuthorizationService.clear();
    JCustosServiceResolver.setJCustosAuditService(audit);
    SubjectStores.setSubjectStore(subjects);
    versionStore = new ObservableJCustosVersionStore(new InMemoryJCustosVersionStore());
    BridgeWorkView.ACTIONS.set(0);

    JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(versionStore, audit);
    JCustosVersionEnforcerListener listener = new JCustosVersionEnforcerListener(enforcer, BridgeLoginView.class);
    VaadinJCustosVersionChangeBridge bridge = new VaadinJCustosVersionChangeBridge(enforcer, BridgeLoginView.class);
    pipeline = RequestPipeline.start(Clock.systemUTC(),
        List.of(listener::register, event -> bridge.register(event, versionStore)),
        BridgeWorkView.class, BridgeLoginView.class, BridgeCustomerView.class);
    session = pipeline.session();
    ui = pipeline.ui();
    subjects.setCurrentSubject("alice", String.class);
  }

  @AfterEach
  void stop() {
    try {
      pipeline.close();
    } finally {
      JCustosServiceResolver.resetAll();
      LoginListeners.reset();
      SubjectStores.reset();
      VaadinSessionRevocation.reset();
      StubAuthorizationService.clear();
    }
    assertEquals(0, versionStore.listenerCount(), "the bridge unsubscribes when the service is destroyed");
  }

  /** Records the login snapshot and navigates, as the login flow does. */
  private BridgeWorkView loggedInWithSnapshot() {
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-r8");
    BridgeWorkView view = pipeline.navigate(BridgeWorkView.class);
    audit.clear();
    return view;
  }

  /**
   * Enables automatic push and connects the UI to a {@link RecordingPushChannel} - the open
   * WebSocket of a browser, as far as the server can tell.
   */
  private RecordingPushChannel connectPush() {
    ui.getPushConfiguration().setPushMode(PushMode.AUTOMATIC);
    RecordingPushChannel channel = new RecordingPushChannel(ui);
    ui.getInternals().setPushConnection(channel);
    return channel;
  }

  @Test
  @DisplayName("with push: the increment alone ends the session - subject dropped, SessionStale, redirect, closed")
  void drift_withPush_endsSessionWithoutARequest() {
    loggedInWithSnapshot();
    RecordingPushChannel browser = connectPush();
    pipeline.releaseLock();

    versionStore.increment(ALICE_KEY);

    assertTrue(browser.receivedRedirectTo("r8-bridge/login"),
        "the redirect to the reroute target was pushed before the session closed: " + browser.received);
    SessionStale stale = audit.single(SessionStale.class);
    assertEquals("alice", stale.subjectId());
    assertEquals(SessionRef.of("sid-r8"), stale.sessionId(), "never the session id (JS-SEC-117)");
    assertEquals(BridgeWorkView.class.getName(), stale.route(),
        "RF16: the class of the view the user had open, as the navigation check names it");
    // reading session state needs the lock under Vaadin's strict check - no request was sent
    pipeline.reacquireLock();
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the session is closed without a request");
    assertNull(session.getSession(), "the HTTP session is invalidated");
    assertTrue(subjects.currentSubject(String.class).isEmpty(), "the subject is dropped");
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(), "the snapshot is cleared");
    assertFalse(subjects.lockHeldOnAccess.contains(Boolean.FALSE),
        "every subject-store access ran under the session lock");
  }

  @Test
  @DisplayName("without push: the session ends on the server at once; the browser learns of it with its next request")
  void drift_withoutPush_nextRequestFindsTheSessionEnded() {
    BridgeWorkView view = loggedInWithSnapshot();
    pipeline.releaseLock();

    versionStore.increment(ALICE_KEY);

    assertEquals(1, audit.all(SessionStale.class).size(), "ended by the bridge, before any request");
    pipeline.reacquireLock();
    assertNotEquals(VaadinSessionState.OPEN, session.getState());
    Exchange next = pipeline.fire(view, "privileged");
    assertNull(next.failure());
    assertTrue(next.sessionExpired(), next.body());
    assertEquals(0, BridgeWorkView.ACTIONS.get(), "the RPC of the ended session never runs");
    assertEquals(1, audit.all(SessionStale.class).size(), "audited once, by the bridge");
  }

  @Test
  @DisplayName("a session busy with a request is ended as soon as that request releases the lock")
  void drift_busySession_endedWhenTheRequestEnds() throws InterruptedException {
    loggedInWithSnapshot();
    // the test thread holds the session lock, as a request of the session would
    Thread administrator = new Thread(() -> versionStore.increment(ALICE_KEY), "administrator-request");
    administrator.start();
    administrator.join(10_000);

    assertEquals(VaadinSessionState.OPEN, session.getState(), "the reaction waits for the lock");
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));

    assertTrue(audit.all(SessionStale.class).isEmpty(), "nothing happened yet");

    session.unlock();
    // the browserless set-up expects the test thread to hold the lock again
    session.getLockInstance().lock();
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "ended when the request let go of the lock");
    assertEquals("alice", audit.single(SessionStale.class).subjectId());
  }

  @Test
  @DisplayName("control: a change of another subject leaves the session alone")
  void otherSubject_untouched() {
    loggedInWithSnapshot();
    pipeline.releaseLock();

    versionStore.increment(BOB_KEY);

    assertTrue(audit.events().isEmpty(), audit.events().toString());
    pipeline.reacquireLock();
    assertEquals(VaadinSessionState.OPEN, session.getState());
    assertEquals(Optional.of("alice"), subjects.currentSubject(String.class));
  }

  @Test
  @DisplayName("no drift - a session without snapshot: the change refreshes its secured components instead")
  void noSnapshot_componentsAreRefreshed() {
    JCustosServiceResolver.setSubjectIdResolver((SubjectIdResolver<String>) SubjectId::new);
    StubAuthorizationService.put("alice", Set.of(ADMIN), Set.of());
    BridgeWorkView view = pipeline.navigate(BridgeWorkView.class);
    assertTrue(view.delete.isEnabled(), "precondition: alice holds the role");
    StubAuthorizationService.put("alice", Set.of(), Set.of());
    pipeline.releaseLock();

    versionStore.increment(ALICE_KEY);

    pipeline.reacquireLock();
    assertFalse(view.delete.isEnabled(), "the button follows the withdrawn role without a request");
    assertEquals(VaadinSessionState.OPEN, session.getState(), "without a snapshot the session stays open");
    assertTrue(audit.all(SessionStale.class).isEmpty());
  }

  @Test
  @DisplayName("RF16: a view with a route parameter - SessionStale names the view class, never the parameter value")
  void drift_routeParameterNotAudited() {
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid-rf16");
    ui.navigate(BridgeCustomerView.class, new RouteParameters("customerId", "4711-alice@example.test"));
    assertTrue(ui.getInternals().getActiveViewLocation().getPath().contains("4711"),
        "precondition: the URL carries the parameter");
    audit.clear();
    pipeline.releaseLock();

    versionStore.increment(ALICE_KEY);

    SessionStale stale = audit.single(SessionStale.class);
    assertEquals(BridgeCustomerView.class.getName(), stale.route());
    assertFalse(stale.route().contains("4711") || stale.route().contains("alice@example.test"),
        "route parameter values must not reach the hash-chained audit trail: " + stale.route());
  }

  @Test
  @DisplayName("RF23: a UI whose push fails does not keep the bridge from the subject's other UI")
  void failingPush_otherUiStillReached() {
    JCustosServiceResolver.setSubjectIdResolver((SubjectIdResolver<String>) SubjectId::new);
    StubAuthorizationService.put("alice", Set.of(ADMIN), Set.of());
    BridgeWorkView first = pipeline.navigate(BridgeWorkView.class);
    // a second tab of the same browser session
    MockVaadin.createUI(MockedUI::new, session);
    UI secondUi = UI.getCurrent();
    secondUi.navigate(BridgeWorkView.class);
    BridgeWorkView second = (BridgeWorkView) secondUi.getInternals().getActiveRouterTargetsChain().get(0);
    UI.setCurrent(ui);
    assertTrue(first.delete.isEnabled() && second.delete.isEnabled(), "precondition: alice holds the role");
    List<UI> tabs = List.of(ui, secondUi);
    for (UI tab : tabs) {
      tab.getPushConfiguration().setPushMode(PushMode.AUTOMATIC);
      tab.getInternals().setPushConnection(new FailingPushChannel());
    }
    StubAuthorizationService.put("alice", Set.of(), Set.of());
    pipeline.releaseLock();
    try {
      versionStore.increment(ALICE_KEY);

      pipeline.reacquireLock();
      assertFalse(first.delete.isEnabled(), "the first tab follows the withdrawn role");
      assertFalse(second.delete.isEnabled(),
          "whichever tab's push failed first, the other tab is still reached");
      assertEquals(VaadinSessionState.OPEN, session.getState());
    } finally {
      pipeline.reacquireLock();
      for (UI tab : tabs) {
        // the teardown releases the lock, which pushes every UI with automatic push
        tab.getPushConfiguration().setPushMode(PushMode.DISABLED);
        tab.getInternals().setPushConnection(null);
      }
    }
  }

  /** A connected push channel that breaks on every push - a dropped WebSocket. */
  private static final class FailingPushChannel implements PushConnection {
    private static final long serialVersionUID = 1L;

    @Override public void push() {
      throw new IllegalStateException("push channel broken");
    }

    @Override public void disconnect() {
    }

    @Override public boolean isConnected() {
      return true;
    }
  }

  /**
   * A connected push channel that records what each push sends: the JavaScript invocations the
   * UIDL message of a real push would carry. Hand-written stand-in for the browser's WebSocket.
   */
  private static final class RecordingPushChannel implements PushConnection {
    private static final long serialVersionUID = 1L;
    private final transient UI ui;
    final List<String> received = new CopyOnWriteArrayList<>();

    RecordingPushChannel(UI ui) {
      this.ui = ui;
    }

    @Override public void push() {
      String state = ui.isClosing() ? "[closing UI] " : "[open UI] ";
      for (PendingJavaScriptInvocation invocation : ui.getInternals().dumpPendingJavaScriptInvocations()) {
        received.add(state + invocation.getInvocation().getExpression() + " "
            + invocation.getInvocation().getParameters());
      }
    }

    @Override public void disconnect() {
    }

    @Override public boolean isConnected() {
      return true;
    }

    /** The redirect has to travel as a message of the open UI, not as the UI's farewell. */
    boolean receivedRedirectTo(String location) {
      return received.stream().anyMatch(sent -> sent.startsWith("[open UI] ")
          && sent.contains("window.open") && sent.contains(location));
    }
  }

  @Route("r8-bridge/work")
  public static class BridgeWorkView extends Div {
    static final AtomicInteger ACTIONS = new AtomicInteger();
    final SecuredButton delete = new SecuredButton("Delete", Requirement.role(ADMIN));

    public BridgeWorkView() {
      add(delete);
      getElement().addEventListener("privileged", event -> ACTIONS.incrementAndGet());
    }
  }

  @Route("r8-bridge/customer/:customerId")
  public static class BridgeCustomerView extends Div {
  }

  @Route("r8-bridge/login")
  public static class BridgeLoginView extends LoginView {
    @Override public boolean checkCredentials() {
      return false;
    }

    @Override public void navigateToApp() {
    }

    @Override public void reactOnFailedLogin() {
    }
  }
}
