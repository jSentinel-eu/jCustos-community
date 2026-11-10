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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer.EnforcementOutcome;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.server.RequestHandler;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinRequestInterceptor;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.shared.Registration;

import java.io.IOException;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Vaadin adapter for {@link JCustosVersionEnforcer}.
 * <p>
 * Registered ahead of {@code AuthorizationListener} (priority
 * {@code Integer.MAX_VALUE}) so a drifted session is refused
 * before any annotation evaluation runs. Reads the per-session
 * snapshot from {@link VaadinJCustosVersionContext}; sessions
 * without a recorded snapshot pass through untouched (the
 * application opted out by not calling
 * {@link VaadinJCustosVersionContext#record record} after login).
 *
 * <p>On drift during a navigation:
 * <ol>
 *   <li>{@link JCustosVersionEnforcer#enforce enforce} publishes
 *       a {@code SessionStale} audit event.</li>
 *   <li>The cached subject is dropped from the {@code SubjectStore} so the
 *       next navigation is evaluated as unauthenticated — revocation is
 *       actually enforced, not just deflected once (JS-SEC-002 / CWE-613).</li>
 *   <li>The recorded snapshot is cleared from the session.</li>
 *   <li>{@code BeforeEnterEvent#rerouteTo} sends the user to the
 *       supplied target — typically the login view.</li>
 * </ol>
 *
 * <p>On drift during a client message (a UIDL request, or a message that arrives through
 * the push channel with {@code Transport.WEBSOCKET}) the subject, the snapshot and a bound
 * token credential are dropped, the Vaadin session is closed, the HTTP session invalidated
 * and the message is <em>not</em> executed: the client receives Vaadin's session-expired
 * message (JS-SEC-155, CWE-613).
 *
 * <p><strong>Registration.</strong> {@link #register(ServiceInitEvent)} wires all three
 * entry points. Applications that register by hand need the navigation listener on every
 * UI, {@code ServiceInitEvent.addRequestHandler(listener)} and
 * {@code ServiceInitEvent.addVaadinRequestInterceptor(listener)}; without the interceptor
 * a WebSocket-only push transport is checked on navigation only.
 *
 * <p>The target route is supplied as a {@code Class<?>} so apps
 * keep type-safety with their {@code LoginView} subclass and so
 * the listener stays adapter-internal — there is no global
 * configuration of "the login route" here.
 */
@ExperimentalJCustosApi
@ListenerPriority(Integer.MAX_VALUE)
public final class JCustosVersionEnforcerListener
    implements BeforeEnterListener, RequestHandler, VaadinRequestInterceptor, HasLogger {

  private final JCustosVersionEnforcer enforcer;
  private final Class<? extends Component> rerouteTargetOnStale;

  /**
   * @param enforcer              the adapter-neutral enforcer; non-null
   * @param rerouteTargetOnStale  navigation target for drifted sessions;
   *                              non-null. Typically the application's
   *                              {@code LoginView} subclass
   */
  public JCustosVersionEnforcerListener(JCustosVersionEnforcer enforcer,
                                         Class<? extends Component> rerouteTargetOnStale) {
    this.enforcer = requireNonNull(enforcer, "enforcer must not be null");
    this.rerouteTargetOnStale = requireNonNull(rerouteTargetOnStale,
        "rerouteTargetOnStale must not be null");
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    Optional<VaadinJCustosVersionContext.Snapshot> snapshotOpt =
        VaadinJCustosVersionContext.current();
    if (snapshotOpt.isEmpty()) {
      return;
    }
    VaadinJCustosVersionContext.Snapshot snapshot = snapshotOpt.get();
    String route = event.getNavigationTarget() == null
        ? null
        : event.getNavigationTarget().getName();
    EnforcementOutcome outcome = enforcer.enforce(
        snapshot.subjectId(),
        snapshot.tenant(),
        snapshot.snapshot(),
        snapshot.sessionId(),
        route);
    if (outcome instanceof EnforcementOutcome.SessionStale) {
      // JS-SEC-002 (CWE-613): drop the cached subject so the very next
      // navigation is evaluated as unauthenticated. Clearing only the version
      // snapshot left the revoked subject bound and authoritative — the
      // enforcer then no-op'd (snapshot gone) and the AuthorizationListener
      // granted against the stale subject, so revocation was never enforced
      // beyond the single reroute.
      clearCurrentSubject();
      // Clear the snapshot so subsequent requests aren't re-checked
      // against the stale value while the user is on the login page.
      VaadinJCustosVersionContext.clear(VaadinSession.getCurrent());
      event.rerouteTo(rerouteTargetOnStale);
    }
  }

  /**
   * Wires the listener into a service: the navigation listener on every UI, the request
   * handler for UIDL requests and the request interceptor for messages that arrive through
   * the push channel (JS-SEC-155).
   *
   * @param event the service-init event of the application's {@code VaadinServiceInitListener}
   * @since 00.84.00
   */
  public void register(ServiceInitEvent event) {
    requireNonNull(event, "event must not be null");
    event.addRequestHandler(this);
    event.addVaadinRequestInterceptor(this);
    event.getSource().addUIInitListener((UIInitListener) uiInit -> {
      UI ui = uiInit.getUI();
      Registration registration = ui.addBeforeEnterListener(this);
      ui.addDetachListener(detach -> registration.remove());
    });
  }

  /**
   * JS-SEC-082 / JS-SEC-155 (CWE-613, CWE-667): drift enforcement per UIDL request. A session
   * whose roles were revoked kept working inside the current view because only navigations
   * were checked. Applications register the same instance through
   * {@code ServiceInitEvent.addRequestHandler(listener)}; the handler then runs ahead of the
   * framework handlers. Vaadin calls it <em>without</em> the session lock, so it takes the
   * lock for the check. On drift it drops the subject, clears the snapshot, closes the
   * Vaadin session, invalidates the HTTP session and <em>consumes</em> the request: the
   * response is Vaadin's session-expired message and the RPC invocations of the request are
   * never executed.
   *
   * @return {@code true} when the session was ended and the request answered
   * @since 00.84.00
   */
  @Override
  public boolean handleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response)
      throws IOException {
    if (session == null || !SessionTermination.isUidlRequest(request)) {
      return false;
    }
    boolean ended = SessionTermination.underLock(session, Boolean.FALSE, locked -> {
      boolean stale = dropIdentityIfStale(locked);
      if (stale) {
        SessionTermination.closeInvalidateAndDestroy(locked);
      }
      return stale;
    });
    if (!ended) {
      return false;
    }
    SessionTermination.writeSessionExpired(request, response);
    return true;
  }

  /**
   * JS-SEC-155 (CWE-613): drift enforcement for client messages that arrive through the push
   * channel ({@code Transport.WEBSOCKET}); these never reach a request handler. The session
   * is ended before Vaadin's push handler looks it up, so the message is not executed.
   *
   * @since 00.84.00
   */
  @Override
  public void requestStart(VaadinRequest request, VaadinResponse response) {
    try {
      if (request == null || !SessionTermination.isPushMessage(request)) {
        return;
      }
      SessionTermination.sessionOf(request).ifPresent(session ->
          SessionTermination.underLock(session, Boolean.FALSE, locked -> {
            boolean stale = dropIdentityIfStale(locked);
            if (stale) {
              // the request will end without a session, so nobody else destroys this one
              SessionTermination.closeInvalidateAndDestroy(locked);
            }
            return stale;
          }));
    } catch (RuntimeException checkFailure) {
      logger().warn("Security-version check for a push message failed: {}", checkFailure.toString());
    }
  }

  @Override
  public void handleException(VaadinRequest request, VaadinResponse response,
                              VaadinSession vaadinSession, Exception t) {
    // nothing to add - the framework reports the failure
  }

  @Override
  public void requestEnd(VaadinRequest request, VaadinResponse response, VaadinSession session) {
    // nothing to release - the check holds the session lock only while it runs
  }

  /** Drops the identity of the locked, current session when its snapshot drifted. */
  private boolean dropIdentityIfStale(VaadinSession session) {
    Optional<VaadinJCustosVersionContext.Snapshot> snapshotOpt =
        VaadinJCustosVersionContext.current(session);
    if (snapshotOpt.isEmpty()) {
      return false;
    }
    VaadinJCustosVersionContext.Snapshot snapshot = snapshotOpt.get();
    EnforcementOutcome outcome = enforcer.enforce(
        snapshot.subjectId(),
        snapshot.tenant(),
        snapshot.snapshot(),
        snapshot.sessionId(),
        null);
    if (!(outcome instanceof EnforcementOutcome.SessionStale)) {
      return false;
    }
    SessionTermination.clearIdentity(session, null);
    return true;
  }

  /**
   * Best-effort drop of the cached subject on drift. A missing
   * {@code SubjectStore}, an unresolvable subject type, or a removal failure
   * must never break the reroute — but on the common path this forces the next
   * navigation to be evaluated without a subject, so the revoked user is
   * effectively logged out until re-authentication.
   */
  private static void clearCurrentSubject() {
    try {
      Optional<SubjectStore> store = SubjectStores.findSubjectStore();
      if (store.isEmpty()) {
        return;
      }
      Class<?> subjectType = SessionTermination.resolveSubjectType();
      if (subjectType == null) {
        return;
      }
      SessionTermination.removeSubjectUnchecked(store.get(), subjectType);
    } catch (RuntimeException ignored) {
      // never block the reroute because subject removal failed
    }
  }
}
