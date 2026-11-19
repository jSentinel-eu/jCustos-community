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
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.session.NoopSessionPolicy;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import com.vaadin.flow.component.PollEvent;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.PushConfiguration;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.server.RequestHandler;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinRequestInterceptor;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import com.vaadin.flow.shared.Registration;
import com.vaadin.flow.shared.ui.Transport;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Enforces the {@link SessionPolicy} lifetime (idle timeout, absolute lifetime) and the
 * revocation state of a session on every way a client reaches the server:
 *
 * <ul>
 *   <li>as a {@link BeforeEnterListener} on every navigation - this covers page loads;</li>
 *   <li>as a {@link RequestHandler} on every UIDL request sent over XHR - button clicks,
 *       grid paging, {@code @ClientCallable} (JS-SEC-082, CWE-613) - and on every download,
 *       upload and {@code StreamResource} request ({@code DownloadHandler},
 *       {@code UploadHandler}, {@code StreamResource}, {@code StreamReceiver}; exit review
 *       XR03). Heartbeats, page loads and static resources are not checked;</li>
 *   <li>as a {@link VaadinRequestInterceptor} on every client message that travels through
 *       the push channel, which is how {@code Transport.WEBSOCKET} delivers them and which
 *       never reaches a request handler (JS-SEC-155, CWE-613).</li>
 * </ul>
 *
 * <p>A request handler an application registers itself through
 * {@code ServiceInitEvent.addRequestHandler} runs <em>before</em> this one when it is added
 * later, and a plain request outside the stream paths is not checked; such a handler checks
 * the session itself.
 *
 * <p>The navigation listener runs at {@link Integer#MAX_VALUE} priority so it fires
 * <em>before</em> the
 * {@code eu.jsentinel.jcustos.authorization.impl.AuthorizationListener}
 * (priority {@code MAX_VALUE - 1}). When the session is idle, past its absolute lifetime
 * or revoked, the listener:
 * <ol>
 *   <li>removes the cached subject from the {@link SubjectStore}, together with the
 *       security-version snapshot and a bound token credential;</li>
 *   <li>emits a {@link SessionExpired} audit event with an {@code IdleTimeout} or
 *       {@code AbsoluteLifetimeExceeded} reason, or {@code SessionInvalidated} with the
 *       reason {@code Revoked};</li>
 *   <li>on a navigation forwards to the configured {@link LoginView} (resolved through the
 *       registered {@link LoginListener}); on a client message closes the Vaadin session,
 *       invalidates the HTTP session and answers with Vaadin's session-expired message
 *       <em>instead of</em> executing the message (JS-SEC-155).</li>
 * </ol>
 *
 * <p><strong>Locking (JS-SEC-155, CWE-667).</strong> Vaadin calls a plain request handler
 * and a request interceptor <em>without</em> the session lock. Both entry points take the
 * lock themselves before they read or write session state; with
 * {@code sessionLockCheckStrategy=throw}, which Vaadin applies outside production mode,
 * every unlocked access would otherwise fail the request.
 *
 * <p><strong>Activity (JS-SEC-155, CWE-613).</strong> The listener keeps its own
 * last-activity instant in a session attribute. Navigations and client messages advance it;
 * a message that turns out to be an automatic poll ({@code UI.setPollInterval}) restores the
 * previous value, so a polling view no longer keeps an unattended session alive. Vaadin's
 * {@link VaadinSession#getLastRequestTimestamp() last request timestamp} is not used: it is
 * stamped for polls as well. A message that carries a poll <em>and</em> a user interaction
 * counts as a poll; the next interaction advances the activity again. A download or upload is
 * checked but does not advance the activity either: an image or a chart served as a
 * {@code StreamResource} is fetched by the browser on its own, after every poll that
 * refreshes it.
 *
 * <p><strong>Failures (exit review XR05, CWE-636).</strong> A check that throws on the XHR
 * path stops the request: the exception reaches Vaadin's error handling and the RPC is not
 * executed. On the push channel the interceptor would let the message through, so there the
 * session is ended instead. A {@code SessionStore} that cannot be read is the documented
 * exception: the revocation check is skipped with a warning and the lifetime check still
 * runs (JS-SEC-131).
 *
 * <p>The listener is loaded via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 * Demos can register it by adding the FQN to that file.
 */
@ListenerPriority(Integer.MAX_VALUE)
public class SessionLifetimeListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener, RequestHandler,
               VaadinRequestInterceptor, HasLogger, Serializable {

  @Serial
  private static final long serialVersionUID = 1L;

  /** Session attribute under which the last-activity instant is stored. */
  static final String LAST_ACTIVITY_ATTRIBUTE =
      "eu.jsentinel.jcustos.session.lastActivity";

  /** Request attribute: the activity value before this request advanced it (JS-SEC-155). */
  static final String ACTIVITY_BEFORE_REQUEST_ATTRIBUTE =
      "eu.jsentinel.jcustos.session.activityBeforeRequest";

  /** Request attribute: set once a poll was seen in this request (JS-SEC-155). */
  static final String POLL_SEEN_ATTRIBUTE =
      "eu.jsentinel.jcustos.session.pollSeen";

  /** JS-SEC-035 (CWE-613): warn once when session-lifetime enforcement is inert. */
  private static final AtomicBoolean NOOP_POLICY_WARNED = new AtomicBoolean(false);

  /** JS-SEC-155 (CWE-384): warn once when the push transport cannot rotate a session id. */
  private static final AtomicBoolean WEBSOCKET_TRANSPORT_WARNED = new AtomicBoolean(false);

  private final transient Clock clock;

  /** Default — uses {@link Clock#systemUTC()}. */
  public SessionLifetimeListener() {
    this(Clock.systemUTC());
  }

  /** Test seam: inject a fixed clock. */
  public SessionLifetimeListener(Clock clock) {
    this.clock = clock;
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    VaadinService service = event.getSource();
    service.addUIInitListener(this);
    // JS-SEC-131 (CWE-613): a revoke has to reach the live session, so the service's
    // sessions are tracked from their start to their destruction.
    service.addSessionInitListener(init -> VaadinSessionRevocation.track(init.getSession()));
    service.addSessionDestroyListener(destroy -> VaadinSessionRevocation.untrack(destroy.getSession()));
    // JS-SEC-082 (CWE-613): RPC round-trips never reach beforeEnter - enforce per UIDL request too.
    event.addRequestHandler(this);
    // JS-SEC-155 (CWE-613): with Transport.WEBSOCKET the messages bypass the request handlers.
    event.addVaadinRequestInterceptor(this);
  }

  @Override
  public void uiInit(UIInitEvent event) {
    UI ui = event.getUI();
    Registration reg = ui.addBeforeEnterListener(this);
    // JS-SEC-155 (CWE-613): an automatic poll is no user activity.
    Registration poll = ui.addPollListener(SessionLifetimeListener::pollSeen);
    ui.addDetachListener(e -> {
      reg.remove();
      poll.remove();
    });
    warnIfWebSocketOnly(ui.getPushConfiguration());
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return;
    }
    endIfDue(session, VaadinRequest.getCurrent(), true).ifPresent(ending -> {
      if (ending.revoked()) {
        // JS-SEC-131 (CWE-613): a revoked session does not live on as an anonymous one.
        SessionTermination.closeAndInvalidate(session);
      }
      forwardToLogin(event);
    });
  }

  /**
   * JS-SEC-082 / JS-SEC-155 / XR03 (CWE-613, CWE-667): enforcement per request. Button
   * clicks, grid paging and {@code @ClientCallable} calls travel through the UIDL handler,
   * downloads and uploads through Vaadin's stream handler; neither reaches
   * {@link #beforeEnter(BeforeEnterEvent)}. This handler is registered through
   * {@link ServiceInitEvent#addRequestHandler} and therefore runs ahead of the framework
   * handlers. Vaadin calls it <em>without</em> the session lock, so it takes the lock for
   * the check. For an expired or revoked session it drops the subject, audits, closes the
   * Vaadin session, invalidates the HTTP session and <em>consumes</em> the request: a client
   * message is answered with Vaadin's session-expired message and its RPC invocations are
   * never executed; a download or upload is answered with {@code 403} and never served.
   * Heartbeats, page loads and static resources pass unchecked.
   *
   * @return {@code true} when the session was ended and the request answered
   * @since 00.84.00
   */
  @Override
  public boolean handleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response)
      throws IOException {
    if (session == null || !SessionTermination.isCheckedRequest(request)) {
      return false;
    }
    // XR03: a download or upload is checked, but it is no user activity (see the class doc)
    boolean activity = !SessionTermination.isStreamRequest(request);
    boolean ended = SessionTermination.underLock(session, Boolean.FALSE, locked -> {
      Optional<Ending> ending = endIfDue(locked, request, activity);
      ending.ifPresent(due -> SessionTermination.closeInvalidateAndDestroy(locked));
      return ending.isPresent();
    });
    if (!ended) {
      return false;
    }
    SessionTermination.answerEnded(request, response);
    return true;
  }

  /**
   * JS-SEC-155 (CWE-613): enforcement for client messages that arrive through the push
   * channel. With {@code @Push(transport = Transport.WEBSOCKET)} Vaadin's {@code PushHandler}
   * hands every message straight to the RPC handler; the request handlers are not consulted,
   * but {@code VaadinService.requestStart} - and with it every request interceptor - is. For
   * an expired or revoked session the interceptor ends the session before the push handler
   * looks it up, so the handler finds none, sends the session-expired message and drops the
   * RPC invocations. A check that fails with an exception ends the session the same way
   * (exit review XR05): the push handler would otherwise execute the message.
   *
   * @since 00.84.00
   */
  @Override
  public void requestStart(VaadinRequest request, VaadinResponse response) {
    Optional<VaadinSession> pushSession;
    try {
      if (request == null || !SessionTermination.isPushMessage(request)) {
        return;
      }
      pushSession = SessionTermination.sessionOf(request);
    } catch (RuntimeException unreadableRequest) {
      logger().warn("Session check for a push message skipped, the request could not be read: {}",
          unreadableRequest.getClass().getName());
      return;
    }
    pushSession.ifPresent(session -> {
      try {
        SessionTermination.underLock(session, Boolean.FALSE, locked -> {
          Optional<Ending> ending = endIfDue(locked, request, true);
          // the request will end without a session, so nobody else destroys this one
          ending.ifPresent(due -> SessionTermination.closeInvalidateAndDestroy(locked));
          return ending.isPresent();
        });
      } catch (RuntimeException checkFailure) {
        // XR05 (CWE-636): fail closed, as the XHR path does - the class only, the message may
        // carry what the failing component was asked for
        logger().warn("Session check for a push message failed ({}); the session is ended",
            checkFailure.getClass().getName());
        SessionTermination.endAfterFailedCheck(session);
      }
    });
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

  /**
   * Drops the identity of the locked, current session and audits when the policy or the
   * store says the session is over. Closing the session is left to the caller, because it
   * differs between the entry points.
   */
  private Optional<Ending> endIfDue(VaadinSession session, VaadinRequest request, boolean activity) {
    Optional<Ending> ending = check(session, request, activity);
    ending.ifPresent(due -> enforce(session, due));
    return ending;
  }

  /**
   * Why a session ends: whose subject to drop and what to audit.
   *
   * @param reason the {@link SessionExpired} reason, or {@code null} for a revoked session
   */
  private record Ending(String subjectId, String sessionId, String reason) {
    boolean revoked() {
      return reason == null;
    }
  }

  /** The activity value a request found before it advanced it; {@code null} when none. */
  private record ActivityBefore(Instant value) { }

  /**
   * Evaluates revocation and lifetime for the bound subject. Advances the last-activity
   * attribute for an active session - unless {@code activity} is {@code false} - and returns
   * empty; returns the ending to enforce otherwise. The caller holds the session lock.
   */
  private Optional<Ending> check(VaadinSession session, VaadinRequest request, boolean activity) {
    if (SubjectStores.findSubjectStore().isEmpty()) {
      return Optional.empty();
    }
    Instant now = Instant.now(clock);

    // JS-SEC-097 / XR05 (CWE-1041, CWE-636): the subject comes from the shared facade, but a
    // store that cannot be read is thrown, not read as "no subject" - here that would mean
    // "nothing to end" and let the request pass.
    Optional<Object> currentSubject = CurrentSubject.currentPropagatingFailures();
    if (currentSubject.isEmpty()) {
      // Nothing to expire, but the round-trip is activity: a login later in this session
      // must not inherit a stamp from before the anonymous browsing.
      if (activity) {
        recordActivity(session, request, now);
      }
      return Optional.empty();
    }
    // JS-SEC-004 / JS-SEC-097 (CWE-532): the registered SubjectIdResolver, otherwise the
    // identity handle - never subject.toString(), and never blank (SessionMetadata rejects
    // a blank id). The same id the navigation and the login rotation derive.
    String subjectId = CurrentSubject.subjectIdOf(currentSubject.get());
    String sessionId = SessionTermination.sessionIdOf(session);

    // JS-SEC-131 (CWE-613): "Revoke" has to end the session, not only edit the store. The
    // audit names the subject as the node where Revoke was clicked does (decision F21): the
    // resolver's id, else the record's, else the identity handle.
    Optional<VaadinSessionRevocation.Revoked> revoked = VaadinSessionRevocation.revocationOf(session);
    if (revoked.isPresent()) {
      return Optional.of(new Ending(
          VaadinSessionRevocation.auditSubjectId(revoked.get().recordSubjectId()), sessionId, null));
    }

    Instant createdAt = sessionCreatedAt(session);
    if (createdAt == null) {
      return Optional.empty();
    }
    Instant lastActivity = lastActivityOf(session, createdAt);

    SessionMetadata metadata = new SessionMetadata(subjectId, createdAt, lastActivity);
    SessionPolicy<Object> policy = JCustosServiceResolver.sessionPolicy();
    if (policy instanceof NoopSessionPolicy && NOOP_POLICY_WARNED.compareAndSet(false, true)) {
      // JS-SEC-035 (CWE-613) / JS-SEC-065 (CWE-1188): since 00.84.00 the resolver default is
      // an enforcing TimeoutSessionPolicy, so a NoopSessionPolicy here is an explicit
      // registration — the integrator opted out of idle and absolute-lifetime enforcement.
      // Say so once (mirrors JS-SEC-027) so the choice is visible in the log.
      logger().warn("Session lifetime enforcement is switched off: NoopSessionPolicy is registered "
          + "explicitly, so SessionLifetimeListener enforces neither an idle timeout nor an "
          + "absolute-lifetime cap (the servlet container's idle timeout still applies). Remove the "
          + "registration to get the secure default (30 min idle, 12 h absolute).");
    }
    SessionPolicyDecision decision = policy.evaluate(metadata);

    return switch (decision) {
      case SessionPolicyDecision.Active ignored -> {
        if (activity) {
          recordActivity(session, request, now);
        }
        yield Optional.empty();
      }
      case SessionPolicyDecision.IdleTimeout ignored ->
          Optional.of(new Ending(subjectId, sessionId, SessionExpired.REASON_IDLE_TIMEOUT));
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored ->
          Optional.of(new Ending(subjectId, sessionId, SessionExpired.REASON_ABSOLUTE_LIFETIME));
    };
  }

  private static void enforce(VaadinSession session, Ending ending) {
    SessionTermination.clearIdentity(session);
    if (ending.revoked()) {
      VaadinSessionRevocation.auditRevoked(ending.subjectId(), ending.sessionId());
    } else {
      audit(ending.subjectId(), ending.reason());
    }
  }

  /**
   * JS-SEC-155 (CWE-613): the listener's own activity attribute is the only activity signal.
   * Vaadin's {@code getLastRequestTimestamp()} is stamped for every UIDL message, automatic
   * polls included, and therefore kept a polling view alive for ever. Neither value may
   * predate the session.
   */
  private static Instant lastActivityOf(VaadinSession session, Instant createdAt) {
    Optional<Instant> fromAttribute = lastActivityAttribute(session);
    return fromAttribute.isPresent() && fromAttribute.get().isAfter(createdAt)
        ? fromAttribute.get()
        : createdAt;
  }

  /**
   * Advances the activity attribute and remembers, once per request, the value it replaced,
   * so {@link #pollSeen(PollEvent)} can take the advance back. A request in which a poll was
   * already seen does not advance the activity any more.
   */
  private static void recordActivity(VaadinSession session, VaadinRequest request, Instant now) {
    VaadinRequest current = request != null ? request : VaadinRequest.getCurrent();
    if (current != null) {
      if (Boolean.TRUE.equals(current.getAttribute(POLL_SEEN_ATTRIBUTE))) {
        return;
      }
      if (current.getAttribute(ACTIVITY_BEFORE_REQUEST_ATTRIBUTE) == null) {
        current.setAttribute(ACTIVITY_BEFORE_REQUEST_ATTRIBUTE,
            new ActivityBefore(lastActivityAttribute(session).orElse(null)));
      }
    }
    session.setAttribute(LAST_ACTIVITY_ATTRIBUTE, now);
  }

  /**
   * JS-SEC-155 (CWE-613): a poll round-trip is no user activity. The request that carries it
   * advanced the activity before the message was decoded; restore the value from before.
   */
  static void pollSeen(PollEvent event) {
    if (!event.isFromClient()) {
      return;
    }
    VaadinRequest current = VaadinRequest.getCurrent();
    VaadinSession session = event.getSource().getSession();
    if (current == null || session == null) {
      return;
    }
    current.setAttribute(POLL_SEEN_ATTRIBUTE, Boolean.TRUE);
    if (current.getAttribute(ACTIVITY_BEFORE_REQUEST_ATTRIBUTE) instanceof ActivityBefore before) {
      session.setAttribute(LAST_ACTIVITY_ATTRIBUTE, before.value());
    }
  }

  /**
   * JS-SEC-155 (CWE-384): start-up diagnostic for {@code @Push(transport = Transport.WEBSOCKET)}.
   * The lifetime, revocation and drift checks run for WebSocket messages through the request
   * interceptor, but an HTTP session id cannot be rotated over a WebSocket frame - there is
   * no response that could carry {@code Set-Cookie}. {@code LoginView} and the OAuth2
   * callback therefore refuse a login that arrives through the push channel (exit review
   * XR09-2); until then it kept its pre-login session id.
   *
   * @return {@code true} when the transport is WebSocket-only
   */
  boolean warnIfWebSocketOnly(PushConfiguration push) {
    if (push == null || !push.getPushMode().isEnabled() || push.getTransport() != Transport.WEBSOCKET) {
      return false;
    }
    if (WEBSOCKET_TRANSPORT_WARNED.compareAndSet(false, true)) {
      logger().warn("Push transport WEBSOCKET is active. Session lifetime, revocation and "
          + "security-version checks run per client message through the request interceptor, but "
          + "the HTTP session id cannot be rotated over a WebSocket frame (no Set-Cookie): a login "
          + "that arrives through the push channel is refused, because it would keep its pre-login "
          + "session id. Use Transport.WEBSOCKET_XHR (the Vaadin default), which sends client "
          + "messages over XHR.");
    }
    return true;
  }

  private static Instant sessionCreatedAt(VaadinSession session) {
    WrappedSession wrapped = session.getSession();
    if (wrapped == null) {
      return null;
    }
    long millis = wrapped.getCreationTime();
    return millis <= 0 ? null : Instant.ofEpochMilli(millis);
  }

  private static Optional<Instant> lastActivityAttribute(VaadinSession session) {
    Object value = session.getAttribute(LAST_ACTIVITY_ATTRIBUTE);
    return value instanceof Instant instant ? Optional.of(instant) : Optional.empty();
  }

  private static void forwardToLogin(BeforeEnterEvent event) {
    Optional<LoginListener<Object>> listener = LoginListeners.findLoginListener();
    if (listener.isEmpty()) {
      return;
    }
    Class<? extends LoginView> target = listener.get().loginNavigationTarget();
    if (target != null) {
      event.forwardTo(target);
    }
  }

  private static void audit(String subjectId, String reasonLabel) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new SessionExpired(
          Instant.now(), subjectId == null ? "" : subjectId, null, reasonLabel));
    } catch (RuntimeException auditFailure) {
      // never block navigation because the audit sink failed
    }
  }
}
