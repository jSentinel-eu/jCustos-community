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
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.session.NoopSessionPolicy;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.server.HandlerHelper;
import com.vaadin.flow.server.RequestHandler;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Vaadin {@link BeforeEnterListener} that consults the
 * {@link SessionPolicy} on every navigation and enforces idle / absolute
 * session lifetime via {@code SessionPolicy.evaluate(SessionMetadata)}.
 * <p>
 * The listener runs at {@link Integer#MAX_VALUE} priority so it fires
 * <em>before</em> the
 * {@code eu.jsentinel.jcustos.authorization.impl.AuthorizationListener}
 * (priority {@code MAX_VALUE - 1}). If the session is idle or has
 * exceeded its absolute lifetime, the listener:
 * <ol>
 *   <li>Removes the cached subject from the {@link SubjectStore} so
 *       downstream filters see an unauthenticated request.</li>
 *   <li>Emits a {@link SessionExpired} audit event with an
 *       {@code IdleTimeout} or {@code AbsoluteLifetimeExceeded} reason.</li>
 *   <li>Forwards the navigation to the configured
 *       {@link LoginView} (resolved through the registered
 *       {@link LoginListener}).</li>
 * </ol>
 *
 * <p>For active sessions the listener writes the current time back to a
 * private session attribute so the next navigation observes the
 * advanced last-activity timestamp. Since 00.84.00 (JS-SEC-082, CWE-613) the
 * listener is also a {@link RequestHandler}: every UIDL request - button
 * clicks, grid paging, {@code @ClientCallable} - is evaluated as well, and
 * Vaadin's {@link VaadinSession#getLastRequestTimestamp() last request
 * timestamp} counts as activity, so a user working inside one view is neither
 * left unenforced nor logged out spuriously on the next navigation.
 *
 * <p>The listener is loaded via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 * Demos can register it by adding the FQN to that file.
 */
@ListenerPriority(Integer.MAX_VALUE)
public class SessionLifetimeListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener, RequestHandler,
               HasLogger, Serializable {

  @Serial
  private static final long serialVersionUID = 1L;

  /** Session attribute under which the last-activity instant is stored. */
  static final String LAST_ACTIVITY_ATTRIBUTE =
      "eu.jsentinel.jcustos.session.lastActivity";

  /** JS-SEC-035 (CWE-613): warn once when session-lifetime enforcement is inert. */
  private static final java.util.concurrent.atomic.AtomicBoolean NOOP_POLICY_WARNED =
      new java.util.concurrent.atomic.AtomicBoolean(false);

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
    event.getSource().addUIInitListener(this);
    // JS-SEC-082 (CWE-613): RPC round-trips never reach beforeEnter - enforce per UIDL request too.
    event.addRequestHandler(this);
  }

  @Override
  public void uiInit(UIInitEvent event) {
    UI ui = event.getUI();
    Registration reg = ui.addBeforeEnterListener(this);
    ui.addDetachListener(e -> reg.remove());
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return;
    }
    evaluate(session).ifPresent(expiry -> {
      removeSubject(expiry.store());
      audit(expiry.subjectId(), expiry.reason());
      forwardToLogin(event);
    });
  }

  /**
   * JS-SEC-082 (CWE-613): enforcement per UIDL request. Button clicks, grid paging and
   * {@code @ClientCallable} calls travel through the UIDL handler and never reach
   * {@link #beforeEnter(BeforeEnterEvent)}, so a session past its absolute lifetime kept
   * working inside the current view. This handler is registered through
   * {@link ServiceInitEvent#addRequestHandler} and therefore runs ahead of the framework
   * handlers with the session locked: for an expired session it drops the subject, audits
   * the expiry, sends the browser to the login route and closes the session. The request
   * is never consumed - the UIDL handler still runs, now without a subject.
   *
   * @since 00.84.00
   */
  @Override
  public boolean handleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response) {
    if (session == null || !HandlerHelper.isRequestType(request, HandlerHelper.RequestType.UIDL)) {
      return false;
    }
    evaluate(session).ifPresent(expiry -> {
      removeSubject(expiry.store());
      audit(expiry.subjectId(), expiry.reason());
      redirectToLogin(session, request);
      session.close();
    });
    return false;
  }

  /** An expired session: whose subject to drop and which reason to audit. */
  private record Expiry(SubjectStore store, String subjectId, String reason) { }

  /**
   * Evaluates the policy for the bound subject. Advances the private last-activity
   * attribute for an active session and returns empty; returns the expiry to enforce
   * otherwise.
   */
  private Optional<Expiry> evaluate(VaadinSession session) {
    Optional<SubjectStore> store = SubjectStores.findSubjectStore();
    if (store.isEmpty()) {
      return Optional.empty();
    }

    Optional<?> currentSubject = currentSubject(store.get());
    if (currentSubject.isEmpty()) {
      return Optional.empty();
    }
    String subjectId = subjectIdOf(currentSubject.get());

    Instant createdAt = sessionCreatedAt(session);
    if (createdAt == null) {
      return Optional.empty();
    }
    Instant now = Instant.now(clock);
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
        session.setAttribute(LAST_ACTIVITY_ATTRIBUTE, now);
        yield Optional.empty();
      }
      case SessionPolicyDecision.IdleTimeout ignored ->
          Optional.of(new Expiry(store.get(), subjectId, SessionExpired.REASON_IDLE_TIMEOUT));
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored ->
          Optional.of(new Expiry(store.get(), subjectId, SessionExpired.REASON_ABSOLUTE_LIFETIME));
    };
  }

  /**
   * JS-SEC-082: Vaadin stamps every serviced UIDL request ({@code ServerRpcHandler}); that is
   * the activity signal of a single-view application, which used to be logged out on its next
   * navigation because only navigations advanced the private attribute. The attribute remains
   * for adapters and tests that drive the listener without the request pipeline. The later of
   * both wins; neither may predate the session.
   */
  private static Instant lastActivityOf(VaadinSession session, Instant createdAt) {
    Instant latest = createdAt;
    long stamped = session.getLastRequestTimestamp();
    if (stamped > 0) {
      Instant fromVaadin = Instant.ofEpochMilli(stamped);
      if (fromVaadin.isAfter(latest)) {
        latest = fromVaadin;
      }
    }
    Optional<Instant> fromAttribute = lastActivityAttribute(session);
    if (fromAttribute.isPresent() && fromAttribute.get().isAfter(latest)) {
      latest = fromAttribute.get();
    }
    return latest;
  }

  private static void removeSubject(SubjectStore store) {
    Class<?> subjectType = resolveSubjectType();
    if (subjectType != null) {
      removeSubjectUnchecked(store, subjectType);
    }
  }

  private static void redirectToLogin(VaadinSession session, VaadinRequest request) {
    try {
      UI ui = session.getService().findUI(request);
      if (ui != null) {
        ui.getPage().setLocation(loginUrl(request));
      }
    } catch (RuntimeException ignored) {
      // the session is closed regardless; the next round-trip lands on the login page
    }
  }

  private static String loginUrl(VaadinRequest request) {
    String route = LoginListeners.findLoginListener()
        .map(LoginListener::loginNavigationTarget)
        .filter(Objects::nonNull)
        .map(target -> RouteConfiguration.forSessionScope().getUrl(target))
        .orElseGet(JCustosServiceResolver::loginRouteName);
    String contextPath = request.getContextPath();
    return (contextPath == null ? "" : contextPath) + "/" + route;
  }

  private Optional<?> currentSubject(SubjectStore store) {
    Class<?> subjectType = resolveSubjectType();
    if (subjectType == null) {
      return Optional.empty();
    }
    return store.currentSubject(subjectType);
  }

  private static Class<?> resolveSubjectType() {
    try {
      return JCustosServiceResolver.<Object, Object>authenticationService().subjectType();
    } catch (RuntimeException ignored) {
      return null;
    }
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static void removeSubjectUnchecked(SubjectStore store, Class<?> subjectType) {
    Class raw = subjectType;
    store.deleteCurrentSubject(raw);
  }

  private static String subjectIdOf(Object subject) {
    // JS-SEC-004 (CWE-532): derive the audit subjectId via the registered
    // SubjectIdResolver — never subject.toString(), which commonly serialises
    // PII (email / hash / internal id) into the audit channel. SessionMetadata
    // rejects a blank subjectId, so when no resolver is registered (or it
    // yields blank) fall back to a non-PII identity handle, never toString().
    Optional<SubjectIdResolver<Object>> resolver =
        JCustosServiceResolver.findSubjectIdResolver();
    if (resolver.isPresent()) {
      String resolved = resolver.get().resolve(subject).value();
      if (resolved != null && !resolved.isBlank()) {
        return resolved;
      }
    }
    return subject.getClass().getSimpleName()
        + "@" + Integer.toHexString(System.identityHashCode(subject));
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
