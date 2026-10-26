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
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.time.Clock;
import java.time.Instant;
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
 * advanced last-activity timestamp.
 *
 * <p>The listener is loaded via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 * Demos can register it by adding the FQN to that file.
 */
@ListenerPriority(Integer.MAX_VALUE)
public class SessionLifetimeListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener,
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

    Optional<SubjectStore> store = SubjectStores.findSubjectStore();
    if (store.isEmpty()) {
      return;
    }

    Optional<?> currentSubject = currentSubject(store.get());
    if (currentSubject.isEmpty()) {
      return;
    }
    String subjectId = subjectIdOf(currentSubject.get());

    Instant createdAt = sessionCreatedAt(session);
    if (createdAt == null) {
      return;
    }
    Instant now = Instant.now(clock);
    Instant lastActivity = lastActivityAttribute(session)
        .filter(activity -> !activity.isBefore(createdAt))
        .orElse(createdAt);

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

    switch (decision) {
      case SessionPolicyDecision.Active ignored -> session.setAttribute(LAST_ACTIVITY_ATTRIBUTE, now);
      case SessionPolicyDecision.IdleTimeout ignored ->
          expire(event, store.get(), subjectId, SessionExpired.REASON_IDLE_TIMEOUT);
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored ->
          expire(event, store.get(), subjectId, SessionExpired.REASON_ABSOLUTE_LIFETIME);
    }
  }

  private void expire(BeforeEnterEvent event, SubjectStore store,
                      String subjectId, String reasonLabel) {
    Class<?> subjectType = resolveSubjectType();
    if (subjectType != null) {
      removeSubjectUnchecked(store, subjectType);
    }
    audit(subjectId, reasonLabel);
    forwardToLogin(event);
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
