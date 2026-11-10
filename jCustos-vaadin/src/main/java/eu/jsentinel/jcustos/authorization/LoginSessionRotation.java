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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.VaadinJCustosVersionContext;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * What every successful login in the Vaadin adapter owes the session it happens in
 * (JS-SEC-146, CWE-384): a new HTTP session id, the {@link SessionPolicy} notification, the
 * rotation audit and the security-version snapshot.
 *
 * <p>Until 00.84.00 this sequence was private code of {@link LoginView}. A login that did not
 * go through that form - the OAuth2 / OIDC callback above all - bound the subject into the
 * session the browser had arrived with and kept its id: session fixation. The sequence now
 * lives here; {@code LoginView} and {@code AbstractOAuth2CallbackView} both call it, and so
 * should every other place that binds a subject.
 *
 * <p>Call {@link #afterLogin(RotationHook)} <em>after</em> the subject was bound to the
 * {@link SubjectStore} and from the request thread of the login. The steps, in this order:
 * <ol>
 *   <li>The HTTP session id is rotated through {@code HttpServletRequest.changeSessionId()}:
 *       the servlet session object - and with it the {@link VaadinSession}, the bound subject
 *       and every other attribute - stays in place, only the id changes. Non-servlet
 *       transports fall back to {@link VaadinService#reinitializeSession(VaadinRequest)}.</li>
 *   <li>{@link SessionPolicy#onLogin(SessionContext)} observes the login with the id that
 *       lives on (JS-SEC-060).</li>
 *   <li>A {@code SessionInvalidated} audit event is emitted for the <em>old</em> id, with
 *       the reason of an {@link SessionDecision.Invalidate Invalidate} decision or
 *       {@value #DEFAULT_REASON}.</li>
 *   <li>The hook is told the old and the new id, so records keyed by the session id can
 *       follow (a {@code SessionStore} record, a {@code SubjectSessionRegistry} entry).</li>
 *   <li>The {@link JCustosVersion} snapshot is recorded in
 *       {@link VaadinJCustosVersionContext} when a {@link JCustosVersionStore} and a
 *       {@link SubjectIdResolver} are registered.</li>
 * </ol>
 *
 * <p>The method never throws. Its {@link Outcome} says whether the id really changed, so the
 * caller decides what a failed rotation means: {@code LoginView} warns and continues, the
 * OAuth2 callback aborts the login.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class LoginSessionRotation {

  /** Audit reason when the policy does not supply one. */
  public static final String DEFAULT_REASON = "RotationAfterLogin";

  /**
   * JS-SEC-027: warns once (not per login) when a JCustosVersionStore is
   * registered but no SubjectIdResolver is resolvable, so drift detection is
   * silently inert.
   */
  private static final AtomicBoolean DRIFT_INERT_WARNED = new AtomicBoolean(false);

  private LoginSessionRotation() {
    throw new AssertionError("no instances");
  }

  /**
   * Receives the session ids of a rotation.
   */
  @FunctionalInterface
  public interface RotationHook {

    /**
     * Called once after the id rotated, the policy observed the login and the rotation was
     * audited. Exceptions are logged and never block the login.
     *
     * @param previousSessionId the id before the rotation (may be {@code null} when the
     *                          transport exposed none)
     * @param currentSessionId  the surviving id
     */
    void onSessionRotated(String previousSessionId, String currentSessionId);
  }

  /**
   * What {@link #afterLogin(RotationHook)} did.
   *
   * @param sessionBound      {@code false} when no {@link VaadinSession} is bound to the
   *                          thread - nothing was done
   * @param rotated           {@code true} when the HTTP session id changed
   * @param previousSessionId the id before the call; {@code null} without a session
   * @param currentSessionId  the id after the call; equals {@code previousSessionId} when
   *                          the rotation did not happen
   */
  public record Outcome(boolean sessionBound, boolean rotated,
                        String previousSessionId, String currentSessionId) {
  }

  /**
   * Runs the post-login sequence without a hook.
   *
   * @return what was done
   */
  public static Outcome afterLogin() {
    return afterLogin(null);
  }

  /**
   * Runs the post-login sequence for the session bound to the current thread.
   *
   * @param hook receives the old and the new session id after a rotation; may be
   *             {@code null}
   * @return what was done; never {@code null}
   */
  public static Outcome afterLogin(RotationHook hook) {
    Outcome outcome = rotateAndNotify(hook);
    captureJCustosVersionSnapshot();
    return outcome;
  }

  private static Outcome rotateAndNotify(RotationHook hook) {
    String previousSessionId = null;
    String currentSessionId = null;
    boolean sessionBound = false;
    boolean rotated = false;
    try {
      SessionPolicy<Object> policy = JCustosServiceResolver.sessionPolicy();
      Optional<SessionContext<Object>> beforeRotation = buildSessionContext();
      if (beforeRotation.isEmpty()) {
        return new Outcome(false, false, null, null);
      }
      sessionBound = true;
      previousSessionId = beforeRotation.get().sessionId();
      currentSessionId = previousSessionId;
      // JS-SEC-003 / JS-SEC-060 / JS-SEC-146 (CWE-384): rotate the HTTP session id on every
      // successful login, independently of the SessionPolicy decision, and do it before the
      // policy runs so SessionCreated names the surviving id.
      rotated = rotateSessionId(previousSessionId);
      SessionContext<Object> context = rotated
          ? buildSessionContext().orElse(beforeRotation.get())
          : beforeRotation.get();
      currentSessionId = context.sessionId();
      SessionDecision decision = policy.onLogin(context);
      String reason = decision instanceof SessionDecision.Invalidate invalidate
          ? invalidate.reason()
          : DEFAULT_REASON;
      if (rotated) {
        auditRotation(context, previousSessionId, reason);
        notifySessionRotated(hook, previousSessionId, context.sessionId());
      }
    } catch (RuntimeException notifyFailure) {
      HasLogger.staticLogger().warn("SessionPolicy.onLogin notification failed: {}",
          notifyFailure.toString());
    }
    return new Outcome(sessionBound, rotated, previousSessionId, currentSessionId);
  }

  /**
   * Rotates the underlying HTTP session id while preserving the
   * {@link VaadinSession} (and therefore the just-bound subject). Standard
   * session-fixation mitigation: callers that pass credentials over a
   * pre-existing session id cannot replay the post-login session because
   * the id changes here.
   *
   * @return {@code true} when the id changed, {@code false} when no request is bound, the
   *         container refused or the transport cannot rotate (a WebSocket frame carries no
   *         {@code Set-Cookie}, so its request reports the old id again)
   */
  private static boolean rotateSessionId(String previousSessionId) {
    VaadinRequest request = VaadinRequest.getCurrent();
    if (request == null) {
      return false;
    }
    try {
      if (request instanceof VaadinServletRequest servletRequest) {
        HttpServletRequest http = servletRequest.getHttpServletRequest();
        http.changeSessionId();
      } else {
        // Non-servlet transport: the legacy path copies the attributes into a
        // fresh session. Deprecated for removal from Flow 25.4, kept only here.
        VaadinService.reinitializeSession(request);
      }
    } catch (RuntimeException rotationFailure) {
      HasLogger.staticLogger().warn("Session id rotation after login failed: {}",
          rotationFailure.toString());
      return false;
    }
    String currentSessionId = currentSessionId();
    if (currentSessionId != null && currentSessionId.equals(previousSessionId)) {
      // JS-SEC-146 (CWE-384): do not report a rotation that did not happen.
      HasLogger.staticLogger().warn("Session id rotation after login had no effect: the transport "
          + "of this request cannot change the session id (a login over a WebSocket-only push "
          + "channel keeps its pre-login id).");
      return false;
    }
    return true;
  }

  private static String currentSessionId() {
    VaadinSession vaadin = VaadinSession.getCurrent();
    WrappedSession wrapped = vaadin == null ? null : vaadin.getSession();
    return wrapped == null ? null : wrapped.getId();
  }

  private static void notifySessionRotated(RotationHook hook, String previousSessionId,
                                           String currentSessionId) {
    if (hook == null) {
      return;
    }
    try {
      hook.onSessionRotated(previousSessionId, currentSessionId);
    } catch (RuntimeException hookFailure) {
      HasLogger.staticLogger().warn("onSessionRotated hook failed: {}", hookFailure.toString());
    }
  }

  private static void auditRotation(SessionContext<Object> context, String oldSessionId, String reason) {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      sink.publish(new SessionInvalidated(
          Instant.now(),
          subjectIdOf(context),
          oldSessionId,
          reason == null ? DEFAULT_REASON : reason));
    } catch (RuntimeException auditFailure) {
      // never block login because the audit sink failed
    }
  }

  // Package-private for direct testing of the id-derivation (R14): the
  // auditRotation() path itself needs a live Vaadin session, so the
  // security-relevant logic — never leak subject.toString() — is unit-tested
  // in isolation (through LoginView.subjectIdOf, which delegates here).
  static String subjectIdOf(SessionContext<Object> context) {
    Object subject = context.subject();
    if (subject == null) {
      return "";
    }
    // R14 (V00.76.10): never publish subject.toString() as the audit subject id.
    // An application user object's toString() commonly serialises email / hash /
    // internal ids into the audit channel — the leak class R019 / R020-R021
    // closed on the REST / StepUp / policy paths. Derive a stable id via the
    // registered SubjectIdResolver (the same resolver the JCustosVersion
    // snapshot path uses), falling back to a non-PII empty id when none is
    // registered (audit attribution requires a resolver by design).
    Optional<SubjectIdResolver<Object>> resolver =
        JCustosServiceResolver.findSubjectIdResolver();
    return resolver.map(r -> r.resolve(subject).value()).orElse("");
  }

  /**
   * Builds a {@link SessionContext} from the current Vaadin runtime —
   * subject (best-effort, looked up via the active
   * {@link SubjectStore} keyed on the application's subject type),
   * sessionId + createdAt from the {@link WrappedSession}, lastActivity
   * = createdAt for a fresh login, clientAddress from the
   * {@link VaadinRequest}.
   *
   * @return populated context, or empty when no Vaadin session is bound
   */
  private static Optional<SessionContext<Object>> buildSessionContext() {
    VaadinSession vaadin = VaadinSession.getCurrent();
    if (vaadin == null) {
      return Optional.empty();
    }
    WrappedSession wrapped = vaadin.getSession();
    Instant createdAt = wrapped == null
        ? Instant.now()
        : Instant.ofEpochMilli(wrapped.getCreationTime());
    String sessionId = wrapped == null ? null : wrapped.getId();
    // JS-SEC-061 (CWE-348): the client address comes from the registered
    // ClientAddressResolver, never from getRemoteAddr() directly, so a
    // reverse-proxy deployment cannot be keyed on a forgeable header.
    String clientAddress = VaadinClientAddress.current().orElse(null);
    Object subject = currentSubject().orElse(null);
    return Optional.of(new SessionContext<>(
        subject, sessionId, createdAt, createdAt, clientAddress, Map.of()));
  }

  @SuppressWarnings("unchecked")
  private static Optional<Object> currentSubject() {
    try {
      Class<?> subjectType = JCustosServiceResolver
          .<Object, Object>authenticationService()
          .subjectType();
      if (subjectType == null) {
        return Optional.empty();
      }
      SubjectStore store = SubjectStores.findSubjectStore().orElse(null);
      if (store == null) {
        return Optional.empty();
      }
      @SuppressWarnings({"rawtypes", "unchecked"})
      Class raw = subjectType;
      return store.currentSubject(raw).map(value -> (Object) value);
    } catch (RuntimeException ignored) {
      return Optional.empty();
    }
  }

  /**
   * Phase 4c-Followup: best-effort capture of the
   * {@link JCustosVersion} snapshot into
   * {@link VaadinJCustosVersionContext} so the
   * {@code JCustosVersionEnforcerListener} can detect drift on
   * subsequent requests.
   * <p>
   * Runs after the rotation so the recorded {@code sessionId}
   * matches the new servlet session. The capture is a strict
   * three-way no-op when any prerequisite is missing:
   * <ol>
   *   <li>No SPI-registered {@link JCustosVersionStore} (Phase 4a
   *       not wired) — skip.</li>
   *   <li>No SPI-registered {@link SubjectIdResolver} — the
   *       framework cannot derive a {@link SubjectId} from the
   *       application's typed user, so skip.</li>
   *   <li>No active Vaadin session / no current subject — skip.</li>
   * </ol>
   * Any exception thrown by the resolver, the store, or
   * {@link VaadinJCustosVersionContext#record} is swallowed —
   * snapshot capture must never block the login flow.
   */
  private static void captureJCustosVersionSnapshot() {
    try {
      Optional<JCustosVersionStore> storeOpt = JCustosServiceResolver.findJCustosVersionStore();
      if (storeOpt.isEmpty()) {
        return;
      }
      Optional<SubjectIdResolver<Object>> resolverOpt =
          JCustosServiceResolver.findSubjectIdResolver();
      if (resolverOpt.isEmpty()) {
        // JS-SEC-027 (CWE-636): a version store is registered but no
        // SubjectIdResolver — the snapshot is never captured, so the drift
        // enforcer no-ops on every navigation (mid-session revocation is silently
        // not enforced). Warn once so a manual-SPI integrator gets a runtime
        // signal (the DX bootstrap fails this as a STRICT/ERROR diagnostic).
        if (DRIFT_INERT_WARNED.compareAndSet(false, true)) {
          HasLogger.staticLogger().warn("JCustosVersion drift detection is inert: a JCustosVersionStore "
              + "is registered but no SubjectIdResolver is resolvable, so no login snapshot is "
              + "captured and mid-session role/permission revocation will not be enforced. "
              + "Register a SubjectIdResolver.");
        }
        return;
      }
      Object subject = currentSubject().orElse(null);
      if (subject == null) {
        return;
      }
      VaadinSession session = VaadinSession.getCurrent();
      if (session == null) {
        return;
      }
      SubjectIdResolver<Object> resolver = resolverOpt.get();
      SubjectId subjectId = resolver.resolve(subject);
      TenantId tenant = resolver.tenantFor(subject);
      JCustosVersion snapshot = storeOpt.get()
          .current(new JCustosVersionKey(tenant, subjectId));
      WrappedSession wrapped = session.getSession();
      String sessionId = wrapped == null ? null : wrapped.getId();
      VaadinJCustosVersionContext.record(session, subjectId, tenant, snapshot, sessionId);
    } catch (RuntimeException captureFailure) {
      HasLogger.staticLogger().warn("JCustosVersion snapshot capture failed: {}",
          captureFailure.toString());
    }
  }
}
