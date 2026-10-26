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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.SessionCreated;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Minimal {@link SessionPolicy} with idle timeout, absolute lifetime, and
 * optional session-id rotation after login.
 * <p>
 * The policy is Vaadin-free and stateless — it makes decisions purely
 * from the {@link SessionContext}'s timestamps. Tracking last-activity
 * inside the session is the adapter's job.
 *
 * <h2>Decisions</h2>
 *
 * <ul>
 *   <li>{@link #onLogin(SessionContext)} — emits
 *       {@link SessionCreated}.
 *       If {@link Config#rotateSessionAfterLogin()} is {@code true},
 *       returns {@link SessionDecision.Invalidate} carrying the rotation
 *       reason; otherwise {@link SessionDecision.Continue#INSTANCE}. Since
 *       V00.79.30 (JS-SEC-003) the Vaadin adapter's {@code LoginView} rotates
 *       the session id on <em>every</em> login regardless of this flag — the
 *       flag now only selects the audit reason recorded for the rotation.</li>
 *   <li>{@link #beforeNavigation(SessionContext)} — checks absolute
 *       lifetime first, then idle timeout. Either trip emits
 *       {@link SessionExpired}
 *       and returns {@link SessionDecision.Invalidate}.</li>
 *   <li>{@link #onLogout(SessionContext)} — emits
 *       {@link SessionInvalidated}.</li>
 * </ul>
 *
 * <h2>Resolver default (JS-SEC-065, CWE-1188)</h2>
 *
 * Since 00.84.00 this policy with {@link Config#defaults(String)} is what
 * {@code JCustosServiceResolver.sessionPolicy()} falls back to when no
 * {@link SessionPolicy} is registered — idle and absolute lifetime are
 * enforced out of the box. {@link NoopSessionPolicy} is the explicit opt-out.
 *
 * @param <U> subject type
 */
public final class TimeoutSessionPolicy<U> implements SessionPolicy<U> {

  /**
   * Tunable thresholds.
   * <p>
   * When {@code rotateSessionAfterLogin} is {@code true},
   * {@link #onLogin(SessionContext)} returns
   * {@link SessionDecision.Invalidate} so the calling adapter rotates
   * the underlying session id. The Vaadin {@code LoginView} honours this
   * by calling {@code VaadinService.reinitializeSession(VaadinRequest)} —
   * the {@code VaadinSession} (and therefore the just-bound subject)
   * survives the rotation; only the HTTP session id changes. The
   * REST adapter has no equivalent — tokens themselves are the session,
   * and there is no fixation surface to mitigate.
   *
   * @param idleTimeout             maximum allowed time since the last
   *                                observed activity before the session
   *                                is treated as idle-timeout
   * @param absoluteLifetime        maximum allowed time since session
   *                                creation, regardless of activity
   * @param rotateSessionAfterLogin if {@code true}, {@code onLogin}
   *                                returns {@code Invalidate} so the
   *                                adapter rotates the HTTP session id
   * @param loginRoute              route used for the {@code Invalidate}
   *                                decision in the {@code beforeNavigation}
   *                                context (ignored after login rotation)
   */
  public record Config(
      Duration idleTimeout,
      Duration absoluteLifetime,
      boolean rotateSessionAfterLogin,
      String loginRoute
  ) {
    public Config {
      Objects.requireNonNull(idleTimeout, "idleTimeout");
      Objects.requireNonNull(absoluteLifetime, "absoluteLifetime");
      Objects.requireNonNull(loginRoute, "loginRoute");
      if (loginRoute.isBlank()) {
        throw new IllegalArgumentException("loginRoute must not be blank");
      }
      if (idleTimeout.isNegative() || idleTimeout.isZero()) {
        throw new IllegalArgumentException("idleTimeout must be positive");
      }
      if (absoluteLifetime.isNegative() || absoluteLifetime.isZero()) {
        throw new IllegalArgumentException("absoluteLifetime must be positive");
      }
    }

    /** Sensible defaults — 30 min idle, 12 h absolute, rotate after login, /login. */
    public static Config defaults() {
      return defaults("/login");
    }

    /**
     * The secure defaults — 30 min idle, 12 h absolute, rotation after login —
     * with an application-specific login route (JS-SEC-065).
     *
     * @param loginRoute non-blank route the {@code Invalidate} decisions carry
     * @return the default configuration for that route
     * @since 00.84.00
     */
    public static Config defaults(String loginRoute) {
      return new Config(Duration.ofMinutes(30), Duration.ofHours(12), true, loginRoute);
    }
  }

  /**
   * The policy the resolver falls back to when no {@link SessionPolicy} is
   * registered (JS-SEC-065, CWE-1188): {@link Config#defaults(String)} with the
   * audit service resolved per event.
   *
   * @param loginRoute route for the {@code Invalidate} decisions
   * @param <U>        subject type
   * @return a fresh secure-default policy
   * @since 00.84.00
   */
  public static <U> TimeoutSessionPolicy<U> secureDefault(String loginRoute) {
    return new TimeoutSessionPolicy<>(Config.defaults(loginRoute), Clock.systemUTC(), null);
  }

  private final Config config;
  private final Clock clock;
  private final JCustosAuditService auditService;

  public TimeoutSessionPolicy() {
    this(Config.defaults(), Clock.systemUTC(), null);
  }

  /**
   * @param config       thresholds and post-login behaviour
   * @param clock        time source — fixed clocks make testing deterministic
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link JCustosServiceResolver} on each event
   */
  public TimeoutSessionPolicy(Config config, Clock clock, JCustosAuditService auditService) {
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.auditService = auditService;
  }

  @Override
  public SessionDecision onLogin(SessionContext<U> context) {
    publish(new SessionCreated(
        Instant.now(clock), subjectIdOf(context), context.sessionId()));
    if (config.rotateSessionAfterLogin()) {
      return new SessionDecision.Invalidate("Session rotated after login", config.loginRoute());
    }
    return SessionDecision.Continue.INSTANCE;
  }

  @Override
  public SessionDecision beforeNavigation(SessionContext<U> context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);

    if (now.isAfter(context.createdAt().plus(config.absoluteLifetime()))) {
      publish(new SessionExpired(
          Instant.now(clock), subjectIdOf(context), context.sessionId(),
          SessionExpired.REASON_ABSOLUTE_LIFETIME));
      return new SessionDecision.Invalidate("Session lifetime exceeded", config.loginRoute());
    }
    Instant lastActivity = context.lastActivity() == null ? context.createdAt() : context.lastActivity();
    if (now.isAfter(lastActivity.plus(config.idleTimeout()))) {
      publish(new SessionExpired(
          Instant.now(clock), subjectIdOf(context), context.sessionId(),
          SessionExpired.REASON_IDLE_TIMEOUT));
      return new SessionDecision.Invalidate("Session idle timeout", config.loginRoute());
    }
    return SessionDecision.Continue.INSTANCE;
  }

  /**
   * Pure-query lifetime check called by the Vaadin
   * {@code SessionLifetimeListener} and by the REST filters.
   * <p>
   * Returns {@link SessionPolicyDecision.AbsoluteLifetimeExceeded} first
   * when both bounds are tripped — the absolute lifetime trumps the
   * idle timeout, mirroring the precedence in
   * {@link #beforeNavigation(SessionContext)}.
   * <p>
   * Audit emit-sites are deliberately not duplicated here:
   * {@link #beforeNavigation(SessionContext)} is the audit boundary,
   * since the lifecycle hooks carry the richer
   * {@link SessionContext#subject() subject} and
   * {@link SessionContext#sessionId() sessionId}. The Vaadin / REST
   * adapter that calls {@code evaluate(...)} is expected to emit the
   * audit event itself when it acts on the decision.
   *
   * @param metadata current session view
   * @return decision; never {@code null}
   */
  @Override
  public SessionPolicyDecision evaluate(SessionMetadata metadata) {
    Objects.requireNonNull(metadata, "metadata");
    Instant now = Instant.now(clock);

    if (now.isAfter(metadata.createdAt().plus(config.absoluteLifetime()))) {
      return SessionPolicyDecision.absoluteLifetimeExceeded();
    }
    if (now.isAfter(metadata.lastActivityAt().plus(config.idleTimeout()))) {
      return SessionPolicyDecision.idleTimeout();
    }
    return SessionPolicyDecision.active();
  }

  @Override
  public void onLogout(SessionContext<U> context) {
    publish(new SessionInvalidated(
        Instant.now(clock), subjectIdOf(context), context.sessionId(), "Logout"));
  }

  private String subjectIdOf(SessionContext<U> context) {
    // JS-SEC-004 (CWE-532): derive the audit subjectId via the registered
    // SubjectIdResolver — never subject.toString(), which commonly serialises
    // PII (email / hash / internal id) into the audit channel. Empty fallback
    // is safe here: these are audit-only emissions (SessionCreated /
    // SessionExpired / SessionInvalidated) which accept an empty subjectId,
    // mirroring LoginView.subjectIdOf.
    U subject = context.subject();
    if (subject == null) {
      return "";
    }
    return JCustosServiceResolver.<U>findSubjectIdResolver()
        .map(r -> r.resolve(subject).value())
        .orElse("");
  }

  private void publish(AuditEvent event) {
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block a session decision because the audit sink failed
    }
  }
}
