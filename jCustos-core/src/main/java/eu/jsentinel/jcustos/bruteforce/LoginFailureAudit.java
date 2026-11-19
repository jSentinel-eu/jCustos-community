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
package eu.jsentinel.jcustos.bruteforce;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Publishes the audit events of the shipped {@link LoginAttemptPolicy}
 * implementations: the one {@link LoginFailed} event of a rejected login - the single audit
 * point the SPI describes for {@link LoginAttemptPolicy#recordFailure(LoginAttemptContext)} -,
 * {@link BruteForceLimitReached} when a failure locks a key, and {@link RateLimitExceeded} when
 * the {@link CredentialCheckGate} defers attempts - at most one a second, with their count.
 *
 * <p>An audit sink that fails must never break the security decision that emitted the event,
 * so its exception is caught. Until 00.84.00 it was also swallowed without a trace - a sink that
 * failed for hours left no failed login in the audit trail and nothing in the log. Every failure
 * is now counted, and a WARN {@code bruteforce/audit-sink-failed} is logged at most once per
 * {@link #SINK_FAILURE_WARNING_INTERVAL} (JS-SEC-123, CWE-778).</p>
 */
final class LoginFailureAudit {

  /** At most one {@code bruteforce/audit-sink-failed} line per this interval. */
  static final Duration SINK_FAILURE_WARNING_INTERVAL = Duration.ofMinutes(1);

  private static final long WARNING_INTERVAL_NANOS = SINK_FAILURE_WARNING_INTERVAL.toNanos();
  private static final AtomicLong SINK_FAILURES = new AtomicLong();
  /** {@link System#nanoTime()} from which the next warning may be logged; 0 before the first. */
  private static final AtomicLong NEXT_WARNING_AT = new AtomicLong();
  private static final AtomicLong WARNINGS_LOGGED = new AtomicLong();

  private LoginFailureAudit() {
  }

  /**
   * @param auditService the policy's audit service, or {@code null} for the registered one
   * @param at           event time
   * @param context      the attempt; user name and client address go into the event
   * @param reason       the caller's reason; {@code null} or blank means
   *                     {@link LoginAttemptPolicy#REASON_CREDENTIALS_REJECTED}
   */
  static void publish(JCustosAuditService auditService, Instant at,
                      LoginAttemptContext context, String reason) {
    publishGuarded(auditService, () -> new LoginFailed(
        at,
        context.username() == null ? "" : context.username(),
        context.clientAddress(),
        reason == null || reason.isBlank()
            ? LoginAttemptPolicy.REASON_CREDENTIALS_REJECTED
            : reason));
  }

  /**
   * Publishes {@link BruteForceLimitReached}: a failure locked the key.
   *
   * @param auditService   the policy's audit service, or {@code null} for the registered one
   * @param at             event time
   * @param context        the attempt; user name and client address go into the event
   * @param failedAttempts failures held against the key
   * @param lockout        how long the key is locked from {@code at}
   */
  static void publishLimitReached(JCustosAuditService auditService, Instant at,
                                  LoginAttemptContext context, int failedAttempts,
                                  Duration lockout) {
    publishGuarded(auditService, () -> new BruteForceLimitReached(
        at,
        context.username() == null ? "" : context.username(),
        context.clientAddress(),
        failedAttempts,
        lockout));
  }

  /**
   * Publishes {@link RateLimitExceeded} for attempts the {@link CredentialCheckGate} deferred
   * (JS-SEC-063, CWE-770): every permit was busy for the whole wait. The event names no user -
   * the gate bounds all logins together. The gate publishes at most one such event a second
   * and hands over how many deferrals it stands for (exit review RF11, CWE-779).
   *
   * @param auditService  the gate's audit service, or {@code null} for the registered one
   * @param at            event time
   * @param maxConcurrent the gate's permits - the limit
   * @param gateWait      how long each attempt waited; zero is recorded as one nanosecond,
   *                      because the event requires a positive window
   * @param deferrals     the deferrals since the previous event, the current one included -
   *                      recorded as {@link RateLimitExceeded#eventsInWindow()}; positive
   */
  static void publishCredentialCheckDeferred(JCustosAuditService auditService, Instant at,
                                             int maxConcurrent, Duration gateWait,
                                             int deferrals) {
    Duration window = gateWait.isZero() || gateWait.isNegative() ? Duration.ofNanos(1) : gateWait;
    publishGuarded(auditService, () -> new RateLimitExceeded(
        at, CredentialCheckGate.AUDIT_SCOPE, "", maxConcurrent, window, deferrals));
  }

  /** @return audit-sink failures seen since the class was loaded - for tests */
  static long sinkFailures() {
    return SINK_FAILURES.get();
  }

  /** @return {@code bruteforce/audit-sink-failed} lines logged since the class was loaded - for tests */
  static long warningsLogged() {
    return WARNINGS_LOGGED.get();
  }

  private static void publishGuarded(JCustosAuditService auditService,
                                     Supplier<AuditEvent> event) {
    String type = "audit event";
    try {
      JCustosAuditService sink = auditService != null
          ? auditService
          : JCustosServiceResolver.securityAuditService();
      AuditEvent built = event.get();
      type = built.getClass().getSimpleName();
      sink.publish(built);
    } catch (RuntimeException auditFailure) {
      // never block a security decision because the audit sink failed - but say so
      sinkFailed(type, auditFailure);
    }
  }

  /**
   * JS-SEC-123 (CWE-778): counts a failed publish and logs it, rate-limited. The exception
   * message is scrubbed: a sink may echo the event, and the event carries the user name the
   * client typed.
   */
  private static void sinkFailed(String eventType, RuntimeException failure) {
    long failures = SINK_FAILURES.incrementAndGet();
    long now = System.nanoTime();
    long due = NEXT_WARNING_AT.get();
    boolean first = due == 0L;
    if ((first || now - due >= 0L) && NEXT_WARNING_AT.compareAndSet(due, now + WARNING_INTERVAL_NANOS)) {
      WARNINGS_LOGGED.incrementAndGet();
      HasLogger.staticLogger().warn("bruteforce/audit-sink-failed: the audit sink refused a {} event"
          + " ({} failed publication(s) so far); login decisions are unaffected, the audit trail"
          + " is not: {}: {}", eventType, failures, failure.getClass().getName(),
          LogFieldScrubber.scrubMessage(String.valueOf(failure.getMessage())));
    }
  }
}
