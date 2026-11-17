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
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounds how many credential checks run at the same time (JS-SEC-063, CWE-770).
 *
 * <p>The throttle of a {@link LoginAttemptPolicy} counts failures per key; it does nothing
 * against a flood of logins for many distinct accounts, each of which costs a full credential
 * check - a memory-hard KDF, a directory round trip. This gate holds a fixed number of permits.
 * A login enters the gate after {@link LoginAttemptPolicy#beforeAttempt beforeAttempt} allowed it
 * and leaves it when the check has returned:
 *
 * <pre>{@code
 * CredentialCheckGate gate = policy.credentialCheckGate();
 * if (policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.LockedOut lockout) { ... }
 * switch (gate.enter()) {
 *   case CredentialCheckGate.Admission.Deferred deferred -> {
 *     policy.abandonAttempt(attempt);          // no verdict, nothing counted
 *     // answer "try again" with deferred.retryAfter() - HTTP 429 + Retry-After
 *   }
 *   case CredentialCheckGate.Admission.Entered permit -> {
 *     boolean valid;
 *     try {
 *       valid = authenticationService.checkCredentials(credentials);
 *     } finally {
 *       permit.close();
 *     }
 *     // report the outcome to the policy as before
 *   }
 * }
 * }</pre>
 *
 * <p>When no permit becomes free within {@link LoginAttemptLimits#gateWait()} the attempt is
 * {@linkplain Admission.Deferred deferred}: it is answered like a short lockout, with
 * {@link LoginAttemptLimits#gateRetryAfter()} as its retry-after, the credentials are not
 * evaluated and nothing is counted against the account. Every deferral is audited as
 * {@link RateLimitExceeded} with the scope {@link #AUDIT_SCOPE} and logged as
 * {@code bruteforce/credential-check-deferred}, at most once a minute. An interrupted wait
 * defers as well - fail closed, never a check without a permit.
 *
 * <p>The library {@code LoginView} and {@code StandaloneLoginFlow} use the gate of the
 * registered policy. The gate of {@link #unbounded()} - the default of
 * {@link LoginAttemptPolicy#credentialCheckGate()} and of every policy without
 * {@link LoginAttemptLimits#maxConcurrentCredentialChecks()} - admits every attempt at once.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class CredentialCheckGate implements HasLogger {

  /** The {@link RateLimitExceeded#scope()} of a deferred credential check: {@value}. */
  public static final String AUDIT_SCOPE = "login:credential-check";

  /** At most one {@code bruteforce/credential-check-deferred} line per this interval. */
  private static final long WARNING_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();

  private static final CredentialCheckGate UNBOUNDED = new CredentialCheckGate(
      LoginAttemptLimits.UNBOUNDED_CREDENTIAL_CHECKS, Duration.ZERO,
      LoginAttemptLimits.DEFAULT_GATE_RETRY_AFTER, Clock.systemUTC(), null);

  private final int maxConcurrent;
  private final Duration wait;
  private final Duration retryAfter;
  private final Clock clock;
  private final JCustosAuditService auditService;
  /** {@code null} for the unbounded gate. */
  private final Semaphore permits;
  private final Admission.Entered unboundedEntry;
  private final AtomicLong deferrals = new AtomicLong();
  /** {@link System#nanoTime()} from which the next warning may be logged; 0 before the first. */
  private final AtomicLong nextWarningAt = new AtomicLong();

  private CredentialCheckGate(int maxConcurrent, Duration wait, Duration retryAfter, Clock clock,
                              JCustosAuditService auditService) {
    this.maxConcurrent = maxConcurrent;
    this.wait = wait;
    this.retryAfter = retryAfter;
    this.clock = clock;
    this.auditService = auditService;
    this.permits = maxConcurrent == LoginAttemptLimits.UNBOUNDED_CREDENTIAL_CHECKS
        ? null
        : new Semaphore(maxConcurrent, true);
    this.unboundedEntry = permits == null ? new Admission.Entered(null) : null;
  }

  /**
   * @return the gate that admits every attempt at once
   */
  public static CredentialCheckGate unbounded() {
    return UNBOUNDED;
  }

  /**
   * The gate for {@code limits}: {@link #unbounded()} when
   * {@link LoginAttemptLimits#maxConcurrentCredentialChecks()} is
   * {@link LoginAttemptLimits#UNBOUNDED_CREDENTIAL_CHECKS}, otherwise a new gate with that many
   * permits. Each call builds its own permits; a policy builds its gate once and hands out that
   * instance.
   *
   * @param limits       the limits; non-null
   * @param clock        time source of the audit event; non-null
   * @param auditService audit sink, or {@code null} to resolve the registered one on each event
   * @return the gate
   */
  public static CredentialCheckGate of(LoginAttemptLimits limits, Clock clock,
                                       JCustosAuditService auditService) {
    Objects.requireNonNull(limits, "limits");
    Objects.requireNonNull(clock, "clock");
    if (!limits.credentialChecksBounded()) {
      return UNBOUNDED;
    }
    return new CredentialCheckGate(limits.maxConcurrentCredentialChecks(), limits.gateWait(),
        limits.gateRetryAfter(), clock, auditService);
  }

  /**
   * @return {@code true} when the gate holds a fixed number of permits
   */
  public boolean bounded() {
    return permits != null;
  }

  /**
   * @return the number of permits, or {@link LoginAttemptLimits#UNBOUNDED_CREDENTIAL_CHECKS}
   */
  public int maxConcurrent() {
    return maxConcurrent;
  }

  /**
   * @return permits in use right now; {@code 0} for the unbounded gate
   */
  public int inUse() {
    return permits == null ? 0 : maxConcurrent - permits.availablePermits();
  }

  /**
   * @return attempts this gate has deferred since it was built
   */
  public long deferredCount() {
    return deferrals.get();
  }

  /**
   * Asks for a permit and waits at most {@link LoginAttemptLimits#gateWait()} for it.
   *
   * @return {@link Admission.Entered} - run the credential check and close the permit
   *         afterwards - or {@link Admission.Deferred} - do not run the check; never
   *         {@code null}
   */
  public Admission enter() {
    if (permits == null) {
      return unboundedEntry;
    }
    boolean acquired;
    try {
      acquired = permits.tryAcquire(wait.toNanos(), TimeUnit.NANOSECONDS);
    } catch (InterruptedException interrupted) {
      // fail closed: a thread that is being stopped does not run a check without a permit
      Thread.currentThread().interrupt();
      acquired = false;
    }
    if (acquired) {
      return new Admission.Entered(permits);
    }
    return defer();
  }

  private Admission.Deferred defer() {
    long total = deferrals.incrementAndGet();
    // JS-SEC-063 (CWE-770): audited through the existing variant, as every other throttle is
    LoginFailureAudit.publishCredentialCheckDeferred(auditService, Instant.now(clock),
        maxConcurrent, wait);
    long now = System.nanoTime();
    long due = nextWarningAt.get();
    if ((due == 0L || now - due >= 0L)
        && nextWarningAt.compareAndSet(due, now + WARNING_INTERVAL_NANOS)) {
      logger().warn("bruteforce/credential-check-deferred: all {} credential-check permits were"
          + " busy for {} ms; the attempt was deferred without being evaluated ({} so far).",
          maxConcurrent, wait.toMillis(), total);
    }
    return new Admission.Deferred(retryAfter);
  }

  /**
   * Outcome of {@link #enter()}.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public sealed interface Admission permits Admission.Entered, Admission.Deferred {

    /**
     * A permit was granted. Run the credential check, then {@link #close()} the permit - in a
     * {@code finally} block or with try-with-resources. Closing more than once releases one
     * permit only.
     */
    final class Entered implements Admission, AutoCloseable {

      private final Semaphore permits;
      private final AtomicBoolean closed = new AtomicBoolean();

      private Entered(Semaphore permits) {
        this.permits = permits;
      }

      /** Gives the permit back. */
      @Override
      public void close() {
        if (permits != null && closed.compareAndSet(false, true)) {
          permits.release();
        }
      }
    }

    /**
     * No permit became free in time. Do not run the credential check, give the attempt back
     * with {@link LoginAttemptPolicy#abandonAttempt abandonAttempt} and answer "try again"
     * after {@code retryAfter}.
     *
     * @param retryAfter when the caller may try again; positive
     */
    record Deferred(Duration retryAfter) implements Admission {

      /** Validates the component. */
      public Deferred {
        Objects.requireNonNull(retryAfter, "retryAfter");
        if (retryAfter.isNegative() || retryAfter.isZero()) {
          throw new IllegalArgumentException("retryAfter must be positive");
        }
      }
    }
  }
}
