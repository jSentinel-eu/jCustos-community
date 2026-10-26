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
package eu.jsentinel.jcustos.ratelimiting;

import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Default {@link RateLimitPolicy} backed by a {@link RateLimitStore}.
 * <p>
 * Sliding-window semantics: every {@link #tryAcquire tryAcquire}
 * counts the events recorded in the last {@code window}; if the
 * count is below the configured {@code limit} a fresh event is
 * recorded and {@link RateLimitDecision.Allowed} is returned;
 * otherwise the request is refused with
 * {@link RateLimitDecision.Throttled} and a
 * {@link RateLimitExceeded} audit event is published.
 *
 * <p>The audit emit-side optionally derives a {@code subjectId}
 * from the {@link RateLimitKey#scope()} when the scope begins
 * with the {@code "subject:"} prefix — purely a convenience so
 * audit consumers can pivot on subject without parsing the
 * composite scope themselves. For other scopes the audit event's
 * {@code subjectId} is empty.
 *
 * <p>Thread-safe via the underlying store.
 *
 * <p>For brute-force / password-guessing detection, use
 * {@link eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy
 * LoginAttemptPolicy} instead — same shape but with progressive
 * backoff and lockout semantics. This policy is for steady-state
 * traffic shaping.
 */
@ExperimentalJCustosApi
public final class InMemoryRateLimitPolicy implements RateLimitPolicy {

  private static final String SUBJECT_PREFIX = "subject:";

  private final RateLimitStore store;
  private final JCustosAuditService auditService;
  private final int limit;
  private final Duration window;
  private final Clock clock;

  /**
   * @param store        non-null
   * @param auditService non-null
   * @param limit        max events per {@code window}; strictly positive
   * @param window       sliding-window duration; non-null, strictly positive
   */
  public InMemoryRateLimitPolicy(RateLimitStore store,
                                 JCustosAuditService auditService,
                                 int limit,
                                 Duration window) {
    this(store, auditService, limit, window, Clock.systemUTC());
  }

  /**
   * Full constructor.
   *
   * @param store        non-null
   * @param auditService non-null
   * @param limit        max events per {@code window}; strictly positive
   * @param window       sliding-window duration; non-null, strictly positive
   * @param clock        time source; non-null
   */
  public InMemoryRateLimitPolicy(RateLimitStore store,
                                 JCustosAuditService auditService,
                                 int limit,
                                 Duration window,
                                 Clock clock) {
    this.store = requireNonNull(store, "store must not be null");
    this.auditService = requireNonNull(auditService, "auditService must not be null");
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be strictly positive");
    }
    requireNonNull(window, "window must not be null");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be strictly positive");
    }
    this.limit = limit;
    this.window = window;
    this.clock = requireNonNull(clock, "clock must not be null");
  }

  @Override
  public RateLimitDecision tryAcquire(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    Instant now = clock.instant();
    Instant cutoff = now.minus(window);
    // JS-SEC-078 (CWE-367): check and record as one step — the store decides
    // atomically whether this event still fits the window, so N concurrent
    // callers at limit-1 cannot all pass. Throttled calls record nothing: only
    // admitted events count toward the window.
    RateLimitStore.Admission admission = store.tryAdmit(key, now, cutoff, limit);
    if (!admission.admitted()) {
      Duration retryAfter = window;
      publishExceeded(now, key, admission.eventsInWindow());
      return new RateLimitDecision.Throttled(admission.eventsInWindow(), limit, window, retryAfter);
    }
    return new RateLimitDecision.Allowed(admission.eventsInWindow(), limit, window);
  }

  /**
   * Resets the per-key state — typically after a successful
   * authentication that cancels the throttle.
   *
   * @param key non-null
   */
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    store.reset(key);
  }

  /**
   * Convenience: purges every event older than {@code now - window}
   * across all keys. Idempotent; safe to schedule.
   *
   * @return number of events removed
   */
  public int purgeOldEvents() {
    return store.purgeOlderThan(clock.instant().minus(window));
  }

  /** @return configured per-window limit */
  public int limit() {
    return limit;
  }

  /** @return configured window duration */
  public Duration window() {
    return window;
  }

  private void publishExceeded(Instant at, RateLimitKey key, int observed) {
    String scope = key.scope();
    String subjectId = scope.startsWith(SUBJECT_PREFIX)
        ? scope.substring(SUBJECT_PREFIX.length())
        : "";
    try {
      auditService.publish(new RateLimitExceeded(
          at, scope, subjectId, limit, window, observed));
    } catch (RuntimeException ignored) {
      // sinks must not block rate-limiting decisions
    }
  }
}
