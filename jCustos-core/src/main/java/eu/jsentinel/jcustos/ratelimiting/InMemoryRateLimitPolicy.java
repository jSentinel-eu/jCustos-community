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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

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
 * <h2>Retry-after (since 00.84.00)</h2>
 * <p>{@link RateLimitDecision.Throttled#retryAfter()} is the time until the
 * oldest event in the window has left it: {@code oldest + window - now}, plus
 * {@link #MIN_RETRY_AFTER}, because the window includes its start - an event
 * exactly {@code window} old still counts. A request at {@code now + retryAfter}
 * finds a free slot, a request one nanosecond earlier does not. When more events
 * than the limit are in the window (a lowered limit, {@code recordEvent} calls)
 * it is a lower bound. Until 00.84.00 it was the whole window. A store that does
 * not report the oldest event ({@link RateLimitStore.Admission#oldestInWindow()}
 * empty) still yields the whole window.</p>
 *
 * <h2>Escalation (opt-in, since 00.84.00)</h2>
 * <p>With a {@link RateLimitEscalation} the policy also counts the key's
 * throttles - under the key {@link #THROTTLE_SCOPE_PREFIX}{@code + scope} in the
 * same store, admitted through {@link RateLimitStore#tryAdmit}, so that parallel
 * throttles cannot all stay below the threshold. The throttle that reaches it
 * blocks the key for the block duration ({@link RateLimitStore#block}) and is answered with
 * {@link RateLimitDecision.Blocked}, as is every request while the block lasts;
 * a blocked request records nothing. Each throttle publishes one
 * {@link RateLimitExceeded}, the one that starts the block included. The store has
 * to keep blocks: a store whose {@link RateLimitStore#blockedUntil} refuses with
 * {@link UnsupportedOperationException} is refused at construction. Without an
 * escalation the policy never blocks and never reads a block.</p>
 *
 * <h2>Audit of a blocked key (exit review RF11, CWE-779)</h2>
 * <p>The requests of a key that is already blocked are audited at most once a
 * second per key. The first refusal publishes a {@link RateLimitExceeded} at once;
 * the refusals within the following second are counted, not published; the first
 * refusal one second or more after the last event publishes the next one. For these
 * events {@link RateLimitExceeded#eventsInWindow()} is the number of refusals the
 * event stands for: those of the key since its previous event of this kind, the one
 * that publishes it included - {@code 1} for the first refusal. Summed over these
 * events, those of {@link #UNTRACKED_KEYS_AUDIT_SCOPE} included, plus the refusals
 * still counted, it is the number of blocked requests. The other components keep their
 * meaning: the scope of the key, the policy's limit and window. A refusal that is
 * counted after the last event of its key is reported by the next refusal of that
 * key, or by {@link #purgeOldEvents()}, which publishes every count whose second is
 * over - a burst that ends within a second of the last event is not reported before
 * one of the two happens. Such an event carries the correlation id of the request,
 * or of the thread, that publishes it.</p>
 *
 * <p>The counts of at most 10 000 keys are kept. A key that is refused for the first
 * time while all of them are taken evicts the key with the oldest event, if that event
 * is at least a second old; the evicted key's counted refusals then move to the
 * aggregate scope {@link #UNTRACKED_KEYS_AUDIT_SCOPE}. When every tracked key has
 * published within the last second, the new key's refusals are counted under that
 * scope, again at most one event a second. However many keys a flood brings, the
 * blocked requests of one policy cost at most 10 001 events a second and a bounded
 * amount of memory; the refusals counted under the aggregate scope keep their count
 * but lose their scope. No refusal goes unaudited.</p>
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

  /**
   * Added to {@code oldest + window - now} for the retry-after of a throttled
   * request, and its least value: one nanosecond, the smallest unit of
   * {@link Instant}. The window includes its start, so the oldest event leaves it
   * one unit after {@code oldest + window}.
   *
   * @since 00.84.00
   */
  public static final Duration MIN_RETRY_AFTER = Duration.ofNanos(1);

  /**
   * Scope prefix of the keys under which an escalating policy counts the
   * throttles of a key: {@value}. Reserved - with an escalation, {@link #tryAcquire}
   * refuses keys whose scope starts with it, so that no request can be counted as
   * another key's throttle.
   *
   * @since 00.84.00
   */
  public static final String THROTTLE_SCOPE_PREFIX = "#throttled:";

  /**
   * The {@link RateLimitExceeded#scope()} under which an escalating policy counts the
   * refusals of blocked keys whose counts it cannot keep individually: {@value}. Its
   * {@link RateLimitExceeded#eventsInWindow()} is the number of such refusals since the
   * previous event of this scope; see the class description. It starts with
   * {@link #THROTTLE_SCOPE_PREFIX}, which an escalating policy refuses as the scope of a
   * request, so no request key shares it.
   *
   * @since 00.84.00
   */
  public static final String UNTRACKED_KEYS_AUDIT_SCOPE = THROTTLE_SCOPE_PREFIX + "untracked-keys";

  /** Key the constructor asks for a block, to learn whether the store keeps blocks. */
  private static final RateLimitKey BLOCK_PROBE =
      new RateLimitKey(TenantId.DEFAULT, THROTTLE_SCOPE_PREFIX + "probe");

  private final RateLimitStore store;
  private final JCustosAuditService auditService;
  private final int limit;
  private final Duration window;
  private final Clock clock;
  /** {@code null} when the policy does not escalate. */
  private final RateLimitEscalation escalation;
  /** Audit throttle of the refusals of blocked keys; {@code null} when the policy does not escalate. */
  private final RefusalAuditThrottle blockedRefusals;

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
   * @param limit        max events per {@code window}; strictly positive and at
   *                     most {@link RateLimitStore#maxEventsPerKey()} of the store
   * @param window       sliding-window duration; non-null, strictly positive
   * @param clock        time source; non-null
   * @throws IllegalArgumentException if {@code limit} exceeds the per-key bound of
   *                                  the store (since 00.84.00): the store would
   *                                  refuse every request beyond its bound, so the
   *                                  configured limit would never take effect
   */
  public InMemoryRateLimitPolicy(RateLimitStore store,
                                 JCustosAuditService auditService,
                                 int limit,
                                 Duration window,
                                 Clock clock) {
    this(store, auditService, limit, window, clock, Optional.empty());
  }

  /**
   * Full constructor of a policy that blocks a key which keeps hitting its limit
   * (since 00.84.00). There is deliberately no overload without the clock: next to
   * the constructor with a {@link Clock}, a call with a literal {@code null} would no
   * longer compile.
   *
   * @param store        non-null; must keep blocks ({@link RateLimitStore#block})
   * @param auditService non-null
   * @param limit        max events per {@code window}; strictly positive and at
   *                     most {@link RateLimitStore#maxEventsPerKey()} of the store
   * @param window       sliding-window duration; non-null, strictly positive
   * @param clock        time source; non-null
   * @param escalation   when to block and for how long; non-null
   * @throws IllegalArgumentException as {@link #InMemoryRateLimitPolicy(RateLimitStore,
   *                                  JCustosAuditService, int, Duration, Clock)}, and when
   *                                  the store keeps no blocks or the escalation's
   *                                  threshold exceeds the store's per-key bound
   * @since 00.84.00
   */
  public InMemoryRateLimitPolicy(RateLimitStore store,
                                 JCustosAuditService auditService,
                                 int limit,
                                 Duration window,
                                 Clock clock,
                                 RateLimitEscalation escalation) {
    this(store, auditService, limit, window, clock,
        Optional.of(requireNonNull(escalation, "escalation must not be null")));
  }

  private InMemoryRateLimitPolicy(RateLimitStore store,
                                  JCustosAuditService auditService,
                                  int limit,
                                  Duration window,
                                  Clock clock,
                                  Optional<RateLimitEscalation> escalation) {
    this.store = requireNonNull(store, "store must not be null");
    this.auditService = requireNonNull(auditService, "auditService must not be null");
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be strictly positive");
    }
    // XR08 (CWE-1284): InMemoryRateLimitStore keeps at most maxEventsPerKey events per
    // key and refuses beyond that, so a larger limit was capped without a word.
    int storeBound = store.maxEventsPerKey();
    if (limit > storeBound) {
      throw new IllegalArgumentException("limit " + limit + " exceeds the " + storeBound
          + " events the rate-limit store keeps per key, so it would never take effect; "
          + "lower the limit or construct the store with a larger maxEventsPerKey");
    }
    requireNonNull(window, "window must not be null");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be strictly positive");
    }
    this.limit = limit;
    this.window = window;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.escalation = escalation.map(wanted -> requireStoreCanEscalate(store, wanted)).orElse(null);
    this.blockedRefusals = this.escalation == null
        ? null
        : new RefusalAuditThrottle(new RateLimitKey(TenantId.DEFAULT, UNTRACKED_KEYS_AUDIT_SCOPE));
  }

  /** Refuses an escalation the store could not carry out - fail closed, at construction. */
  private static RateLimitEscalation requireStoreCanEscalate(RateLimitStore store,
                                                             RateLimitEscalation escalation) {
    int storeBound = store.maxEventsPerKey();
    if (escalation.throttleThreshold() > storeBound) {
      throw new IllegalArgumentException("throttleThreshold " + escalation.throttleThreshold()
          + " exceeds the " + storeBound + " events the rate-limit store keeps per key, so the"
          + " escalation would never block; lower the threshold or use a larger store bound");
    }
    try {
      store.blockedUntil(BLOCK_PROBE);
    } catch (UnsupportedOperationException noBlocks) {
      throw new IllegalArgumentException("the rate-limit store " + store.getClass().getName()
          + " keeps no blocks (RateLimitStore.blockedUntil / block), so the escalation could"
          + " never block; use a store that implements them, or no escalation", noBlocks);
    }
    return escalation;
  }

  @Override
  public RateLimitDecision tryAcquire(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    Instant now = clock.instant();
    if (escalation != null) {
      if (key.scope().startsWith(THROTTLE_SCOPE_PREFIX)) {
        throw new IllegalArgumentException("scopes that start with " + THROTTLE_SCOPE_PREFIX
            + " are reserved for the throttle counts of an escalating rate-limit policy");
      }
      Optional<Instant> blockedUntil = store.blockedUntil(key);
      if (blockedUntil.isPresent() && now.isBefore(blockedUntil.get())) {
        // blocked: nothing is recorded, neither an event nor a throttle
        int events = store.countSince(key, minusSaturating(now, window));
        // RF11 (CWE-779): at most one audit event per key and second, carrying the count
        publish(now, blockedRefusals.refused(key, now));
        return new RateLimitDecision.Blocked(events, limit, window,
            Duration.between(now, blockedUntil.get()), escalation.throttleThreshold());
      }
    }
    // saturating like every other operation of this class: a window beyond the timeline
    // (about a billion years) counts every event instead of throwing on every request
    Instant cutoff = minusSaturating(now, window);
    // JS-SEC-078 (CWE-367): check and record as one step — the store decides
    // atomically whether this event still fits the window, so N concurrent
    // callers at limit-1 cannot all pass. Throttled calls record nothing: only
    // admitted events count toward the window.
    RateLimitStore.Admission admission = store.tryAdmit(key, now, cutoff, limit);
    if (admission.admitted()) {
      return new RateLimitDecision.Allowed(admission.eventsInWindow(), limit, window);
    }
    publishExceeded(now, key, admission.eventsInWindow());
    if (escalation != null && reachesThreshold(key, now)) {
      Instant until = store.block(key, plusSaturating(now, escalation.blockDuration()));
      // the throttles that caused this block do not count towards the next one
      store.reset(throttleKey(key));
      return new RateLimitDecision.Blocked(admission.eventsInWindow(), limit, window,
          positive(Duration.between(now, until)), escalation.throttleThreshold());
    }
    return new RateLimitDecision.Throttled(admission.eventsInWindow(), limit, window,
        retryAfter(admission, now));
  }

  /**
   * Counts this throttle against the key's escalation window, as one step in the store, so
   * that parallel throttles cannot all stay below the threshold. A throttle that finds the
   * count already at the threshold - a block lifted by {@code store.reset(key)} alone, or a
   * parallel throttle that is about to block - escalates as well; the block only grows.
   */
  private boolean reachesThreshold(RateLimitKey key, Instant now) {
    int threshold = escalation.throttleThreshold();
    RateLimitStore.Admission throttle = store.tryAdmit(throttleKey(key), now,
        minusSaturating(now, escalation.escalationWindow()), threshold);
    return throttle.eventsInWindow() >= threshold;
  }

  /** @return {@code oldest + window - now + MIN_RETRY_AFTER}; the window if the store is silent */
  private Duration retryAfter(RateLimitStore.Admission admission, Instant now) {
    if (admission.oldestInWindow().isEmpty()) {
      return window; // a store that does not report the oldest event: the shape before 00.84.00
    }
    Instant leaves = plusSaturating(admission.oldestInWindow().get(), window);
    Duration untilLeft = Duration.between(now, leaves);
    if (untilLeft.isNegative()) {
      return MIN_RETRY_AFTER; // never negative, whatever a foreign store reports
    }
    try {
      return untilLeft.plus(MIN_RETRY_AFTER);
    } catch (ArithmeticException beyondDuration) {
      return untilLeft;
    }
  }

  private static Duration positive(Duration duration) {
    return duration.isNegative() || duration.isZero() ? MIN_RETRY_AFTER : duration;
  }

  private static RateLimitKey throttleKey(RateLimitKey key) {
    return new RateLimitKey(key.tenant(), THROTTLE_SCOPE_PREFIX + key.scope());
  }

  private static Instant plusSaturating(Instant instant, Duration duration) {
    try {
      return instant.plus(duration);
    } catch (DateTimeException | ArithmeticException beyondTheTimeline) {
      return Instant.MAX;
    }
  }

  private static Instant minusSaturating(Instant instant, Duration duration) {
    try {
      return instant.minus(duration);
    } catch (DateTimeException | ArithmeticException beyondTheTimeline) {
      return Instant.MIN;
    }
  }

  /**
   * Resets the per-key state — typically after a successful
   * authentication that cancels the throttle. With an escalation it also
   * lifts the key's block and forgets its throttles (since 00.84.00).
   *
   * @param key non-null
   */
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    store.reset(key);
    if (escalation != null) {
      store.reset(throttleKey(key));
    }
  }

  /**
   * Convenience: purges every event older than {@code now - window}
   * across all keys - with an escalation, older than the longer of the window
   * and the escalation window, so that the throttles the escalation still counts
   * survive (since 00.84.00); blocks that ended before that go as well.
   * Idempotent; safe to schedule — unless the store is
   * shared with a policy that has a longer window: the purge covers all keys
   * of the store and would remove events that policy still counts
   * (JS-SEC-118). Purge with the longest window then, or give each policy
   * its own store.
   *
   * <p>With an escalation it also publishes the counted refusals of blocked keys
   * whose second is over, one {@link RateLimitExceeded} per key, and forgets the
   * keys that have nothing counted (exit review RF11). Scheduled outside a request,
   * those events carry no correlation id.</p>
   *
   * @return number of events removed
   */
  public int purgeOldEvents() {
    Instant now = clock.instant();
    Duration retention = window;
    if (escalation != null) {
      publish(now, blockedRefusals.flushDue(now));
      if (escalation.escalationWindow().compareTo(window) > 0) {
        retention = escalation.escalationWindow();
      }
    }
    return store.purgeOlderThan(minusSaturating(now, retention));
  }

  /** @return configured per-window limit */
  public int limit() {
    return limit;
  }

  /** @return configured window duration */
  public Duration window() {
    return window;
  }

  /**
   * @return the configured escalation; empty when the policy never blocks
   * @since 00.84.00
   */
  public Optional<RateLimitEscalation> escalation() {
    return Optional.ofNullable(escalation);
  }

  /** @return the audit throttle of blocked keys, {@code null} without an escalation - for tests */
  RefusalAuditThrottle blockedRefusalAudit() {
    return blockedRefusals;
  }

  /** Publishes what the audit throttle of blocked keys released - outside its lock. */
  private void publish(Instant at, List<RefusalAuditThrottle.Publication> publications) {
    for (RefusalAuditThrottle.Publication publication : publications) {
      publishExceeded(at, publication.key(), publication.refusals());
    }
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
