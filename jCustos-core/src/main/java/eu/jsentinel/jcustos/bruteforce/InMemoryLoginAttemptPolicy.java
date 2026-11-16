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
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.util.CapacityBound;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.Objects;

/**
 * In-memory {@link LoginAttemptPolicy} suitable for single-node demos
 * and small deployments.
 * <p>
 * Counts failures per (username, clientAddress) pair plus an additional
 * username-only counter so an attacker cannot cycle clients to evade the
 * combined counter. The username passes through the configured
 * {@link SubjectKeyCanonicalizer} (default: NFKC, lower-case, trimmed), the
 * client address is trimmed and lower-cased, before either is used as a key.
 * <p>
 * After {@link LoginAttemptConfiguration#failureThreshold()} failures
 * inside {@link LoginAttemptConfiguration#window()} the key is locked
 * for {@link LoginAttemptConfiguration#initialLockout()}. Repeated
 * breaches double the lockout up to
 * {@link LoginAttemptConfiguration#maxLockout()} (progressive backoff).
 * A successful login resets both counters - unless a lockout is in force,
 * which a success never lifts (see {@link #confirmSuccess}).
 *
 * <h2>Attempts in flight (JS-SEC-123, CWE-367)</h2>
 *
 * <p>{@link #beforeAttempt} does not merely read. Under the policy's monitor
 * it checks the lockouts, counts the attempt as in flight on both keys and
 * allows it only while {@code failures + inFlight} stays below the
 * threshold. The report that follows - {@link #recordFailure},
 * {@link #confirmSuccess}/{@link #recordSuccess} or {@link #abandonAttempt} -
 * releases the reservation. Fifty requests that arrive together therefore
 * get at most {@code failureThreshold} evaluations; the others receive
 * {@link LoginAttemptDecision.LockedOut} with the time until a slot frees up.
 * A reservation whose report never comes lapses after
 * {@link #ATTEMPT_RESERVATION_TTL}.
 *
 * <h2>Capacity (JS-SEC-122, CWE-307, CWE-770)</h2>
 *
 * <p>Each of the two maps holds at most {@code maxEntries} keys - a hard
 * bound. A key that is locked or has an attempt in flight is never evicted.
 * State that has expired (failures older than the window, a lockout that
 * ended more than {@code maxLockout} ago) is dropped on the next call via an
 * expiry index. When room is still needed the unprotected entry written
 * longest ago goes; when every entry is protected, an attempt on a new key
 * is denied with {@link LoginAttemptDecision.LockedOut} until the first
 * lockout ends, and {@code bruteforce/capacity-exhausted} is logged.
 *
 * <h2>Audit</h2>
 *
 * <p>The policy emits audit events through the
 * {@link JCustosServiceResolver#securityAuditService() resolved}
 * {@link JCustosAuditService}:
 *
 * <ul>
 *   <li>{@link LoginFailed} on every
 *       {@link #recordFailure(LoginAttemptContext) recordFailure} - the one
 *       event of a rejected login, see {@link LoginAttemptPolicy#recordFailure}</li>
 *   <li>{@link BruteForceLimitReached} the first time a key crosses the
 *       failure threshold</li>
 * </ul>
 *
 * <p>Audit-sink failures are swallowed — they must never break the
 * security flow that emitted them.
 */
public final class InMemoryLoginAttemptPolicy implements LoginAttemptPolicy, HasLogger {

  /**
   * How long an allowed attempt counts as in flight when no report follows. Long enough for a
   * memory-hard KDF behind a saturated limiter or a remote identity provider, short enough that
   * a caller which loses a report does not hold the slot for the length of a lockout.
   *
   * @since 00.84.00
   */
  public static final Duration ATTEMPT_RESERVATION_TTL = Duration.ofSeconds(30);

  /** At most one {@code bruteforce/capacity-exhausted} line per this interval. */
  private static final Duration CAPACITY_WARNING_INTERVAL = Duration.ofMinutes(1);

  private final LoginAttemptConfiguration config;
  private final Clock clock;
  private final JCustosAuditService auditService;
  private final SubjectKeyCanonicalizer canonicalizer;
  private final int maxEntries;
  private final Object monitor = new Object();
  private final BoundedAttemptTable<CombinedKey, State> byCombinedKey;
  private final BoundedAttemptTable<String, State> byUsername;
  private Instant lastCapacityWarning;

  /** Defaults — suitable for single-node demos. */
  public InMemoryLoginAttemptPolicy() {
    this(LoginAttemptConfiguration.defaults(), Clock.systemUTC(), null);
  }

  /**
   * @param config       throttling thresholds
   * @param clock        time source — fixed clocks make testing deterministic
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link JCustosServiceResolver} on each event
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptConfiguration config,
                                    Clock clock,
                                    JCustosAuditService auditService) {
    this(config, clock, auditService, CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * JS-SEC-048 (CWE-770): additionally bound the per-key maps. Both maps are keyed on
   * attacker-controlled username / client address, so a spray of distinct throwaway usernames would
   * otherwise grow the heap without limit. JS-SEC-122 (CWE-307, CWE-770): the bound is hard, and an
   * in-force lockout is never evicted (the RF01 invariant) - see the type description for what
   * happens when only lockouts remain.
   *
   * @param maxEntries per-map key cap (shared default {@link CapacityBound#DEFAULT_MAX_ENTRIES})
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptConfiguration config,
                                    Clock clock,
                                    JCustosAuditService auditService,
                                    int maxEntries) {
    this(config, clock, auditService, maxEntries, SubjectKeyCanonicalizer.defaults());
  }

  /**
   * JS-SEC-123 (CWE-178): the canonicaliser decides which spellings of a user name are the same
   * account. Hand the same instance to the credential store, otherwise two accounts share one
   * counter or one account gets several.
   *
   * @param canonicalizer maps a user name onto its throttle key; non-null
   * @since 00.84.00
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptConfiguration config,
                                    Clock clock,
                                    JCustosAuditService auditService,
                                    int maxEntries,
                                    SubjectKeyCanonicalizer canonicalizer) {
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.auditService = auditService;
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.byCombinedKey = new BoundedAttemptTable<>(maxEntries, null);
    this.byUsername = new BoundedAttemptTable<>(maxEntries, null);
  }

  /** Package-visible for tests: number of tracked combined-key entries (JS-SEC-048 bound). */
  int trackedCombinedKeyCount() {
    synchronized (monitor) {
      return byCombinedKey.size();
    }
  }

  /** Package-visible for tests: number of tracked username entries (JS-SEC-122 bound). */
  int trackedUsernameCount() {
    synchronized (monitor) {
      return byUsername.size();
    }
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    String usernameKey = combinedKey.username();

    boolean capacityExhausted = false;
    LoginAttemptDecision decision;
    synchronized (monitor) {
      State combined = byCombinedKey.get(combinedKey, now);
      State user = byUsername.get(usernameKey, now);

      LoginAttemptDecision locked = firstLockout(combined, user, now);
      if (locked != null) {
        return locked;
      }

      // JS-SEC-123 (CWE-367): the check and the reservation are one step. Requests that arrive
      // together see each other's attempts in flight instead of all reading "below threshold".
      combined = prepare(combined, now);
      user = prepare(user, now);
      LoginAttemptDecision saturated = saturation(combined, now);
      if (saturated == null) {
        saturated = saturation(user, now);
      }
      if (saturated != null) {
        return saturated;
      }

      Instant reservedUntil = plus(now, ATTEMPT_RESERVATION_TTL);
      combined.reserve(reservedUntil);
      if (!store(byCombinedKey, combinedKey, combined, now)) {
        decision = capacityRefusal(byCombinedKey, now);
        capacityExhausted = true;
      } else {
        user.reserve(reservedUntil);
        if (!store(byUsername, usernameKey, user, now)) {
          combined.release(now);
          store(byCombinedKey, combinedKey, combined, now);
          decision = capacityRefusal(byUsername, now);
          capacityExhausted = true;
        } else {
          decision = LoginAttemptDecision.allowed();
        }
      }
      if (capacityExhausted) {
        capacityExhausted = capacityWarningDue(now);
      }
    }
    if (capacityExhausted) {
      // JS-SEC-122 (CWE-770): never silent - the throttle is refusing accounts it does not track.
      logger().warn("bruteforce/capacity-exhausted: all {} tracked login keys are locked or have an "
          + "attempt in flight; attempts on further keys are denied until the first lockout ends.",
          maxEntries);
    }
    return decision;
  }

  @Override
  public LoginAttemptDecision peek(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    synchronized (monitor) {
      LoginAttemptDecision locked = firstLockout(
          byCombinedKey.get(combinedKey, now), byUsername.get(combinedKey.username(), now), now);
      return locked != null ? locked : LoginAttemptDecision.allowed();
    }
  }

  @Override
  public void recordSuccess(LoginAttemptContext context) {
    confirmSuccess(context);
  }

  @Override
  public LoginAttemptDecision confirmSuccess(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    String usernameKey = combinedKey.username();

    synchronized (monitor) {
      State combined = byCombinedKey.get(combinedKey, now);
      State user = byUsername.get(usernameKey, now);
      if (combined != null) {
        combined.release(now);
      }
      if (user != null) {
        user.release(now);
      }
      LoginAttemptDecision locked = firstLockout(combined, user, now);
      if (locked != null) {
        // JS-SEC-123 (CWE-307): the key was locked while this attempt was being checked. The
        // lockout stays, and the caller is told to deny the login.
        restore(byCombinedKey, combinedKey, combined, now);
        restore(byUsername, usernameKey, user, now);
        return locked;
      }
      if (combined != null) {
        combined.clear();
        store(byCombinedKey, combinedKey, combined, now);
      }
      if (user != null) {
        user.clear();
        store(byUsername, usernameKey, user, now);
      }
      return LoginAttemptDecision.allowed();
    }
  }

  @Override
  public void abandonAttempt(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    String usernameKey = combinedKey.username();

    // JS-SEC-126 (CWE-703): the check produced no verdict - release the slot, count nothing.
    synchronized (monitor) {
      State combined = byCombinedKey.get(combinedKey, now);
      if (combined != null) {
        combined.release(now);
        store(byCombinedKey, combinedKey, combined, now);
      }
      State user = byUsername.get(usernameKey, now);
      if (user != null) {
        user.release(now);
        store(byUsername, usernameKey, user, now);
      }
    }
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    recordFailure(context, REASON_CREDENTIALS_REJECTED);
  }

  @Override
  public void recordFailure(LoginAttemptContext context, String reason) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    String usernameKey = combinedKey.username();

    State justLocked;
    Instant lockedUntil;
    int totalFailures;
    synchronized (monitor) {
      State combined = recordOn(byCombinedKey, combinedKey, now);
      State user = recordOn(byUsername, usernameKey, now);
      justLocked = combined.justLocked ? combined : user.justLocked ? user : null;
      lockedUntil = justLocked == null ? null : justLocked.lockedUntil;
      totalFailures = justLocked == null ? 0 : justLocked.totalFailuresObserved;
    }

    LoginFailureAudit.publish(auditService, Instant.now(clock), context, reason);
    if (justLocked != null) {
      auditBruteForceLimitReached(context, lockedUntil, totalFailures, now);
    }
  }

  private <K> State recordOn(BoundedAttemptTable<K, State> table, K key, Instant now) {
    State state = prepare(table.get(key, now), now);
    state.release(now);
    state.addFailure(now, config);
    store(table, key, state, now);
    return state;
  }

  /** Returns a state ready for this call: outdated failures dropped, lapsed reservations gone. */
  private State prepare(State state, Instant now) {
    if (state == null) {
      return new State();
    }
    state.justLocked = false;
    if (state.firstFailureAt != null && now.isAfter(plus(state.firstFailureAt, config.window()))) {
      state.failures = 0;
      state.firstFailureAt = null;
    }
    state.pruneReservations(now);
    return state;
  }

  private static LoginAttemptDecision firstLockout(State combined, State user, Instant now) {
    LoginAttemptDecision decision = lockoutDecision(combined, now);
    return decision != null ? decision : lockoutDecision(user, now);
  }

  private static LoginAttemptDecision lockoutDecision(State state, Instant now) {
    if (state == null || !state.isLocked(now)) {
      return null;
    }
    return LoginAttemptDecision.lockedOut(nonNegative(now, state.lockedUntil),
        state.totalFailuresObserved);
  }

  /** Denies when the failures counted plus the attempts in flight have used up the threshold. */
  private LoginAttemptDecision saturation(State state, Instant now) {
    if (state.failures + state.inFlight() < config.failureThreshold()) {
      return null;
    }
    return LoginAttemptDecision.lockedOut(
        nonNegative(now, state.earliestReservationEnd()), state.totalFailuresObserved);
  }

  /**
   * JS-SEC-122 (CWE-770): the map is full of lockouts and attempts in flight. The new key is
   * denied until the first of them ends - the map neither grows nor gives up a lockout.
   */
  private static LoginAttemptDecision capacityRefusal(BoundedAttemptTable<?, State> table,
                                                      Instant now) {
    Instant retryAt = table.earliestProtectionEnd().orElse(now);
    return LoginAttemptDecision.lockedOut(nonNegative(now, retryAt), 0);
  }

  private boolean capacityWarningDue(Instant now) {
    if (lastCapacityWarning != null
        && now.isBefore(plus(lastCapacityWarning, CAPACITY_WARNING_INTERVAL))
        && !now.isBefore(lastCapacityWarning)) {
      return false;
    }
    lastCapacityWarning = now;
    return true;
  }

  /**
   * Writes {@code state} back with the deadlines that follow from its content; a state that
   * holds nothing any more is removed.
   *
   * @return {@code false} when the key is new and the table refused it
   */
  private <K> boolean store(BoundedAttemptTable<K, State> table, K key, State state, Instant now) {
    Instant reservedUntil = state.latestReservationEnd();
    Instant lockEnds = state.isLocked(now) ? state.lockedUntil : null;
    // failures count up to and including the instant the window ends, see prepare(...)
    Instant failuresEnd = state.firstFailureAt == null
        ? null
        : plus(plus(state.firstFailureAt, config.window()), Duration.ofNanos(1));
    // the lockout level is remembered for one maxLockout after the lockout ended, so that a
    // repeat offender still escalates while the map does not keep every key for ever
    Instant levelEnds = state.lockedUntil == null
        ? null
        : plus(state.lockedUntil, config.maxLockout());
    Instant expiresAt = latest(latest(failuresEnd, levelEnds), reservedUntil);
    if (expiresAt == null || !expiresAt.isAfter(now)) {
      table.remove(key);
      return true;
    }
    return table.put(key, state, expiresAt, latest(lockEnds, reservedUntil), now);
  }

  private <K> void restore(BoundedAttemptTable<K, State> table, K key, State state, Instant now) {
    if (state != null) {
      store(table, key, state, now);
    }
  }

  private CombinedKey combinedKey(LoginAttemptContext context) {
    return new CombinedKey(canonicalUsername(context.username()),
        normaliseAddress(context.clientAddress()));
  }

  private String canonicalUsername(String value) {
    return value == null ? "" : canonicalizer.canonicalize(value);
  }

  private static String normaliseAddress(String value) {
    return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
  }

  private static Duration nonNegative(Instant from, Instant to) {
    if (to == null || !to.isAfter(from)) {
      return Duration.ZERO;
    }
    return Duration.between(from, to);
  }

  private static Instant latest(Instant a, Instant b) {
    if (a == null) {
      return b;
    }
    if (b == null) {
      return a;
    }
    return a.isAfter(b) ? a : b;
  }

  private static Instant plus(Instant instant, Duration duration) {
    try {
      return instant.plus(duration);
    } catch (DateTimeException | ArithmeticException overflow) {
      return Instant.MAX;
    }
  }

  private void auditBruteForceLimitReached(
      LoginAttemptContext context, Instant lockedUntil, int totalFailures, Instant now) {
    JCustosAuditService sink = sink();
    try {
      sink.publish(new BruteForceLimitReached(
          Instant.now(clock),
          context.username() == null ? "" : context.username(),
          context.clientAddress(),
          totalFailures,
          nonNegative(now, lockedUntil)));
    } catch (RuntimeException auditFailure) {
      // never block a security decision because the audit sink failed
    }
  }

  private JCustosAuditService sink() {
    return auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
  }

  // ── State ─────────────────────────────────────────────────────

  /**
   * The (user, client) key. A record instead of a joined string, so a separator inside a user
   * name cannot make two different pairs collide.
   */
  private record CombinedKey(String username, String clientAddress) {
  }

  /**
   * Per-key throttling state; only touched under the policy's monitor.
   * {@link #totalFailuresObserved} is the failure count since the key was last cleared - what the
   * {@link LoginAttemptDecision.LockedOut#failedAttempts()} field reports.
   */
  private static final class State {
    private int failures;
    private Instant firstFailureAt;
    private Instant lockedUntil;
    private int lockoutLevel;
    private boolean justLocked;
    private int totalFailuresObserved;
    /** End of each attempt in flight, oldest first; {@code null} while there is none. */
    private ArrayDeque<Instant> reservations;

    private boolean isLocked(Instant now) {
      return lockedUntil != null && now.isBefore(lockedUntil);
    }

    private void addFailure(Instant now, LoginAttemptConfiguration config) {
      failures++;
      totalFailuresObserved++;
      if (firstFailureAt == null) {
        firstFailureAt = now;
      }
      if (failures >= config.failureThreshold()) {
        lockoutLevel++;
        lockedUntil = plus(now, lockoutDuration(lockoutLevel, config));
        failures = 0;
        firstFailureAt = null;
        justLocked = true;
      }
    }

    /** A successful login: everything but the attempts still in flight is forgotten. */
    private void clear() {
      failures = 0;
      firstFailureAt = null;
      lockedUntil = null;
      lockoutLevel = 0;
      justLocked = false;
      totalFailuresObserved = 0;
    }

    private int inFlight() {
      return reservations == null ? 0 : reservations.size();
    }

    private void reserve(Instant until) {
      if (reservations == null) {
        reservations = new ArrayDeque<>(2);
      }
      reservations.addLast(until);
    }

    /** Drops lapsed reservations, then the oldest one that is still running. */
    private void release(Instant now) {
      pruneReservations(now);
      if (reservations != null) {
        reservations.pollFirst();
        if (reservations.isEmpty()) {
          reservations = null;
        }
      }
    }

    private void pruneReservations(Instant now) {
      if (reservations == null) {
        return;
      }
      while (!reservations.isEmpty() && !reservations.peekFirst().isAfter(now)) {
        reservations.pollFirst();
      }
      if (reservations.isEmpty()) {
        reservations = null;
      }
    }

    private Instant earliestReservationEnd() {
      return reservations == null ? null : reservations.peekFirst();
    }

    private Instant latestReservationEnd() {
      return reservations == null ? null : reservations.peekLast();
    }

    private static Duration lockoutDuration(int level, LoginAttemptConfiguration config) {
      Duration initial = config.initialLockout();
      Duration max = config.maxLockout();

      // 1 -> initial, 2 -> 2x, 3 -> 4x ... capped at max
      long shift = Math.max(0, level - 1);
      Duration scaled;
      try {
        scaled = initial.multipliedBy(1L << Math.min(shift, 30));
      } catch (ArithmeticException overflow) {
        scaled = max;
      }
      return scaled.compareTo(max) > 0 ? max : scaled;
    }
  }
}
