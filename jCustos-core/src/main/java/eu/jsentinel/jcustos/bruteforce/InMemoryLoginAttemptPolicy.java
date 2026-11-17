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
import java.util.Optional;

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
 * <h2>Password spraying: the address counter (JS-SEC-062, CWE-307)</h2>
 *
 * <p>The two counters above are per account. One address that tries a
 * password or two against each of many accounts stays below all of them.
 * With {@link LoginAttemptLimits#perAddress()} set, a third counter on the
 * client address alone catches that: its own threshold, window and
 * progressive lockout, the same reservation of attempts in flight, the same
 * capacity bound and the same promise never to evict a live lockout. The
 * counter is used only for an attempt that carries a client address. A
 * successful login releases its reservation but does not reset it - an
 * attacker with one account of their own could otherwise reset the counter
 * of the address they spray from. A lockout of the address is audited as
 * {@link BruteForceLimitReached} with an empty user name. Without
 * {@code perAddress} - the default - the counter does not exist.
 *
 * <h2>Concurrent credential checks (JS-SEC-063, CWE-770)</h2>
 *
 * <p>{@link #credentialCheckGate()} returns the gate of the policy's
 * {@link LoginAttemptLimits}: unbounded by default, a fixed number of permits
 * with {@link LoginAttemptLimits#maxConcurrentCredentialChecks()}.
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
 * <p>Each of the maps (account and user name, and the address map when the
 * address counter is on) holds at most {@code maxEntries} keys - a hard
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
 *       failure threshold - with an empty user name when the key is an
 *       address</li>
 *   <li>{@link eu.jsentinel.jcustos.audit.RateLimitExceeded} when the
 *       {@link #credentialCheckGate() gate} defers an attempt</li>
 * </ul>
 *
 * <p>Audit-sink failures never break the security flow that emitted them.
 * They are counted and logged as {@code bruteforce/audit-sink-failed}, at most
 * once a minute; until 00.84.00 they were swallowed without a trace.
 *
 * <h2>A failure that cannot be stored (JS-SEC-122, CWE-770)</h2>
 *
 * <p>A failure reported after its reservation lapsed finds no entry for its
 * key; when the table is full of lockouts and attempts in flight at that
 * moment, there is no room for one either. Such a failure is not counted
 * against the key - the table neither grows nor gives up a lockout - but it
 * is no longer lost silently: it is counted, logged as
 * {@code bruteforce/failure-not-recorded} at most once a minute, and the key
 * is not reported as locked by it. Attempts on that key are refused anyway
 * while the table stays full.</p>
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

  private final LoginAttemptLimits limits;
  private final LoginAttemptConfiguration config;
  /** Thresholds of the address counter; {@code null} while it is off (JS-SEC-062). */
  private final LoginAttemptConfiguration addressConfig;
  private final CredentialCheckGate gate;
  private final Clock clock;
  private final JCustosAuditService auditService;
  private final SubjectKeyCanonicalizer canonicalizer;
  private final int maxEntries;
  private final Object monitor = new Object();
  private final BoundedAttemptTable<CombinedKey, State> byCombinedKey;
  private final BoundedAttemptTable<String, State> byUsername;
  /** {@code null} while the address counter is off. */
  private final BoundedAttemptTable<String, State> byAddress;
  private Instant lastCapacityWarning;
  private Instant lastUnrecordedWarning;
  /** Failures that found no room in a table (JS-SEC-122); guarded by {@link #monitor}. */
  private long unrecordedFailures;

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
    this(LoginAttemptLimits.of(Objects.requireNonNull(config, "config")), clock, auditService,
        maxEntries, canonicalizer);
  }

  /**
   * JS-SEC-062 / JS-SEC-063: a policy with the address counter and the bound on concurrent
   * credential checks of {@code limits}, the default capacity and the default canonicaliser.
   *
   * @param limits       thresholds; non-null
   * @param clock        time source
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link JCustosServiceResolver} on each event
   * @since 00.84.00
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptLimits limits,
                                    Clock clock,
                                    JCustosAuditService auditService) {
    this(limits, clock, auditService, CapacityBound.DEFAULT_MAX_ENTRIES,
        SubjectKeyCanonicalizer.defaults());
  }

  /**
   * Full constructor (JS-SEC-062, JS-SEC-063).
   *
   * @param limits        thresholds, address counter and bound on concurrent credential checks;
   *                      non-null
   * @param clock         time source
   * @param auditService  audit sink, or {@code null} to resolve from
   *                      {@link JCustosServiceResolver} on each event
   * @param maxEntries    per-map key cap
   * @param canonicalizer maps a user name onto its throttle key; non-null
   * @since 00.84.00
   */
  public InMemoryLoginAttemptPolicy(LoginAttemptLimits limits,
                                    Clock clock,
                                    JCustosAuditService auditService,
                                    int maxEntries,
                                    SubjectKeyCanonicalizer canonicalizer) {
    this.limits = Objects.requireNonNull(limits, "limits");
    this.config = limits.perAccount();
    this.addressConfig = limits.perAddress()
        .map(LoginAttemptLimits.AddressLimit::asConfiguration)
        .orElse(null);
    this.clock = Objects.requireNonNull(clock, "clock");
    this.auditService = auditService;
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.byCombinedKey = new BoundedAttemptTable<>(maxEntries, null);
    this.byUsername = new BoundedAttemptTable<>(maxEntries, null);
    this.byAddress = addressConfig == null ? null : new BoundedAttemptTable<>(maxEntries, null);
    this.gate = CredentialCheckGate.of(limits, clock, auditService);
  }

  /**
   * @return the limits this policy counts with
   * @since 00.84.00
   */
  public LoginAttemptLimits limits() {
    return limits;
  }

  /**
   * The gate of this policy's {@link LoginAttemptLimits}; the same instance on every call.
   *
   * @return the gate
   * @since 00.84.00
   */
  @Override
  public CredentialCheckGate credentialCheckGate() {
    return gate;
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

  /** Package-visible for tests: number of tracked address entries (JS-SEC-062). */
  int trackedAddressCount() {
    synchronized (monitor) {
      return byAddress == null ? 0 : byAddress.size();
    }
  }

  /** Package-visible for tests: failures that found no room in a table (JS-SEC-122). */
  long unrecordedFailureCount() {
    synchronized (monitor) {
      return unrecordedFailures;
    }
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    String usernameKey = combinedKey.username();
    String addressKey = addressKey(combinedKey);

    boolean capacityExhausted = false;
    LoginAttemptDecision decision;
    synchronized (monitor) {
      State combined = byCombinedKey.get(combinedKey, now);
      State user = byUsername.get(usernameKey, now);
      State address = addressKey == null ? null : byAddress.get(addressKey, now);

      Optional<LoginAttemptDecision> locked = firstLockout(now, combined, user, address);
      if (locked.isPresent()) {
        return locked.get();
      }

      // JS-SEC-123 (CWE-367): the check and the reservation are one step. Requests that arrive
      // together see each other's attempts in flight instead of all reading "below threshold".
      combined = prepare(combined, now, config);
      user = prepare(user, now, config);
      if (addressKey != null) {
        address = prepare(address, now, addressConfig);
      }
      Optional<LoginAttemptDecision> saturated = saturation(combined, now, config);
      if (saturated.isEmpty()) {
        saturated = saturation(user, now, config);
      }
      if (saturated.isEmpty() && addressKey != null) {
        // JS-SEC-062 (CWE-307): a spray across many accounts saturates the address
        saturated = saturation(address, now, addressConfig);
      }
      if (saturated.isPresent()) {
        return saturated.get();
      }

      Instant reservedUntil = plus(now, ATTEMPT_RESERVATION_TTL);
      combined.reserve(reservedUntil);
      if (!store(byCombinedKey, combinedKey, combined, now, config)) {
        decision = capacityRefusal(byCombinedKey, now);
        capacityExhausted = true;
      } else {
        user.reserve(reservedUntil);
        if (!store(byUsername, usernameKey, user, now, config)) {
          combined.release(now);
          store(byCombinedKey, combinedKey, combined, now, config);
          decision = capacityRefusal(byUsername, now);
          capacityExhausted = true;
        } else if (addressKey != null) {
          address.reserve(reservedUntil);
          if (!store(byAddress, addressKey, address, now, addressConfig)) {
            combined.release(now);
            store(byCombinedKey, combinedKey, combined, now, config);
            user.release(now);
            store(byUsername, usernameKey, user, now, config);
            decision = capacityRefusal(byAddress, now);
            capacityExhausted = true;
          } else {
            decision = LoginAttemptDecision.allowed();
          }
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
    String addressKey = addressKey(combinedKey);
    synchronized (monitor) {
      return firstLockout(now,
          byCombinedKey.get(combinedKey, now), byUsername.get(combinedKey.username(), now),
          addressKey == null ? null : byAddress.get(addressKey, now))
          .orElseGet(LoginAttemptDecision::allowed);
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
    String addressKey = addressKey(combinedKey);

    synchronized (monitor) {
      State combined = byCombinedKey.get(combinedKey, now);
      State user = byUsername.get(usernameKey, now);
      State address = addressKey == null ? null : byAddress.get(addressKey, now);
      if (combined != null) {
        combined.release(now);
      }
      if (user != null) {
        user.release(now);
      }
      if (address != null) {
        address.release(now);
      }
      Optional<LoginAttemptDecision> locked = firstLockout(now, combined, user, address);
      if (locked.isPresent()) {
        // JS-SEC-123 (CWE-307): the key was locked while this attempt was being checked. The
        // lockout stays, and the caller is told to deny the login.
        restore(byCombinedKey, combinedKey, combined, now, config);
        restore(byUsername, usernameKey, user, now, config);
        restore(byAddress, addressKey, address, now, addressConfig);
        return locked.get();
      }
      if (combined != null) {
        combined.clear();
        store(byCombinedKey, combinedKey, combined, now, config);
      }
      if (user != null) {
        user.clear();
        store(byUsername, usernameKey, user, now, config);
      }
      // JS-SEC-062: the address counter keeps its failures - one account of the attacker's own
      // must not reset the counter of the address they spray from. Only the slot is given back.
      restore(byAddress, addressKey, address, now, addressConfig);
      return LoginAttemptDecision.allowed();
    }
  }

  @Override
  public void abandonAttempt(LoginAttemptContext context) {
    Objects.requireNonNull(context, "context");
    Instant now = Instant.now(clock);
    CombinedKey combinedKey = combinedKey(context);
    String usernameKey = combinedKey.username();
    String addressKey = addressKey(combinedKey);

    // JS-SEC-126 (CWE-703): the check produced no verdict - release the slot, count nothing.
    synchronized (monitor) {
      State combined = byCombinedKey.get(combinedKey, now);
      if (combined != null) {
        combined.release(now);
        store(byCombinedKey, combinedKey, combined, now, config);
      }
      State user = byUsername.get(usernameKey, now);
      if (user != null) {
        user.release(now);
        store(byUsername, usernameKey, user, now, config);
      }
      State address = addressKey == null ? null : byAddress.get(addressKey, now);
      if (address != null) {
        address.release(now);
        store(byAddress, addressKey, address, now, addressConfig);
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
    String addressKey = addressKey(combinedKey);

    State justLocked;
    Instant lockedUntil;
    int totalFailures;
    Instant addressLockedUntil = null;
    int addressFailures = 0;
    boolean unrecordedWarningDue = false;
    long unrecordedSoFar = 0;
    synchronized (monitor) {
      State combined = recordOn(byCombinedKey, combinedKey, now, config);
      State user = recordOn(byUsername, usernameKey, now, config);
      State address = addressKey == null
          ? null
          : recordOn(byAddress, addressKey, now, addressConfig);
      justLocked = combined.justLocked ? combined : user.justLocked ? user : null;
      lockedUntil = justLocked == null ? null : justLocked.lockedUntil;
      totalFailures = justLocked == null ? 0 : justLocked.totalFailuresObserved;
      if (address != null && address.justLocked) {
        addressLockedUntil = address.lockedUntil;
        addressFailures = address.totalFailuresObserved;
      }
      if (combined.unrecorded || user.unrecorded || (address != null && address.unrecorded)) {
        unrecordedFailures++;
        unrecordedSoFar = unrecordedFailures;
        unrecordedWarningDue = unrecordedWarningDue(now);
      }
    }
    if (unrecordedWarningDue) {
      // JS-SEC-122 (CWE-770): never silent - a failure that does not count is a gap in the throttle.
      logger().warn("bruteforce/failure-not-recorded: a failed login arrived after its reservation"
          + " had lapsed and the {} tracked login keys were all locked or in flight; the failure"
          + " was not counted ({} so far).", maxEntries, unrecordedSoFar);
    }

    LoginFailureAudit.publish(auditService, Instant.now(clock), context, reason);
    if (justLocked != null) {
      auditBruteForceLimitReached(context, lockedUntil, totalFailures, now);
    }
    if (addressLockedUntil != null) {
      // JS-SEC-062: the lockout belongs to the address, not to the account that was tried last
      auditBruteForceLimitReached(new LoginAttemptContext("", context.clientAddress(),
          context.sessionId(), context.timestamp()), addressLockedUntil, addressFailures, now);
    }
  }

  private <K> State recordOn(BoundedAttemptTable<K, State> table, K key, Instant now,
                             LoginAttemptConfiguration thresholds) {
    State state = prepare(table.get(key, now), now, thresholds);
    state.release(now);
    state.addFailure(now, thresholds);
    state.unrecorded = !store(table, key, state, now, thresholds);
    if (state.unrecorded) {
      // JS-SEC-122: nothing was stored, so there is no lockout to announce either
      state.justLocked = false;
    }
    return state;
  }

  /** Returns a state ready for this call: outdated failures dropped, lapsed reservations gone. */
  private static State prepare(State state, Instant now, LoginAttemptConfiguration thresholds) {
    if (state == null) {
      return new State();
    }
    state.justLocked = false;
    state.unrecorded = false;
    if (state.firstFailureAt != null
        && now.isAfter(plus(state.firstFailureAt, thresholds.window()))) {
      state.failures = 0;
      state.firstFailureAt = null;
    }
    state.pruneReservations(now);
    return state;
  }

  /**
   * The first lockout in force among {@code states}; {@code null} entries are skipped.
   *
   * @return the lockout, or empty when none of the states is locked
   */
  private static Optional<LoginAttemptDecision> firstLockout(Instant now, State... states) {
    for (State state : states) {
      Optional<LoginAttemptDecision> decision = lockoutDecision(state, now);
      if (decision.isPresent()) {
        return decision;
      }
    }
    return Optional.empty();
  }

  /** @return the lockout of {@code state}, or empty when it is absent or not locked */
  private static Optional<LoginAttemptDecision> lockoutDecision(State state, Instant now) {
    if (state == null || !state.isLocked(now)) {
      return Optional.empty();
    }
    return Optional.of(LoginAttemptDecision.lockedOut(nonNegative(now, state.lockedUntil),
        state.totalFailuresObserved));
  }

  /**
   * Denies when the failures counted plus the attempts in flight have used up the threshold.
   *
   * @return the denial, or empty while the threshold has room
   */
  private static Optional<LoginAttemptDecision> saturation(State state, Instant now,
                                                           LoginAttemptConfiguration thresholds) {
    if (state.failures + state.inFlight() < thresholds.failureThreshold()) {
      return Optional.empty();
    }
    return Optional.of(LoginAttemptDecision.lockedOut(
        nonNegative(now, state.earliestReservationEnd()), state.totalFailuresObserved));
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

  private boolean unrecordedWarningDue(Instant now) {
    if (lastUnrecordedWarning != null
        && now.isBefore(plus(lastUnrecordedWarning, CAPACITY_WARNING_INTERVAL))
        && !now.isBefore(lastUnrecordedWarning)) {
      return false;
    }
    lastUnrecordedWarning = now;
    return true;
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
   * Writes {@code state} back with the deadlines that follow from its content and
   * {@code thresholds}; a state that holds nothing any more is removed.
   *
   * @return {@code false} when the key is new and the table refused it
   */
  private static <K> boolean store(BoundedAttemptTable<K, State> table, K key, State state,
                                   Instant now, LoginAttemptConfiguration thresholds) {
    Instant reservedUntil = state.latestReservationEnd();
    Instant lockEnds = state.isLocked(now) ? state.lockedUntil : null;
    // failures count up to and including the instant the window ends, see prepare(...)
    Instant failuresEnd = state.firstFailureAt == null
        ? null
        : plus(plus(state.firstFailureAt, thresholds.window()), Duration.ofNanos(1));
    // the lockout level is remembered for one maxLockout after the lockout ended, so that a
    // repeat offender still escalates while the map does not keep every key for ever
    Instant levelEnds = state.lockedUntil == null
        ? null
        : plus(state.lockedUntil, thresholds.maxLockout());
    Instant expiresAt = latest(latest(failuresEnd, levelEnds), reservedUntil);
    if (expiresAt == null || !expiresAt.isAfter(now)) {
      table.remove(key);
      return true;
    }
    return table.put(key, state, expiresAt, latest(lockEnds, reservedUntil), now);
  }

  private static <K> void restore(BoundedAttemptTable<K, State> table, K key, State state,
                                  Instant now, LoginAttemptConfiguration thresholds) {
    if (state != null) {
      store(table, key, state, now, thresholds);
    }
  }

  private CombinedKey combinedKey(LoginAttemptContext context) {
    return new CombinedKey(canonicalUsername(context.username()),
        normaliseAddress(context.clientAddress()));
  }

  /**
   * JS-SEC-062: the key of the address counter, or {@code null} when the counter is off or the
   * attempt carries no client address - an address that is not known is not counted.
   */
  private String addressKey(CombinedKey combinedKey) {
    return byAddress == null || combinedKey.clientAddress().isEmpty()
        ? null
        : combinedKey.clientAddress();
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
    // a failing sink is counted and reported by LoginFailureAudit (JS-SEC-123, CWE-778)
    LoginFailureAudit.publishLimitReached(auditService, Instant.now(clock), context,
        totalFailures, nonNegative(now, lockedUntil));
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
    /** The last {@code recordOn} found no room for this state (JS-SEC-122). */
    private boolean unrecorded;
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
