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
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link LoginAttemptStore}. Suitable for tests, demos, and
 * single-process applications.
 *
 * <p>JS-SEC-122 (CWE-307, CWE-770) and JS-SEC-123 (CWE-367): the store
 * implements the atomic attempt operations of the SPI. Every operation runs
 * under one monitor, so "is the key locked, are there too many attempts in
 * flight, then reserve" is one step, and the entries live in a
 * {@link BoundedAttemptTable}:
 *
 * <ul>
 *   <li>the number of tracked keys never exceeds the configured bound;</li>
 *   <li>a key that is locked, or that has an attempt in flight, is never
 *       evicted — a spray of new keys cannot push a victim's lockout out;</li>
 *   <li>entries whose counter has outlived the window and whose lockout
 *       has ended are dropped on the next access, through an expiry index;</li>
 *   <li>when the store is full of entries it must keep, a new key is
 *       refused: {@link #tryBeginAttempt} answers "blocked" until the first
 *       lockout ends, instead of growing the map.</li>
 * </ul>
 *
 * <p>A lockout is not stored as a field of its own. It follows from the
 * counter, the last failure and the limits the entry was last written
 * with: locked while {@code failures >= failureThreshold} and
 * {@code now < lastFailureAt + lockout}. The same derivation is what the
 * SPI's default methods compute, so a persistent store that keeps only
 * counter and timestamp recovers its lockouts after a restart.
 *
 * <p>A failure reported after its reservation lapsed finds no entry for its
 * key, and when the store is full of entries it must keep there is no room
 * for one either. Such a failure is not counted against the key - the bound
 * holds and no lockout is evicted for it - but it is counted and logged as
 * {@code bruteforce/failure-not-recorded}, at most once a minute (JS-SEC-122,
 * CWE-770); until 00.84.00 it was lost without a trace. The status
 * {@link #completeFailure} returns is the one the failure would have caused.
 *
 * <p>The older {@link #recordFailure}/{@link #failureCount}/
 * {@link #lastFailureAt}/{@link #reset} keep working. An entry written only
 * through them carries no limits; the store then applies the limits it saw
 * first in an atomic operation, and treats the entry as unprotected until
 * it has seen any.
 */
@ExperimentalJCustosApi
public final class InMemoryLoginAttemptStore implements LoginAttemptStore, HasLogger {

  /** At most one {@code bruteforce/failure-not-recorded} line per this interval. */
  private static final Duration UNRECORDED_WARNING_INTERVAL = Duration.ofMinutes(1);

  private final Object monitor = new Object();
  /** Failures that found no room (JS-SEC-122); guarded by {@link #monitor}. */
  private long unrecordedFailures;
  /** When the last {@code bruteforce/failure-not-recorded} line was logged; guarded by the monitor. */
  private Instant lastUnrecordedWarning;
  private final BoundedAttemptTable<LoginAttemptKey, Ledger> table;
  /** The limits of the first atomic operation; applied to entries that carry none. */
  private AttemptLimits knownLimits;

  /** Creates an empty store bounded at {@link CapacityBound#DEFAULT_MAX_ENTRIES}. */
  public InMemoryLoginAttemptStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * JS-SEC-048 (CWE-770): the store is keyed on an attacker-controlled login key, so a spray of
   * distinct keys would grow the heap without limit. JS-SEC-122 (CWE-307): the bound is hard and
   * never costs a live lockout — see the type description.
   *
   * @param maxEntries key cap (shared default {@link CapacityBound#DEFAULT_MAX_ENTRIES})
   */
  public InMemoryLoginAttemptStore(int maxEntries) {
    this(maxEntries, null);
  }

  /**
   * For adapters that keep this store as their working state and mirror it elsewhere, such as
   * the Eclipse-Store adapter: {@code removalListener} is told about every key that leaves the
   * store — reset, expired or evicted — while the store's monitor is held. It must not call back
   * into the store.
   *
   * @param maxEntries      key cap
   * @param removalListener receives every removed key; may be {@code null}
   * @since 00.84.00
   */
  public InMemoryLoginAttemptStore(int maxEntries, Consumer<LoginAttemptKey> removalListener) {
    this.table = new BoundedAttemptTable<>(maxEntries, removalListener);
  }

  /** Package-visible for tests: number of tracked ledger keys (JS-SEC-048 / JS-SEC-122 bound). */
  int trackedKeyCount() {
    synchronized (monitor) {
      return table.size();
    }
  }

  /** Package-visible for tests: failures that found no room in the store (JS-SEC-122). */
  long unrecordedFailureCount() {
    synchronized (monitor) {
      return unrecordedFailures;
    }
  }

  /**
   * Puts a counter back that an adapter has read from its persistent copy. The entry behaves like
   * one written through {@link #recordFailure}: its lockout is derived as soon as the store knows
   * limits. When the store is full of entries it must keep, the counter is dropped and the
   * removal listener is told.
   *
   * @param key           failure dimension; must not be {@code null}
   * @param failures      failures held against the key; at least 1
   * @param lastFailureAt instant of the most recent failure; must not be {@code null}
   * @since 00.84.00
   */
  public void restore(LoginAttemptKey key, int failures, Instant lastFailureAt) {
    requireNonNull(key, "key must not be null");
    requireNonNull(lastFailureAt, "lastFailureAt must not be null");
    if (failures < 1) {
      throw new IllegalArgumentException("failures must be >= 1");
    }
    synchronized (monitor) {
      Ledger ledger = new Ledger();
      ledger.count = failures;
      ledger.lastFailureAt = lastFailureAt;
      store(key, ledger, lastFailureAt);
    }
  }

  // ── atomic attempt operations (JS-SEC-122, JS-SEC-123) ─────────────

  @Override
  public AttemptStatus tryBeginAttempt(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    requireNonNull(limits, "limits must not be null");
    synchronized (monitor) {
      adopt(limits, now);
      Ledger ledger = table.get(key, now);
      if (ledger != null) {
        Instant lockedUntil = lockedUntil(ledger, limits);
        if (lockedUntil != null && now.isBefore(lockedUntil)) {
          return AttemptStatus.blocked(ledger.count, lockedUntil);
        }
        forgetOutdatedCounter(ledger, limits, now);
        ledger.pruneReservations(now);
      } else {
        ledger = new Ledger();
      }
      // After a lockout has run out the counter still stands while the window lasts. One attempt
      // at a time is admitted then, and a single further failure locks the key again.
      int held = Math.min(ledger.count, limits.failureThreshold() - 1);
      if (held + ledger.inFlight() >= limits.failureThreshold()) {
        return AttemptStatus.blocked(ledger.count, ledger.earliestReservationEnd());
      }
      Instant reservedUntil = plus(now, limits.reservationTtl());
      ledger.reserve(reservedUntil);
      ledger.limits = limits;
      if (!store(key, ledger, now)) {
        // JS-SEC-122 (CWE-770): full of live lockouts and attempts in flight - refuse the new
        // key instead of growing or evicting one of them.
        return AttemptStatus.blocked(0, table.earliestProtectionEnd().orElse(reservedUntil));
      }
      return AttemptStatus.open(ledger.count);
    }
  }

  @Override
  public AttemptStatus completeFailure(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    requireNonNull(limits, "limits must not be null");
    synchronized (monitor) {
      adopt(limits, now);
      Ledger ledger = table.get(key, now);
      if (ledger == null) {
        ledger = new Ledger();
      } else {
        Instant lockedUntil = lockedUntil(ledger, limits);
        if (lockedUntil == null || !now.isBefore(lockedUntil)) {
          forgetOutdatedCounter(ledger, limits, now);
        }
      }
      ledger.release(now);
      ledger.count++;
      ledger.lastFailureAt = now;
      ledger.limits = limits;
      if (!store(key, ledger, now)) {
        failureNotRecorded(now);
      }
      Instant lockedUntil = lockedUntil(ledger, limits);
      return lockedUntil == null
          ? AttemptStatus.open(ledger.count)
          : AttemptStatus.blocked(ledger.count, lockedUntil);
    }
  }

  @Override
  public AttemptStatus completeSuccess(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    requireNonNull(limits, "limits must not be null");
    synchronized (monitor) {
      adopt(limits, now);
      Ledger ledger = table.get(key, now);
      if (ledger == null) {
        return AttemptStatus.open(0);
      }
      ledger.release(now);
      Instant lockedUntil = lockedUntil(ledger, limits);
      if (lockedUntil != null && now.isBefore(lockedUntil)) {
        // JS-SEC-123 (CWE-307): a success that arrives after the key was locked neither lifts
        // the lockout nor passes it.
        store(key, ledger, now);
        return AttemptStatus.blocked(ledger.count, lockedUntil);
      }
      ledger.count = 0;
      ledger.lastFailureAt = null;
      store(key, ledger, now);
      return AttemptStatus.open(0);
    }
  }

  @Override
  public void abandonAttempt(LoginAttemptKey key, Instant now) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    synchronized (monitor) {
      Ledger ledger = table.get(key, now);
      if (ledger == null) {
        return;
      }
      ledger.release(now);
      store(key, ledger, now);
    }
  }

  // ── counter primitives ─────────────────────────────────────────────

  @Override
  public void recordFailure(LoginAttemptKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    synchronized (monitor) {
      Ledger ledger = table.get(key, at);
      if (ledger == null) {
        ledger = new Ledger();
      }
      ledger.count++;
      ledger.lastFailureAt = at;
      if (!store(key, ledger, at)) {
        failureNotRecorded(at);
      }
    }
  }

  @Override
  public int failureCount(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    synchronized (monitor) {
      Ledger ledger = table.peek(key);
      return ledger == null ? 0 : ledger.count;
    }
  }

  @Override
  public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    synchronized (monitor) {
      Ledger ledger = table.peek(key);
      return ledger == null ? Optional.empty() : Optional.ofNullable(ledger.lastFailureAt);
    }
  }

  @Override
  public void reset(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    synchronized (monitor) {
      table.remove(key);
    }
  }

  // ── internals ──────────────────────────────────────────────────────

  /**
   * Writes {@code ledger} back with the deadlines that follow from its content; an entry that
   * holds nothing any more is removed.
   *
   * @return {@code false} when the key is new and the table refused it
   */
  private boolean store(LoginAttemptKey key, Ledger ledger, Instant now) {
    AttemptLimits effective = ledger.limits != null ? ledger.limits : knownLimits;
    Instant reservedUntil = ledger.latestReservationEnd();
    Instant lockedUntil = effective == null ? null : lockedUntil(ledger, effective);
    Instant counterEnds = ledger.lastFailureAt == null
        ? null
        : effective == null ? Instant.MAX : plus(ledger.lastFailureAt, effective.window());
    Instant expiresAt = latest(latest(lockedUntil, counterEnds), reservedUntil);
    if (expiresAt == null) {
      table.remove(key);
      return true;
    }
    return table.put(key, ledger, expiresAt, latest(lockedUntil, reservedUntil), now);
  }

  /**
   * Caller holds the monitor. JS-SEC-122 (CWE-770): a failure that found no room is counted and
   * reported - the table is full of lockouts and attempts in flight, and this key is not among
   * them.
   */
  private void failureNotRecorded(Instant now) {
    unrecordedFailures++;
    if (lastUnrecordedWarning != null
        && now.isBefore(plus(lastUnrecordedWarning, UNRECORDED_WARNING_INTERVAL))
        && !now.isBefore(lastUnrecordedWarning)) {
      return;
    }
    lastUnrecordedWarning = now;
    logger().warn("bruteforce/failure-not-recorded: a failed login arrived for a key the store no"
        + " longer tracked while all its entries were locked or in flight; the failure was not"
        + " counted ({} so far).", unrecordedFailures);
  }

  /** Remembers the first limits seen and derives the deadlines of entries that carry none. */
  private void adopt(AttemptLimits limits, Instant now) {
    if (knownLimits != null) {
      return;
    }
    knownLimits = limits;
    List<LoginAttemptKey> withoutLimits = new ArrayList<>();
    table.forEach((key, ledger) -> {
      if (ledger.limits == null) {
        withoutLimits.add(key);
      }
    });
    for (LoginAttemptKey key : withoutLimits) {
      Ledger ledger = table.peek(key);
      if (ledger != null) {
        store(key, ledger, now);
      }
    }
  }

  private static Instant lockedUntil(Ledger ledger, AttemptLimits limits) {
    if (ledger.lastFailureAt == null || ledger.count < limits.failureThreshold()) {
      return null;
    }
    return plus(ledger.lastFailureAt, limits.lockout());
  }

  /** Drops a counter whose last failure lies a full window back. */
  private static void forgetOutdatedCounter(Ledger ledger, AttemptLimits limits, Instant now) {
    if (ledger.lastFailureAt != null && !now.isBefore(plus(ledger.lastFailureAt, limits.window()))) {
      ledger.count = 0;
      ledger.lastFailureAt = null;
    }
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

  /** Mutable per-key state; only touched under the monitor. */
  private static final class Ledger {
    private int count;
    private Instant lastFailureAt;
    private AttemptLimits limits;
    /** End of each attempt in flight, oldest first; {@code null} while there is none. */
    private ArrayDeque<Instant> reservations;

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
  }
}
