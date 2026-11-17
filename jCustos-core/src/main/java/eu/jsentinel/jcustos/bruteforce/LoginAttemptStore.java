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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Persistent counter store for the {@link LoginAttemptPolicy} family.
 * <p>
 * The existing default {@code InMemoryLoginAttemptPolicy} keeps its
 * counters in process memory — fine for a single-instance demo, but
 * unsuited for clustered deployments or for tracking lockouts across
 * restarts. {@link StoreBackedLoginAttemptPolicy} delegates counter
 * mutation and lookup to a {@code LoginAttemptStore}, so the lockout state
 * survives the process and - with a store that all nodes reach - is shared
 * across nodes.
 *
 * <p>The API is behaviour-flavoured rather than pure CRUD because
 * the data shape is so narrow (counter + timestamp): callers either
 * record an additional failure, ask how many failures the key has
 * accumulated, or reset it on a successful login.
 *
 * <p>Implementations must be thread-safe; concurrent
 * {@code recordFailure} calls happen on every failed login.
 *
 * <h2>Atomic attempt operations (since 00.84.00)</h2>
 *
 * <p>{@link #tryBeginAttempt}, {@link #completeFailure},
 * {@link #completeSuccess} and {@link #abandonAttempt} are what
 * {@link StoreBackedLoginAttemptPolicy} calls. They exist because the four
 * methods above cannot express two things a throttle needs (JS-SEC-122,
 * JS-SEC-123):
 *
 * <ul>
 *   <li><strong>whether a key is locked right now</strong> — a store that
 *       only sees a counter and a timestamp cannot tell a live lockout
 *       from a stale counter, so a bounded store evicted lockouts under a
 *       spray of new keys;</li>
 *   <li><strong>check and count as one step</strong> — with a read in
 *       {@code beforeAttempt} and a write after the credential check, any
 *       number of parallel requests passed the read before the first
 *       failure was counted.</li>
 * </ul>
 *
 * <p>The four operations have {@code default} implementations built on the
 * older methods, so an existing store keeps compiling and keeps its former
 * behaviour: no reservation, no protection of lockouts against the store's
 * own eviction. A store that wants the full guarantees overrides all four
 * and performs each as one atomic step per key —
 * {@link InMemoryLoginAttemptStore} and the Eclipse-Store adapter do. The
 * shared contract in {@code jCustos-persistence-testkit} states what an
 * atomic implementation has to satisfy.
 *
 * <h2>Address keys (since 00.84.00)</h2>
 *
 * <p>With an address limit, {@link StoreBackedLoginAttemptPolicy} also counts
 * every attempt on {@link LoginAttemptKey#forAddress} (JS-SEC-062, CWE-307) -
 * an ordinary key with the reserved user id
 * {@link LoginAttemptKey#ADDRESS_USER_ID}, passed with limits of its own. A
 * store keeps it like any other key; nothing in this interface changes. A
 * store that derives the deadlines of restored entries from limits it has
 * seen should keep the limits of address keys apart from those of account
 * keys, as {@link InMemoryLoginAttemptStore} does.
 *
 * <h2>Account keys (since 00.84.00)</h2>
 *
 * <p>{@link StoreBackedLoginAttemptPolicy} also counts every attempt on
 * {@link LoginAttemptKey#forAccount} (JS-SEC-166, CWE-307) - an ordinary key
 * whose user id starts with {@link LoginAttemptKey#ACCOUNT_USER_ID_PREFIX} and
 * whose address is {@link LoginAttemptKey#ANY_ADDRESS}, passed with the account
 * limits. A store keeps it like any other key and stores it verbatim. A store
 * that several nodes share has to perform each attempt operation atomically in
 * its backend, not behind a lock inside one JVM; see
 * {@code docs/security/deployment/cluster.md}.
 */
@ExperimentalJCustosApi
public interface LoginAttemptStore {

  /**
   * Increments the failure counter for {@code key} by one and updates
   * its last-failure instant to {@code at}.
   *
   * @param key failure dimension; must not be {@code null}
   * @param at  instant the failure occurred; must not be {@code null}
   */
  void recordFailure(LoginAttemptKey key, Instant at);

  /**
   * Returns the number of failures currently held against {@code key}.
   * Zero when the key has never failed or has been {@link #reset(LoginAttemptKey)}.
   *
   * @param key failure dimension; must not be {@code null}
   * @return non-negative failure count
   */
  int failureCount(LoginAttemptKey key);

  /**
   * Returns the timestamp of the most recent failure on {@code key},
   * if any.
   *
   * @param key failure dimension; must not be {@code null}
   * @return last failure instant, or empty when never failed
   */
  Optional<Instant> lastFailureAt(LoginAttemptKey key);

  /**
   * Clears any state associated with {@code key} — used after a
   * successful login to start the counter from zero again.
   *
   * @param key failure dimension; must not be {@code null}
   */
  void reset(LoginAttemptKey key);

  /**
   * The thresholds a policy hands to the atomic attempt operations.
   *
   * @param failureThreshold failures that lock a key; at least 1
   * @param window           a counter is forgotten once no failure has been
   *                         recorded for this long; positive
   * @param lockout          how long a key stays locked after the failure
   *                         that reached the threshold; positive
   * @param reservationTtl   how long an admitted attempt is counted as in
   *                         flight when its outcome is never reported;
   *                         positive
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  record AttemptLimits(int failureThreshold, Duration window, Duration lockout,
                       Duration reservationTtl) {

    /** Validates the components. */
    public AttemptLimits {
      if (failureThreshold < 1) {
        throw new IllegalArgumentException("failureThreshold must be >= 1");
      }
      requirePositive(window, "window");
      requirePositive(lockout, "lockout");
      requirePositive(reservationTtl, "reservationTtl");
    }

    private static void requirePositive(Duration value, String name) {
      Objects.requireNonNull(value, name);
      if (value.isNegative() || value.isZero()) {
        throw new IllegalArgumentException(name + " must be positive");
      }
    }
  }

  /**
   * What a key looks like after an atomic attempt operation.
   *
   * @param failures     failures currently held against the key
   * @param blockedUntil present when the key refuses attempts: the end of
   *                     its lockout, the moment an attempt in flight frees
   *                     a slot, or — for a store that is full of live
   *                     lockouts — the moment the first of them ends
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  record AttemptStatus(int failures, Optional<Instant> blockedUntil) {

    /** Validates the components. */
    public AttemptStatus {
      if (failures < 0) {
        throw new IllegalArgumentException("failures must be >= 0");
      }
      Objects.requireNonNull(blockedUntil, "blockedUntil");
    }

    /**
     * @return {@code true} when the key refuses attempts
     */
    public boolean blocked() {
      return blockedUntil.isPresent();
    }

    /**
     * @param failures failures currently held against the key
     * @return a status that admits attempts
     */
    public static AttemptStatus open(int failures) {
      return new AttemptStatus(failures, Optional.empty());
    }

    /**
     * @param failures     failures currently held against the key
     * @param blockedUntil when the key admits attempts again
     * @return a status that refuses attempts
     */
    public static AttemptStatus blocked(int failures, Instant blockedUntil) {
      return new AttemptStatus(failures, Optional.of(blockedUntil));
    }
  }

  /**
   * Asks whether an attempt on {@code key} may proceed and, if so, counts
   * it as in flight — one step (JS-SEC-123, CWE-367).
   * <p>
   * An atomic implementation refuses when the key is locked, when the
   * failures held against it plus the attempts in flight have reached the
   * threshold, or when the key is new and the store is full of entries it
   * must not evict (JS-SEC-122, CWE-770). Otherwise it records the
   * reservation and admits. The default only evaluates the lockout from
   * {@link #failureCount} and {@link #lastFailureAt}; it reserves nothing.
   *
   * @param key    failure dimension; must not be {@code null}
   * @param now    current instant; must not be {@code null}
   * @param limits the caller's thresholds; must not be {@code null}
   * @return the key's status; {@link AttemptStatus#blocked()} means the
   *         attempt must not be evaluated
   * @since 00.84.00
   */
  default AttemptStatus tryBeginAttempt(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    Objects.requireNonNull(now, "now must not be null");
    Objects.requireNonNull(limits, "limits must not be null");
    return legacyLockStatus(key, now, limits);
  }

  /**
   * Reports that an admitted attempt failed: releases its reservation,
   * counts the failure and locks the key once the threshold is reached —
   * one step.
   *
   * @param key    failure dimension; must not be {@code null}
   * @param now    current instant; must not be {@code null}
   * @param limits the caller's thresholds; must not be {@code null}
   * @return the key's status after the failure
   * @since 00.84.00
   */
  default AttemptStatus completeFailure(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    Objects.requireNonNull(now, "now must not be null");
    Objects.requireNonNull(limits, "limits must not be null");
    recordFailure(key, now);
    return legacyLockStatus(key, now, limits);
  }

  /**
   * Reports that an admitted attempt succeeded: releases its reservation
   * and clears the counter — unless the key is locked. A live lockout is
   * kept and reported (JS-SEC-123, CWE-307); the caller then denies the
   * login.
   *
   * @param key    failure dimension; must not be {@code null}
   * @param now    current instant; must not be {@code null}
   * @param limits the caller's thresholds; must not be {@code null}
   * @return the key's status; {@link AttemptStatus#blocked()} means the
   *         lockout stands and the login must be denied
   * @since 00.84.00
   */
  default AttemptStatus completeSuccess(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    Objects.requireNonNull(now, "now must not be null");
    Objects.requireNonNull(limits, "limits must not be null");
    AttemptStatus status = legacyLockStatus(key, now, limits);
    if (status.blocked()) {
      return status;
    }
    reset(key);
    return AttemptStatus.open(0);
  }

  /**
   * Gives back an admitted attempt that ended without an outcome — the
   * credential check was shed or threw (JS-SEC-126, CWE-703). The
   * reservation is released; the counter is not touched. The default does
   * nothing because the default {@link #tryBeginAttempt} reserves nothing.
   *
   * @param key failure dimension; must not be {@code null}
   * @param now current instant; must not be {@code null}
   * @since 00.84.00
   */
  default void abandonAttempt(LoginAttemptKey key, Instant now) {
    Objects.requireNonNull(key, "key must not be null");
    Objects.requireNonNull(now, "now must not be null");
  }

  private AttemptStatus legacyLockStatus(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    int failures = failureCount(key);
    if (failures >= limits.failureThreshold()) {
      Optional<Instant> last = lastFailureAt(key);
      if (last.isPresent()) {
        Instant unlocksAt = last.get().plus(limits.lockout());
        if (now.isBefore(unlocksAt)) {
          return AttemptStatus.blocked(failures, unlocksAt);
        }
      }
    }
    return AttemptStatus.open(failures);
  }
}
