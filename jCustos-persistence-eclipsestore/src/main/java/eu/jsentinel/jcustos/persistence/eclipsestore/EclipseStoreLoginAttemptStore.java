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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.LoginAttemptLedger;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link LoginAttemptStore}.
 *
 * <p>JS-SEC-122 (CWE-307, CWE-770) and JS-SEC-123 (CWE-367): the adapter
 * implements the atomic attempt operations. The decisions are taken by an
 * {@link InMemoryLoginAttemptStore} that the storage root holds as its
 * working state ({@link WorkingState}); what Eclipse Store persists is, as
 * before, counter and last-failure instant per key. Every operation runs
 * under the storage's write lock, asks the working state, and then copies
 * the outcome for the key — and every key the working state dropped on the
 * way — into the persistent table, which writes those entries and nothing
 * else (JS-SEC-125).</p>
 *
 * <ul>
 *   <li><strong>Lockouts</strong> follow from counter, last failure and the
 *       limits of the calling policy, so they survive a restart without a
 *       field of their own — the persisted record is unchanged.</li>
 *   <li><strong>Attempts in flight</strong> are working state only; a
 *       restart forgets them, which is correct, as no request survives it
 *       either.</li>
 *   <li><strong>Bound</strong>: at most
 *       {@link CapacityBound#DEFAULT_MAX_ENTRIES} keys. Expired counters are
 *       removed from the persistent table as well; a live lockout is never
 *       evicted; a store full of live lockouts refuses new keys.</li>
 *   <li><strong>Address keys</strong> (JS-SEC-062): the counter of a client
 *       address is persisted under {@link LoginAttemptKey#forAddress}, a key
 *       of the existing shape, so the format is unchanged. After a restart the
 *       working state derives an address lockout from the limits of the first
 *       address operation, not from the shorter limits of the accounts.</li>
 * </ul>
 */
final class EclipseStoreLoginAttemptStore implements LoginAttemptStore {

  private final EclipseStoreJCustosStorage storage;
  private final int maxEntries;

  EclipseStoreLoginAttemptStore(EclipseStoreJCustosStorage storage) {
    this(storage, CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * Test seam for the bound. The working state is shared by every adapter instance of one
   * storage, so the bound that counts is the one of the instance that touches the storage first.
   */
  EclipseStoreLoginAttemptStore(EclipseStoreJCustosStorage storage, int maxEntries) {
    this.storage = storage;
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  /**
   * The working state of the login-attempt store: the deciding in-memory store and the keys it
   * has dropped since the adapter last looked. Not persisted - the root keeps it in a
   * {@code transient} field and it is rebuilt from the persistent table after a restart.
   */
  static final class WorkingState {
    private final Set<LoginAttemptKey> dropped = new LinkedHashSet<>();
    private final InMemoryLoginAttemptStore live;

    WorkingState(int maxEntries) {
      this.live = new InMemoryLoginAttemptStore(maxEntries, dropped::add);
    }
  }

  // ── atomic attempt operations (JS-SEC-122, JS-SEC-123) ─────────────

  @Override
  public AttemptStatus tryBeginAttempt(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    requireNonNull(limits, "limits must not be null");
    return mutate(key, live -> live.tryBeginAttempt(key, now, limits));
  }

  @Override
  public AttemptStatus completeFailure(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    requireNonNull(limits, "limits must not be null");
    return mutate(key, live -> live.completeFailure(key, now, limits));
  }

  @Override
  public AttemptStatus completeSuccess(LoginAttemptKey key, Instant now, AttemptLimits limits) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    requireNonNull(limits, "limits must not be null");
    return mutate(key, live -> live.completeSuccess(key, now, limits));
  }

  @Override
  public void abandonAttempt(LoginAttemptKey key, Instant now) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    mutate(key, live -> {
      live.abandonAttempt(key, now);
      return null;
    });
  }

  // ── counter primitives ─────────────────────────────────────────────

  @Override
  public void recordFailure(LoginAttemptKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    mutate(key, live -> {
      live.recordFailure(key, at);
      return null;
    });
  }

  @Override
  public int failureCount(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    return storage.read(() -> {
      LoginAttemptLedger ledger = storage.tables().loginAttempts.get(key);
      return ledger == null ? 0 : ledger.count();
    });
  }

  @Override
  public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    return storage.read(() -> {
      LoginAttemptLedger ledger = storage.tables().loginAttempts.get(key);
      return ledger == null ? Optional.<Instant>empty() : Optional.of(ledger.lastFailureAt());
    });
  }

  @Override
  public void reset(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    mutate(key, live -> {
      live.reset(key);
      return null;
    });
  }

  // ── working state and its persistent copy ──────────────────────────

  /**
   * Runs one operation on the working state under the write lock and brings the persistent
   * table up to date: the key the operation was about, and every key the working state dropped
   * because it expired or had to make room. Only those entries are written (JS-SEC-125) - until
   * 00.84.00 every failed login rewrote the map of all tracked keys.
   */
  private <R> R mutate(LoginAttemptKey key, Function<InMemoryLoginAttemptStore, R> operation) {
    return storage.write(() -> {
      WorkingState runtime = runtime();
      R result = operation.apply(runtime.live);
      StoredTable<LoginAttemptKey, LoginAttemptLedger> persistent = storage.tables().loginAttempts;
      removeDropped(runtime, persistent);

      int failures = runtime.live.failureCount(key);
      Optional<Instant> lastFailureAt = runtime.live.lastFailureAt(key);
      if (failures > 0 && lastFailureAt.isPresent()) {
        LoginAttemptLedger current = new LoginAttemptLedger(failures, lastFailureAt.get());
        if (!current.equals(persistent.get(key))) {
          persistent.put(key, current);
        }
      } else {
        // a key that only has an attempt in flight holds nothing worth persisting
        persistent.remove(key);
      }
      return result;
    });
  }

  /** Returns the working state, building it from the persistent table on first use. */
  private WorkingState runtime() {
    EclipseStoreJCustosRoot root = storage.root();
    WorkingState runtime = root.loginAttemptRuntime;
    if (runtime == null) {
      runtime = new WorkingState(maxEntries);
      StoredTable<LoginAttemptKey, LoginAttemptLedger> persistent = storage.tables().loginAttempts;
      for (LoginAttemptKey key : persistent.keys()) {
        LoginAttemptLedger ledger = persistent.get(key);
        runtime.live.restore(key, ledger.count(), ledger.lastFailureAt());
      }
      // a storage written before the bound existed can hold more keys than the bound allows
      removeDropped(runtime, persistent);
      root.loginAttemptRuntime = runtime;
    }
    return runtime;
  }

  private static void removeDropped(WorkingState runtime,
                                    StoredTable<LoginAttemptKey, LoginAttemptLedger> persistent) {
    for (LoginAttemptKey dropped : runtime.dropped) {
      persistent.remove(dropped);
    }
    runtime.dropped.clear();
  }
}
