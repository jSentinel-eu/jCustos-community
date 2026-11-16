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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RateLimitStore}: one list of event instants per key, kept
 * in ascending order, in a single map that also carries the order of use.
 *
 * <p>JS-SEC-118 (CWE-367, CWE-770, CWE-401): every operation runs under one
 * lock, so the key set, the order of use and the buckets are one structure
 * and cannot drift apart. Until 00.84.00 the store combined a concurrent map
 * with a separate queue of keys in first-seen order; {@link #reset} and
 * {@link #purgeOlderThan} removed a bucket but left its queue entry behind,
 * so the queue grew with every key that was purged and seen again, and a
 * stale queue entry could evict the bucket a key had just been given anew.
 * The capacity check and the insert were two steps as well, which let
 * parallel callers push the map past its bound.</p>
 *
 * <ul>
 *   <li><strong>Admission</strong> ({@link #tryAdmit}) counts, prunes and
 *       records in one step; of N parallel callers exactly {@code limit} are
 *       admitted.</li>
 *   <li><strong>Events</strong> are a multiset: two events with the same
 *       instant are two events.</li>
 *   <li><strong>Bound on keys</strong>: at most {@code maxEntries}. At the
 *       bound the key that was used least recently is evicted - a key that
 *       is being throttled right now is in use and therefore the last
 *       candidate, not the first.</li>
 *   <li><strong>Bound per key</strong>: at most {@code maxEventsPerKey}
 *       events. {@link #recordEvent} then drops the oldest event of the key;
 *       {@link #tryAdmit} refuses, so a limit above this bound would never be
 *       reached - {@link InMemoryRateLimitPolicy} therefore refuses such a
 *       limit at construction ({@link #maxEventsPerKey()}).</li>
 * </ul>
 *
 * <p>Events that left the window are dropped per key on {@link #tryAdmit};
 * keys that are no longer used stay until {@link #purgeOlderThan(Instant)}
 * or the bound removes them.</p>
 */
@ExperimentalJCustosApi
public final class InMemoryRateLimitStore implements RateLimitStore {

  /**
   * Default upper bound on the events kept under one key (JS-SEC-118, CWE-770).
   * A sliding-window policy keeps at most {@code limit} events per key, so the
   * bound only matters for callers of {@link #recordEvent} that never prune.
   *
   * @since 00.84.00
   */
  public static final int DEFAULT_MAX_EVENTS_PER_KEY = 10_000;

  private final ReentrantLock lock = new ReentrantLock();
  /** Access order: iteration starts at the key that was used least recently. */
  private final LinkedHashMap<RateLimitKey, ArrayList<Instant>> buckets =
      new LinkedHashMap<>(16, 0.75f, true);
  private final int maxEntries;
  private final int maxEventsPerKey;

  /**
   * Bounded to {@link CapacityBound#DEFAULT_MAX_ENTRIES} keys and
   * {@link #DEFAULT_MAX_EVENTS_PER_KEY} events per key.
   */
  public InMemoryRateLimitStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * @param maxEntries upper bound on tracked keys; at the bound the key used
   *                   least recently is evicted (JS-SEC-078, CWE-770: keys are
   *                   client addresses and usernames an attacker chooses freely)
   * @since 00.84.00
   */
  public InMemoryRateLimitStore(int maxEntries) {
    this(maxEntries, DEFAULT_MAX_EVENTS_PER_KEY);
  }

  /**
   * @param maxEntries      upper bound on tracked keys
   * @param maxEventsPerKey upper bound on the events kept under one key
   * @since 00.84.00
   */
  public InMemoryRateLimitStore(int maxEntries, int maxEventsPerKey) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.maxEventsPerKey = CapacityBound.requirePositiveCapacity(maxEventsPerKey);
  }

  /**
   * @return the most events kept under one key
   * @since 00.84.00
   */
  @Override
  public int maxEventsPerKey() {
    return maxEventsPerKey;
  }

  int trackedKeyCount() {
    lock.lock();
    try {
      return buckets.size();
    } finally {
      lock.unlock();
    }
  }

  @Override
  public void recordEvent(RateLimitKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    lock.lock();
    try {
      ArrayList<Instant> events = buckets.get(key);
      if (events == null) {
        events = newBucket(key);
      }
      insertInOrder(events, at);
      if (events.size() > maxEventsPerKey) {
        events.remove(0); // the oldest event of the key makes room
      }
    } finally {
      lock.unlock();
    }
  }

  @Override
  public Admission tryAdmit(RateLimitKey key, Instant at, Instant since, int limit) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    requireNonNull(since, "since must not be null");
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be strictly positive");
    }
    // One critical section for count, prune and record: N concurrent callers at
    // limit-1 see each other's events instead of all passing (JS-SEC-078, CWE-367).
    lock.lock();
    try {
      ArrayList<Instant> events = buckets.get(key);
      int current = 0;
      if (events != null) {
        events.subList(0, firstAtOrAfter(events, since)).clear(); // outside the window
        current = events.size();
      }
      if (current >= limit || current >= maxEventsPerKey) {
        return new Admission(false, current);
      }
      if (events == null) {
        events = newBucket(key);
      }
      insertInOrder(events, at);
      return new Admission(true, current + 1);
    } finally {
      lock.unlock();
    }
  }

  /** Caller holds the lock. Evicts the keys used least recently until the new key fits. */
  private ArrayList<Instant> newBucket(RateLimitKey key) {
    Iterator<Map.Entry<RateLimitKey, ArrayList<Instant>>> leastRecentlyUsed =
        buckets.entrySet().iterator();
    while (buckets.size() >= maxEntries && leastRecentlyUsed.hasNext()) {
      leastRecentlyUsed.next();
      leastRecentlyUsed.remove();
    }
    ArrayList<Instant> events = new ArrayList<>(4);
    buckets.put(key, events);
    return events;
  }

  @Override
  public int countSince(RateLimitKey key, Instant since) {
    requireNonNull(key, "key must not be null");
    requireNonNull(since, "since must not be null");
    lock.lock();
    try {
      ArrayList<Instant> events = buckets.get(key);
      return events == null ? 0 : events.size() - firstAtOrAfter(events, since);
    } finally {
      lock.unlock();
    }
  }

  @Override
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    lock.lock();
    try {
      buckets.remove(key);
    } finally {
      lock.unlock();
    }
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    lock.lock();
    try {
      int purged = 0;
      Iterator<ArrayList<Instant>> all = buckets.values().iterator();
      while (all.hasNext()) {
        ArrayList<Instant> events = all.next();
        int stale = firstAtOrAfter(events, cutoff);
        events.subList(0, stale).clear();
        purged += stale;
        if (events.isEmpty()) {
          all.remove();
        }
      }
      return purged;
    } finally {
      lock.unlock();
    }
  }

  /** Inserts {@code at} behind every event that is not later, keeping the list ascending. */
  private static void insertInOrder(List<Instant> events, Instant at) {
    int size = events.size();
    if (size == 0 || !events.get(size - 1).isAfter(at)) {
      events.add(at); // the usual case: time moves forward
      return;
    }
    int low = 0;
    int high = size;
    while (low < high) {
      int mid = (low + high) >>> 1;
      if (events.get(mid).isAfter(at)) {
        high = mid;
      } else {
        low = mid + 1;
      }
    }
    events.add(low, at);
  }

  /** @return index of the first event at or after {@code bound}; the list size when there is none */
  private static int firstAtOrAfter(List<Instant> events, Instant bound) {
    int low = 0;
    int high = events.size();
    while (low < high) {
      int mid = (low + high) >>> 1;
      if (events.get(mid).isBefore(bound)) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    return low;
  }
}
