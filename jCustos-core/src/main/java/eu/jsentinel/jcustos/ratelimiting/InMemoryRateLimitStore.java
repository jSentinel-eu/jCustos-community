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
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RateLimitStore}: one list of event instants per key, kept
 * in ascending order, in a single map, and the order of use of the keys whose
 * bucket may be evicted.
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
 *       candidate, not the first. A key whose block still lasts is not a
 *       candidate at all while any other key is (see below).</li>
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
 *
 * <p><strong>Blocks</strong> (since 00.84.00): a key's block lives next to its
 * events, under the same lock - {@link #block} extends it atomically,
 * {@link #reset} lifts it with the events, {@link #purgeOlderThan} keeps a key
 * whose block lasts beyond the cutoff although it holds no events.</p>
 *
 * <p><strong>A lasting block survives the bound</strong> (since 00.84.00). A key
 * with a block leaves the order of use and is kept apart, ordered by the end of
 * its block. At the bound the store evicts the key used least recently among those
 * without a lasting block - a key whose block has ended by the instant of the call
 * rejoins the order of use as if it had just been used - and only when every
 * tracked key has a block that still lasts, the key whose block ends first. Before
 * 00.84.00 was released a client that could mint keys - user names of a per-user
 * scope, the addresses of an IPv6 prefix - stopped asking for its blocked key,
 * created {@code maxEntries} fresh ones and found the block gone. The bound stays
 * hard. {@link #block} has no instant of its own, so a key it adds at the bound
 * treats every block as lasting. Making room costs {@code O(log n)} at most per key.</p>
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

  /** The events of one key, ascending, and the end of its block; guarded by the lock. */
  private static final class Bucket {
    final RateLimitKey key;
    /** Breaks the tie between two blocks that end at the same instant. */
    final long sequence;
    final ArrayList<Instant> events = new ArrayList<>(4);
    /** End of the key's block, exclusive; {@code null} while the key has none. */
    Instant blockedUntil;
    /** {@code true} while the bucket is kept in {@code shielded}, not in {@code evictable}. */
    boolean shielded;

    Bucket(RateLimitKey key, long sequence) {
      this.key = key;
      this.sequence = sequence;
    }

    boolean isEmpty() {
      return events.isEmpty() && blockedUntil == null;
    }

    Optional<Instant> oldestEvent() {
      return events.isEmpty() ? Optional.empty() : Optional.of(events.get(0));
    }
  }

  private final ReentrantLock lock = new ReentrantLock();
  /** Every tracked key. */
  private final HashMap<RateLimitKey, Bucket> buckets = new HashMap<>();
  /** The buckets the bound may evict, the one used least recently first. */
  private final LinkedHashSet<Bucket> evictable = new LinkedHashSet<>();
  /** The buckets with a block that may still last, the block that ends first first. */
  private final TreeSet<Bucket> shielded = new TreeSet<>(
      Comparator.comparing((Bucket bucket) -> bucket.blockedUntil)
          .thenComparingLong(bucket -> bucket.sequence));
  private long nextSequence;
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

  /** Package-visible for tests: keys kept apart because their block may still last. */
  int shieldedKeyCount() {
    lock.lock();
    try {
      return shielded.size();
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
      Bucket bucket = use(key);
      if (bucket == null) {
        bucket = newBucket(key, at);
      }
      insertInOrder(bucket.events, at);
      if (bucket.events.size() > maxEventsPerKey) {
        bucket.events.remove(0); // the oldest event of the key makes room
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
      Bucket bucket = use(key);
      int current = 0;
      if (bucket != null) {
        // outside the window
        bucket.events.subList(0, firstAtOrAfter(bucket.events, since)).clear();
        current = bucket.events.size();
      }
      if (current >= limit || current >= maxEventsPerKey) {
        // the oldest event left in the window is the one whose departure frees a slot
        return new Admission(false, current,
            bucket == null ? Optional.empty() : bucket.oldestEvent());
      }
      if (bucket == null) {
        bucket = newBucket(key, at);
      }
      insertInOrder(bucket.events, at);
      return new Admission(true, current + 1, bucket.oldestEvent());
    } finally {
      lock.unlock();
    }
  }

  /**
   * Caller holds the lock. Marks the key's bucket as used just now.
   *
   * @return the bucket; {@code null} for a key the store does not track
   */
  private Bucket use(RateLimitKey key) {
    Bucket bucket = buckets.get(key);
    if (bucket != null && !bucket.shielded) {
      evictable.remove(bucket);
      evictable.add(bucket);
    }
    return bucket;
  }

  /**
   * Caller holds the lock. Makes room for {@code key} at the bound and tracks it.
   *
   * @param now the instant at which a block that has ended no longer protects its key;
   *            {@code null} when the caller has none - every recorded block then protects
   */
  private Bucket newBucket(RateLimitKey key, Instant now) {
    while (buckets.size() >= maxEntries) {
      evictOne(now);
    }
    Bucket bucket = new Bucket(key, nextSequence++);
    buckets.put(key, bucket);
    evictable.add(bucket);
    return bucket;
  }

  /**
   * Caller holds the lock and the store is not empty. Evicts the bucket used least recently
   * among those without a lasting block; when every bucket has one, the block that ends first.
   */
  private void evictOne(Instant now) {
    if (now != null) {
      // a block that has ended by now protects its key no longer
      while (!shielded.isEmpty() && !shielded.first().blockedUntil.isAfter(now)) {
        Bucket ended = shielded.pollFirst();
        ended.shielded = false;
        evictable.add(ended);
      }
    }
    Bucket victim;
    Iterator<Bucket> leastRecentlyUsed = evictable.iterator();
    if (leastRecentlyUsed.hasNext()) {
      victim = leastRecentlyUsed.next();
      leastRecentlyUsed.remove();
    } else {
      victim = shielded.pollFirst();
    }
    buckets.remove(victim.key);
  }

  /** Caller holds the lock. Takes {@code bucket} out of the eviction order or the shield. */
  private void detach(Bucket bucket) {
    if (bucket.shielded) {
      shielded.remove(bucket); // before its block changes: the block is the sort key
      bucket.shielded = false;
    } else {
      evictable.remove(bucket);
    }
  }

  @Override
  public int countSince(RateLimitKey key, Instant since) {
    requireNonNull(key, "key must not be null");
    requireNonNull(since, "since must not be null");
    lock.lock();
    try {
      Bucket bucket = use(key);
      return bucket == null ? 0 : bucket.events.size() - firstAtOrAfter(bucket.events, since);
    } finally {
      lock.unlock();
    }
  }

  @Override
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    lock.lock();
    try {
      Bucket bucket = buckets.remove(key);
      if (bucket != null) {
        detach(bucket);
      }
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
      Iterator<Bucket> all = buckets.values().iterator();
      while (all.hasNext()) {
        Bucket bucket = all.next();
        int stale = firstAtOrAfter(bucket.events, cutoff);
        bucket.events.subList(0, stale).clear();
        purged += stale;
        if (bucket.blockedUntil != null && bucket.blockedUntil.isBefore(cutoff)) {
          if (bucket.shielded) {
            detach(bucket);
            evictable.add(bucket);
          }
          bucket.blockedUntil = null; // the block has ended
        }
        if (bucket.isEmpty()) {
          all.remove();
          detach(bucket);
        }
      }
      return purged;
    } finally {
      lock.unlock();
    }
  }

  /**
   * @return the end of the key's block; empty when none is recorded
   * @since 00.84.00
   */
  @Override
  public Optional<Instant> blockedUntil(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    lock.lock();
    try {
      Bucket bucket = use(key);
      return bucket == null ? Optional.empty() : Optional.ofNullable(bucket.blockedUntil);
    } finally {
      lock.unlock();
    }
  }

  /**
   * Extends the key's block to {@code until} under the store's lock; a key the store does
   * not know yet is added inside the bound. While the block lasts, the key is evicted only when
   * every tracked key has a lasting block (see the type description).
   *
   * @return the end of the key's block after the call
   * @since 00.84.00
   */
  @Override
  public Instant block(RateLimitKey key, Instant until) {
    requireNonNull(key, "key must not be null");
    requireNonNull(until, "until must not be null");
    lock.lock();
    try {
      Bucket bucket = use(key);
      if (bucket == null) {
        bucket = newBucket(key, null);
      }
      if (bucket.blockedUntil == null || until.isAfter(bucket.blockedUntil)) {
        detach(bucket);
        bucket.blockedUntil = until; // a block only ever grows
        bucket.shielded = true;
        shielded.add(bucket);
      }
      return bucket.blockedUntil;
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
