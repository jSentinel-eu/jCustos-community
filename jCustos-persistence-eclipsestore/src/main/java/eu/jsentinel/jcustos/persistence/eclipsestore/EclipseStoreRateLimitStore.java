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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.RateLimitBucket;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitStore;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link RateLimitStore}.
 *
 * <h2>Admission (JS-SEC-118, CWE-367, CWE-799)</h2>
 * <p>{@link #tryAdmit} counts, prunes and records under the storage's write
 * lock. Until 00.84.00 this adapter inherited the default — a count under
 * the read lock followed by a record under the write lock — so parallel
 * requests all read the counter before the first of them wrote, and all
 * passed. The events of a key were a {@code LinkedHashSet}: a second event
 * with the same instant was silently dropped, and with a clock that ticks
 * coarsely the limit was never reached. They are a list now, kept in
 * ascending order; equal instants count separately.</p>
 *
 * <h2>Bounds and expiry (JS-SEC-125, CWE-770)</h2>
 * <ul>
 *   <li>At most {@link EclipseStoreJCustosStorage#maxEntries()} keys. At the
 *       bound, buckets that can no longer influence an admission go first;
 *       then the key without a lasting block that was used least recently
 *       since the storage was opened is evicted. A key under attack is in use
 *       and is the last candidate; a key whose block lasts is no candidate
 *       while any other key is (see Blocks).</li>
 *   <li>At most {@link InMemoryRateLimitStore#DEFAULT_MAX_EVENTS_PER_KEY}
 *       events per key: {@link #recordEvent} drops the key's oldest event,
 *       {@link #tryAdmit} refuses.</li>
 *   <li>{@link #tryAdmit} drops the key's events that left the window and
 *       remembers, per key, the widest window a policy applied. A bucket
 *       whose newest event is older than that window is dead; dead buckets
 *       are removed in passing, at most once per {@link #SWEEP_INTERVAL} of
 *       the callers' time. Keys that only ever saw {@link #recordEvent} have
 *       no known window and stay until {@link #purgeOlderThan} or the bound
 *       removes them.</li>
 * </ul>
 *
 * <p>An admitted event writes the key's event list; a refused request writes
 * nothing unless it pruned.</p>
 *
 * <h2>Blocks (since 00.84.00)</h2>
 * <p>A key's block is a field of its bucket, so it is stored, evicted and reset
 * with the key's events. {@link #block} extends it under the write lock and
 * writes the bucket; {@link #blockedUntil} reads under the read lock and marks a
 * blocked key as used. A bucket is dead only once its block has ended as well, so
 * neither the sweep nor the bound's first pass drops a key whose block lasts.
 * {@link #purgeOlderThan} drops blocks that ended before the cutoff. A bucket
 * stored before blocks existed loads without one.</p>
 *
 * <p><strong>A lasting block survives the bound</strong> (since 00.84.00). At the
 * bound the store evicts the key used least recently among those whose block, if
 * any, has ended by the storage clock's instant; only when every key has a block
 * that still lasts, the key whose block ends first. Before 00.84.00 was released a
 * client that could mint keys stopped asking for its blocked key, created
 * {@code maxEntries} fresh ones and found the block gone. The bound stays hard.
 * Making room walks the order of use from the key used least recently and passes
 * over the keys with a lasting block, so it takes longer the more of them stand
 * before the first candidate; when only such keys are left, finding the block that
 * ends first reads every key.</p>
 */
final class EclipseStoreRateLimitStore implements RateLimitStore, HasLogger {

  /** How much of the callers' time passes at least between two sweeps for dead buckets. */
  static final Duration SWEEP_INTERVAL = Duration.ofMinutes(1);

  private final EclipseStoreJCustosStorage storage;
  private final int maxEventsPerKey;

  EclipseStoreRateLimitStore(EclipseStoreJCustosStorage storage) {
    this(storage, InMemoryRateLimitStore.DEFAULT_MAX_EVENTS_PER_KEY);
  }

  /** Test seam for the bound per key. */
  EclipseStoreRateLimitStore(EclipseStoreJCustosStorage storage, int maxEventsPerKey) {
    this.storage = storage;
    this.maxEventsPerKey = maxEventsPerKey;
  }

  /**
   * @return the most events kept under one key; {@code InMemoryRateLimitPolicy} refuses a
   *         larger limit at construction (XR08, 00.84.00)
   */
  @Override
  public int maxEventsPerKey() {
    return maxEventsPerKey;
  }

  @Override
  public void recordEvent(RateLimitKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    storage.update(() -> {
      RateLimitBucket bucket = bucket(key);
      if (bucket == null) {
        addBucket(key, at, withEvent(at, 0L));
        return;
      }
      insertInOrder(bucket.events, at);
      if (bucket.events.size() > maxEventsPerKey) {
        bucket.events.remove(0); // the oldest event of the key makes room
      }
      storage.markChanged(bucket.events); // changed in place (R002)
    });
  }

  @Override
  public Admission tryAdmit(RateLimitKey key, Instant at, Instant since, int limit) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    requireNonNull(since, "since must not be null");
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be strictly positive");
    }
    // JS-SEC-118 (CWE-367): one critical section for count, prune and record.
    return storage.write(() -> {
      sweepDeadBuckets(at);
      RateLimitBucket bucket = bucket(key);
      int current = 0;
      if (bucket != null) {
        int stale = firstAtOrAfter(bucket.events, since);
        if (stale > 0) {
          bucket.events.subList(0, stale).clear(); // outside the window
          storage.markChanged(bucket.events);
        }
        current = bucket.events.size();
      }
      if (current >= limit || current >= maxEventsPerKey) {
        if (bucket == null) {
          return new Admission(false, current);
        }
        rememberWindow(bucket, windowMillis(at, since));
        // the oldest event left in the window is the one whose departure frees a slot
        return new Admission(false, current, oldestEvent(bucket));
      }
      if (bucket == null) {
        addBucket(key, at, withEvent(at, windowMillis(at, since)));
        return new Admission(true, 1, Optional.of(at));
      }
      insertInOrder(bucket.events, at);
      storage.markChanged(bucket.events);
      rememberWindow(bucket, windowMillis(at, since));
      return new Admission(true, current + 1, oldestEvent(bucket));
    });
  }

  @Override
  public int countSince(RateLimitKey key, Instant since) {
    requireNonNull(key, "key must not be null");
    requireNonNull(since, "since must not be null");
    return storage.read(() -> {
      RateLimitBucket bucket = storage.tables().rateLimitBuckets.get(key);
      return bucket == null ? 0 : bucket.events.size() - firstAtOrAfter(bucket.events, since);
    });
  }

  @Override
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    storage.update(() -> storage.tables().rateLimitBuckets.remove(key));
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    return storage.write(() -> {
      int[] purged = {0};
      StoredTable<RateLimitKey, RateLimitBucket> buckets = storage.tables().rateLimitBuckets;
      buckets.removeIf((key, bucket) -> {
        int stale = firstAtOrAfter(bucket.events, cutoff);
        if (stale > 0) {
          bucket.events.subList(0, stale).clear();
          purged[0] += stale;
        }
        boolean blockEnded = bucket.blockedUntil != null && bucket.blockedUntil.isBefore(cutoff);
        if (blockEnded) {
          bucket.blockedUntil = null;
        }
        if (bucket.events.isEmpty() && bucket.blockedUntil == null) {
          return true;
        }
        if (stale > 0) {
          storage.markChanged(bucket.events);
        }
        if (blockEnded) {
          storage.markChanged(bucket);
          buckets.noteDeadline(bucket.deadAt()); // without its block the bucket dies sooner
        }
        return false;
      });
      return purged[0];
    });
  }

  /**
   * Reads under the read lock. A key that has a block is then marked as used under the write
   * lock - nothing is written - because a blocked client's requests reach the store only
   * here: otherwise the key it keeps hammering would be the first candidate for eviction.
   *
   * @return the end of the key's block; empty when none is recorded
   * @since 00.84.00
   */
  @Override
  public Optional<Instant> blockedUntil(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    Optional<Instant> until = storage.read(() -> {
      RateLimitBucket bucket = storage.tables().rateLimitBuckets.get(key);
      return bucket == null ? Optional.empty() : Optional.ofNullable(bucket.blockedUntil);
    });
    if (until.isPresent()) {
      storage.update(() -> storage.tables().rateLimitBuckets.touch(key));
    }
    return until;
  }

  /**
   * Extends the key's block to {@code until} under the write lock and stores it; a key the
   * store does not know yet gets a bucket inside the bound.
   *
   * @return the end of the key's block after the call
   * @since 00.84.00
   */
  @Override
  public Instant block(RateLimitKey key, Instant until) {
    requireNonNull(key, "key must not be null");
    requireNonNull(until, "until must not be null");
    return storage.write(() -> {
      RateLimitBucket bucket = bucket(key);
      if (bucket == null) {
        RateLimitBucket blocked = new RateLimitBucket();
        blocked.blockedUntil = until;
        addBucket(key, storage.now(), blocked);
        return until;
      }
      if (bucket.blockedUntil == null || until.isAfter(bucket.blockedUntil)) {
        bucket.blockedUntil = until; // a block only ever grows, and so does the deadline
        storage.markChanged(bucket);
      }
      return bucket.blockedUntil;
    });
  }

  // ── buckets; the caller holds the write lock ───────────────────────

  /** @return the key's bucket, marked as used just now; {@code null} when the key is unknown */
  private RateLimitBucket bucket(RateLimitKey key) {
    RateLimitBucket bucket = storage.tables().rateLimitBuckets.get(key);
    if (bucket != null) {
      storage.tables().rateLimitBuckets.touch(key);
    }
    return bucket;
  }

  /**
   * Stores a bucket for a key that had none. The bucket is complete before it enters the table:
   * the table notes the deadline of what it is handed, and an empty bucket would look dead.
   *
   * @param now the instant entries that are dead by then may be dropped to make room
   */
  private void addBucket(RateLimitKey key, Instant now, RateLimitBucket bucket) {
    StoredTable<RateLimitKey, RateLimitBucket> buckets = storage.tables().rateLimitBuckets;
    int maxEntries = storage.maxEntries();
    if (!buckets.hasRoomFor(key, maxEntries)) {
      buckets.dropDead(now);
      // a lasting block goes last: the client it refuses must not lift it with fresh keys
      int evicted = buckets.evictEldest(key, maxEntries, candidate -> !blocksAt(candidate, now));
      while (!buckets.hasRoomFor(key, maxEntries) && evictBlockEndingFirst(buckets)) {
        evicted++;
      }
      buckets.recordEvictions(evicted);
      if (evicted > 0 && buckets.evictionLogDue()) {
        logger().warn("persistence/rate-limit-store-capacity: the rate-limit store is at its"
            + " bound of {} keys; for every new key the key used least recently is dropped -"
            + " a key with a lasting block only when no other is left - and its events no longer"
            + " count", maxEntries);
      }
    }
    buckets.put(key, bucket);
  }

  /** @return {@code true} when {@code bucket} has a block that lasts beyond {@code now} */
  private static boolean blocksAt(RateLimitBucket bucket, Instant now) {
    return bucket.blockedUntil != null && bucket.blockedUntil.isAfter(now);
  }

  /**
   * Evicts the key whose block ends first - the last resort when every key has a lasting block.
   *
   * @return {@code false} when the table is empty
   */
  private static boolean evictBlockEndingFirst(StoredTable<RateLimitKey, RateLimitBucket> buckets) {
    RateLimitKey first = null;
    Instant firstEnd = null;
    for (RateLimitKey candidate : buckets.keys()) {
      Instant end = buckets.get(candidate).blockedUntil;
      Instant effectiveEnd = end == null ? Instant.MIN : end;
      if (firstEnd == null || effectiveEnd.isBefore(firstEnd)) {
        first = candidate;
        firstEnd = effectiveEnd;
      }
    }
    if (first == null) {
      return false;
    }
    buckets.remove(first);
    return true;
  }

  /** @return a new bucket holding {@code firstEvent} */
  private static RateLimitBucket withEvent(Instant firstEvent, long windowMillis) {
    RateLimitBucket bucket = new RateLimitBucket();
    bucket.events.add(firstEvent);
    bucket.retentionMillis = windowMillis;
    return bucket;
  }

  private static Optional<Instant> oldestEvent(RateLimitBucket bucket) {
    return bucket.events.isEmpty() ? Optional.empty() : Optional.of(bucket.events.get(0));
  }

  /** @return the window {@code [since, at]} in milliseconds, rounded up; 0 when there is none */
  private static long windowMillis(Instant at, Instant since) {
    if (!since.isBefore(at)) {
      return 0L;
    }
    try {
      return Math.addExact(Duration.between(since, at).toMillis(), 1);
    } catch (ArithmeticException unbounded) {
      return Long.MAX_VALUE;
    }
  }

  /** Keeps the widest window applied to the bucket, so that the store knows when it is dead. */
  private void rememberWindow(RateLimitBucket bucket, long windowMillis) {
    if (windowMillis > bucket.retentionMillis) {
      bucket.retentionMillis = windowMillis;
      storage.markChanged(bucket);
      storage.tables().rateLimitBuckets.noteDeadline(bucket.deadAt());
    }
  }

  /**
   * Removes the buckets no admission can count any more. The table skips the scan while the
   * earliest deadline it knows lies ahead; this method keeps even that check to once per
   * {@link #SWEEP_INTERVAL}.
   */
  private void sweepDeadBuckets(Instant now) {
    EclipseStoreJCustosRoot root = storage.root();
    if (root.rateLimitNextSweep != null && now.isBefore(root.rateLimitNextSweep)) {
      return;
    }
    root.rateLimitNextSweep = now.isBefore(Instant.MAX.minus(SWEEP_INTERVAL))
        ? now.plus(SWEEP_INTERVAL)
        : Instant.MAX;
    storage.tables().rateLimitBuckets.dropDead(now);
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
