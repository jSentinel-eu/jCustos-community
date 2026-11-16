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
 *       then the key that was used least recently since the storage was
 *       opened is evicted. A key under attack is in use and is the last
 *       candidate.</li>
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

  @Override
  public void recordEvent(RateLimitKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    storage.update(() -> {
      RateLimitBucket bucket = bucket(key);
      if (bucket == null) {
        addBucket(key, at, 0L);
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
        if (bucket != null) {
          rememberWindow(bucket, windowMillis(at, since));
        }
        return new Admission(false, current);
      }
      if (bucket == null) {
        addBucket(key, at, windowMillis(at, since));
      } else {
        insertInOrder(bucket.events, at);
        storage.markChanged(bucket.events);
        rememberWindow(bucket, windowMillis(at, since));
      }
      return new Admission(true, current + 1);
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
      storage.tables().rateLimitBuckets.removeIf((key, bucket) -> {
        int stale = firstAtOrAfter(bucket.events, cutoff);
        if (stale > 0) {
          bucket.events.subList(0, stale).clear();
          purged[0] += stale;
          if (!bucket.events.isEmpty()) {
            storage.markChanged(bucket.events);
          }
        }
        return bucket.events.isEmpty();
      });
      return purged[0];
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
   */
  private void addBucket(RateLimitKey key, Instant firstEvent, long windowMillis) {
    StoredTable<RateLimitKey, RateLimitBucket> buckets = storage.tables().rateLimitBuckets;
    int evicted = buckets.makeRoomFor(key, storage.maxEntries(), firstEvent);
    if (evicted > 0 && buckets.evictionLogDue()) {
      logger().warn("persistence/rate-limit-store-capacity: the rate-limit store is at its bound"
          + " of {} keys; the key used least recently is dropped for every new key - its events"
          + " no longer count", storage.maxEntries());
    }
    RateLimitBucket bucket = new RateLimitBucket();
    bucket.events.add(firstEvent);
    bucket.retentionMillis = windowMillis;
    buckets.put(key, bucket);
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
