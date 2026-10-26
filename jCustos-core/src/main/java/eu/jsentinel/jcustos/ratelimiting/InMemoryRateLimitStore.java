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
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentLinkedQueue;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RateLimitStore} backed by a per-key
 * {@link ConcurrentLinkedDeque} of timestamps.
 * <p>
 * {@link #recordEvent(RateLimitKey, Instant)} appends to the tail in
 * amortised O(1). {@link #countSince(RateLimitKey, Instant)} walks the
 * deque tail-to-head and stops once an entry before the cutoff is
 * found — assumes timestamps are recorded in approximately
 * monotonically-increasing order, which is the standard case for
 * sliding-window throttling.
 *
 * <p>Retention is the application's responsibility via
 * {@link #purgeOlderThan(Instant)}; without periodic purges the
 * deques would grow unboundedly under sustained traffic.
 */
@ExperimentalJCustosApi
public final class InMemoryRateLimitStore implements RateLimitStore {

  private final Map<RateLimitKey, ConcurrentLinkedDeque<Instant>> buckets =
      new ConcurrentHashMap<>();
  /** Keys in first-seen order; the eviction candidate is the head that still has a bucket. */
  private final ConcurrentLinkedQueue<RateLimitKey> arrival = new ConcurrentLinkedQueue<>();
  private final int maxEntries;

  /** Bounded to {@link CapacityBound#DEFAULT_MAX_ENTRIES} keys. */
  public InMemoryRateLimitStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * @param maxEntries upper bound on tracked keys; at the bound the key seen
   *                   first is evicted (JS-SEC-078, CWE-770: keys are client
   *                   addresses and usernames an attacker chooses freely)
   * @since 00.84.00
   */
  public InMemoryRateLimitStore(int maxEntries) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  int trackedKeyCount() {
    return buckets.size();
  }

  @Override
  public void recordEvent(RateLimitKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    bucketFor(key).add(at);
  }

  @Override
  public Admission tryAdmit(RateLimitKey key, Instant at, Instant since, int limit) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    requireNonNull(since, "since must not be null");
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be strictly positive");
    }
    enforceBound(key);
    boolean[] admitted = {false};
    int[] inWindow = {0};
    // compute() runs the function atomically for the key: N concurrent callers at
    // limit-1 see each other's events instead of all passing (JS-SEC-078, CWE-367).
    buckets.compute(key, (k, deque) -> {
      ConcurrentLinkedDeque<Instant> events;
      if (deque == null) {
        events = new ConcurrentLinkedDeque<>();
        arrival.add(k);
      } else {
        events = deque;
      }
      while (!events.isEmpty() && events.peekFirst().isBefore(since)) {
        events.pollFirst(); // outside the window — nothing ever counts it again
      }
      int current = events.size();
      if (current < limit) {
        events.add(at);
        admitted[0] = true;
        inWindow[0] = current + 1;
      } else {
        inWindow[0] = current;
      }
      return events;
    });
    return new Admission(admitted[0], inWindow[0]);
  }

  private ConcurrentLinkedDeque<Instant> bucketFor(RateLimitKey key) {
    enforceBound(key);
    return buckets.computeIfAbsent(key, k -> {
      arrival.add(k);
      return new ConcurrentLinkedDeque<>();
    });
  }

  /** At capacity, evicts the key seen first that still has a bucket; O(1) amortised. */
  private void enforceBound(RateLimitKey incoming) {
    if (buckets.size() < maxEntries || buckets.containsKey(incoming)) {
      return;
    }
    RateLimitKey oldest;
    while ((oldest = arrival.poll()) != null) {
      if (buckets.remove(oldest) != null) {
        return;
      }
    }
  }

  @Override
  public int countSince(RateLimitKey key, Instant since) {
    requireNonNull(key, "key must not be null");
    requireNonNull(since, "since must not be null");
    ConcurrentLinkedDeque<Instant> deque = buckets.get(key);
    if (deque == null) {
      return 0;
    }
    int count = 0;
    Iterator<Instant> it = deque.descendingIterator();
    while (it.hasNext()) {
      Instant event = it.next();
      if (event.isBefore(since)) {
        break;
      }
      count++;
    }
    return count;
  }

  @Override
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    buckets.remove(key);
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    int purged = 0;
    Iterator<Map.Entry<RateLimitKey, ConcurrentLinkedDeque<Instant>>> entries =
        buckets.entrySet().iterator();
    while (entries.hasNext()) {
      ConcurrentLinkedDeque<Instant> deque = entries.next().getValue();
      while (true) {
        Instant head = deque.peek();
        if (head == null || !head.isBefore(cutoff)) {
          break;
        }
        if (deque.remove(head)) {
          purged++;
        } else {
          break;
        }
      }
      if (deque.isEmpty()) {
        entries.remove();
      }
    }
    return purged;
  }
}
