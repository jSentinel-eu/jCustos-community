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

import eu.jsentinel.jcustos.audit.RateLimitExceeded;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * Decides which refusals of a blocked key {@link InMemoryRateLimitPolicy} publishes as
 * {@link RateLimitExceeded}: at most one event per key and {@link #INTERVAL}, carrying the number
 * of refusals it stands for (exit review RF11, CWE-779). Until then every refusal of a blocked key
 * was published, so under the very flood the block exists for the audit sink - and with it an
 * audit chain or an event store - grew at the attacker's pace.
 *
 * <p>Per key: the first refusal is published at once with a count of one. Refusals within the
 * following {@link #INTERVAL} are counted, not published. The first refusal at or after the end of
 * the interval is published with the refusals counted since the previous event, itself included,
 * and starts the next interval. A clock that went back behind the previous event ends the interval
 * as well - fail towards more audit. Refusals counted after the last event of a key are published
 * by its next refusal, or by {@link #flushDue(Instant)}.</p>
 *
 * <p>Bounded: at most {@link #MAX_TRACKED_KEYS} keys, ordered by their last event. A key that
 * refuses for the first time while every slot is taken makes room by evicting the key whose last
 * event is the oldest - if that event is at least one interval old. The evicted key's counted
 * refusals are not dropped: they move to the aggregate key, under the scope
 * {@link InMemoryRateLimitPolicy#UNTRACKED_KEYS_AUDIT_SCOPE}. When every tracked key has published
 * within the last interval, the new key is not tracked and its refusal is counted under the
 * aggregate key. The aggregate key is throttled like any other key. A key leaves only once its
 * last event is an interval old, so within any interval there is at most one event per place in
 * the bound plus one aggregate event - {@link #MAX_TRACKED_KEYS} + 1, however many keys a flood
 * brings. The aggregate loses only the scope of the refusals it folds in. No refusal is lost.</p>
 *
 * <p>Thread-safe: every decision runs under one lock, so concurrent refusals of one key produce
 * exactly one event per interval and every refusal is counted once. The caller publishes the
 * returned {@link Publication}s after the lock is released.</p>
 */
final class RefusalAuditThrottle {

  /**
   * At most one {@link RateLimitExceeded} per key within this interval: one second. Fixed - not
   * configurable - so that the audit volume of a block does not depend on configuration.
   */
  static final Duration INTERVAL = Duration.ofSeconds(1);

  /**
   * Keys whose counts are kept individually: 10 000. Beyond that, refusals are counted under
   * the aggregate key; see the class description.
   */
  static final int MAX_TRACKED_KEYS = 10_000;

  /**
   * One event to publish.
   *
   * @param key      the key the refusals belong to - the aggregate key for refusals that could
   *                 not be tracked individually
   * @param refusals the refusals the event stands for; at least one
   */
  record Publication(RateLimitKey key, int refusals) {
  }

  /** Counting state of one key; guarded by the lock of the throttle. */
  private static final class Slot {
    /** Instant of the last event; {@code null} before the first. */
    private Instant lastPublished;
    /** First instant at which the next event may be published. */
    private Instant due;
    /** Refusals counted since the last event. */
    private long pending;

    private boolean isDue(Instant now) {
      return lastPublished == null || !now.isBefore(due) || now.isBefore(lastPublished);
    }

    /**
     * Counts {@code refusals} and decides whether they are published now.
     *
     * @return the refusals to publish now, or {@code 0} to hold them back
     */
    private int count(Instant now, Duration interval, long refusals) {
      long total = pending + refusals;
      if (isDue(now) || total >= Integer.MAX_VALUE) {
        return publish(now, interval, total);
      }
      pending = total;
      return 0;
    }

    /** @return the counted refusals to publish now, or {@code 0} when none or not yet due */
    private int flushIfDue(Instant now, Duration interval) {
      return pending > 0 && isDue(now) ? publish(now, interval, pending) : 0;
    }

    /** @return {@code true} when nothing is counted and the interval of the last event is over */
    private boolean isIdle(Instant now) {
      return pending == 0 && isDue(now);
    }

    private int publish(Instant now, Duration interval, long total) {
      int published = (int) Math.min(total, Integer.MAX_VALUE);
      pending = total - published;
      lastPublished = now;
      due = plusSaturating(now, interval);
      return published;
    }
  }

  private final Duration interval;
  private final int maxTrackedKeys;
  private final RateLimitKey aggregateKey;
  private final ReentrantLock lock = new ReentrantLock();
  /** The tracked keys, the one with the oldest last event first. */
  private final LinkedHashMap<RateLimitKey, Slot> slots = new LinkedHashMap<>();
  /** Refusals that are not counted under their own key. */
  private final Slot aggregate = new Slot();

  /**
   * @param aggregateKey   the key under which refusals are counted that cannot be tracked
   *                       individually
   */
  RefusalAuditThrottle(RateLimitKey aggregateKey) {
    this(INTERVAL, MAX_TRACKED_KEYS, aggregateKey);
  }

  /** For tests: a smaller bound or a different interval. */
  RefusalAuditThrottle(Duration interval, int maxTrackedKeys, RateLimitKey aggregateKey) {
    requireNonNull(interval, "interval must not be null");
    if (interval.isZero() || interval.isNegative()) {
      throw new IllegalArgumentException("interval must be strictly positive");
    }
    if (maxTrackedKeys < 1) {
      throw new IllegalArgumentException("maxTrackedKeys must be >= 1, was " + maxTrackedKeys);
    }
    this.interval = interval;
    this.maxTrackedKeys = maxTrackedKeys;
    this.aggregateKey = requireNonNull(aggregateKey, "aggregateKey must not be null");
  }

  /**
   * Counts one refusal of {@code key}.
   *
   * @param key the refused key; non-null
   * @param now the instant of the refusal, from the policy's clock; non-null
   * @return the events to publish now - none, one for {@code key}, one for the aggregate key, or
   *         one for each when the refusal also evicted a key with counted refusals; never
   *         {@code null}
   */
  List<Publication> refused(RateLimitKey key, Instant now) {
    requireNonNull(key, "key must not be null");
    requireNonNull(now, "now must not be null");
    List<Publication> publications = new ArrayList<>(1);
    lock.lock();
    try {
      Slot slot = slots.get(key);
      if (slot == null) {
        if (slots.size() >= maxTrackedKeys && !evictOldest(now, publications)) {
          // every tracked key published within the last interval: count it in the aggregate
          addIfAny(publications, aggregateKey, aggregate.count(now, interval, 1));
          return publications;
        }
        slot = new Slot();
        slots.put(key, slot);
      }
      int refusals = slot.count(now, interval, 1);
      if (refusals > 0) {
        slots.putLast(key, slot); // ordered by the last event
        publications.add(new Publication(key, refusals));
      }
      return publications;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Publishes what is counted and due - for every tracked key and the aggregate key - and forgets
   * the keys that have nothing counted and whose interval is over.
   *
   * @param now the current instant, from the policy's clock; non-null
   * @return the events to publish now; never {@code null}
   */
  List<Publication> flushDue(Instant now) {
    requireNonNull(now, "now must not be null");
    List<Publication> publications = new ArrayList<>();
    lock.lock();
    try {
      List<Map.Entry<RateLimitKey, Slot>> published = new ArrayList<>();
      Iterator<Map.Entry<RateLimitKey, Slot>> entries = slots.entrySet().iterator();
      while (entries.hasNext()) {
        Map.Entry<RateLimitKey, Slot> entry = entries.next();
        Slot slot = entry.getValue();
        if (slot.isIdle(now)) {
          entries.remove();
          continue;
        }
        int refusals = slot.flushIfDue(now, interval);
        if (refusals > 0) {
          entries.remove();
          published.add(entry);
          publications.add(new Publication(entry.getKey(), refusals));
        }
      }
      for (Map.Entry<RateLimitKey, Slot> entry : published) {
        slots.putLast(entry.getKey(), entry.getValue()); // ordered by the last event
      }
      addIfAny(publications, aggregateKey, aggregate.flushIfDue(now, interval));
      return publications;
    } finally {
      lock.unlock();
    }
  }

  /** @return the number of keys tracked individually - for tests */
  int trackedKeyCount() {
    lock.lock();
    try {
      return slots.size();
    } finally {
      lock.unlock();
    }
  }

  /** @return refusals counted and not yet published, the aggregate included - for tests */
  long pendingRefusals() {
    lock.lock();
    try {
      long pending = aggregate.pending;
      for (Slot slot : slots.values()) {
        pending += slot.pending;
      }
      return pending;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Evicts the key with the oldest last event if its interval is over; its counted refusals move
   * to the aggregate key.
   *
   * @return {@code false} when the oldest key is still within its interval - so is every other
   */
  private boolean evictOldest(Instant now, List<Publication> publications) {
    Map.Entry<RateLimitKey, Slot> oldest = slots.firstEntry();
    if (oldest == null || !oldest.getValue().isDue(now)) {
      return false;
    }
    slots.pollFirstEntry();
    long carried = oldest.getValue().pending;
    if (carried > 0) {
      addIfAny(publications, aggregateKey, aggregate.count(now, interval, carried));
    }
    return true;
  }

  private static void addIfAny(List<Publication> publications, RateLimitKey key, int refusals) {
    if (refusals > 0) {
      publications.add(new Publication(key, refusals));
    }
  }

  private static Instant plusSaturating(Instant instant, Duration duration) {
    try {
      return instant.plus(duration);
    } catch (DateTimeException | ArithmeticException beyondTheTimeline) {
      return Instant.MAX;
    }
  }
}
