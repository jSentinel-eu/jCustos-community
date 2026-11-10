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
package eu.jsentinel.jcustos.replay.impl;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * A capacity-bounded map of expiring entries that <strong>never rejects an insert</strong>: when
 * it is full it evicts the entry that expires earliest, and it reclaims expired entries a few at a
 * time instead of scanning the whole map (JS-SEC-150, CWE-770).
 *
 * <p>It is the shared building block of the single-JVM stores that are keyed by input an anonymous
 * caller controls ({@code JdkInMemoryStateStore}, {@link InMemoryNonceStore}). The earlier
 * behaviour of those stores — purge by a full scan, then throw when still full — let an anonymous
 * flood of login starts block every login of every user, and each failed attempt paid for a scan
 * over the whole map. Evicting the earliest-expiring entry keeps the store available: a flooding
 * caller can at most displace the oldest in-flight entries, never stop new ones.
 *
 * <p>All operations run in {@code O(log n)}. Thread-safe (synchronised).
 *
 * @param <V> the value type
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class BoundedExpiringMap<V> {

  /** Expired entries reclaimed per insert at most — amortises the purge without a full scan. */
  private static final int PURGE_BATCH = 8;

  /**
   * A value together with the instant it expires.
   *
   * @param value     the stored value
   * @param expiresAt the last instant at which the entry is still valid
   * @param <V>       the value type
   */
  public record Expiring<V>(V value, Instant expiresAt) {
    public Expiring {
      Objects.requireNonNull(value, "value");
      Objects.requireNonNull(expiresAt, "expiresAt");
    }

    /** @return whether the entry is past its expiry at {@code now} */
    public boolean isExpiredAt(Instant now) {
      return now.isAfter(expiresAt);
    }
  }

  private record IndexKey(Instant expiresAt, long sequence) implements Comparable<IndexKey> {
    @Override
    public int compareTo(IndexKey other) {
      int byExpiry = expiresAt.compareTo(other.expiresAt);
      return byExpiry != 0 ? byExpiry : Long.compare(sequence, other.sequence);
    }
  }

  private record Slot<V>(V value, IndexKey index) {
  }

  private final int capacity;
  private final Map<String, Slot<V>> slots = new HashMap<>();
  private final TreeMap<IndexKey, String> byExpiry = new TreeMap<>();
  private long sequence;

  /**
   * @param capacity the largest number of entries retained
   * @throws IllegalArgumentException if {@code capacity < 1}
   */
  public BoundedExpiringMap(int capacity) {
    this.capacity = CapacityBound.requirePositiveCapacity(capacity);
  }

  /**
   * Stores {@code value} under {@code key}, replacing an earlier entry for the same key. When the
   * map is full the entry with the earliest expiry is evicted — an expired one if there is any,
   * otherwise the live entry closest to its expiry.
   *
   * @param key       the entry key
   * @param value     the value
   * @param expiresAt the last instant at which the entry is still valid
   * @param now       the current instant, used to reclaim expired entries
   */
  public synchronized void put(String key, V value, Instant expiresAt, Instant now) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(value, "value");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(now, "now");
    Slot<V> previous = slots.remove(key);
    if (previous != null) {
      byExpiry.remove(previous.index());
    }
    for (int i = 0; i < PURGE_BATCH && !byExpiry.isEmpty()
        && now.isAfter(byExpiry.firstKey().expiresAt()); i++) {
      evictEarliest();
    }
    while (slots.size() >= capacity) {
      evictEarliest();
    }
    IndexKey index = new IndexKey(expiresAt, sequence++);
    slots.put(key, new Slot<>(value, index));
    byExpiry.put(index, key);
  }

  /**
   * Removes and returns the entry for {@code key}. The caller decides whether an expired entry
   * still counts; see {@link Expiring#isExpiredAt(Instant)}.
   *
   * @param key the entry key
   * @return the removed entry, or empty if the key is unknown
   */
  public synchronized Optional<Expiring<V>> remove(String key) {
    Objects.requireNonNull(key, "key");
    Slot<V> slot = slots.remove(key);
    if (slot == null) {
      return Optional.empty();
    }
    byExpiry.remove(slot.index());
    return Optional.of(new Expiring<>(slot.value(), slot.index().expiresAt()));
  }

  /** @return whether an entry is stored under {@code key}, expired or not */
  public synchronized boolean containsKey(String key) {
    return slots.containsKey(Objects.requireNonNull(key, "key"));
  }

  /** @return the number of retained entries, expired ones included */
  public synchronized int size() {
    return slots.size();
  }

  /** Drops every entry. */
  public synchronized void clear() {
    slots.clear();
    byExpiry.clear();
  }

  private void evictEarliest() {
    Map.Entry<IndexKey, String> earliest = byExpiry.pollFirstEntry();
    if (earliest != null) {
      slots.remove(earliest.getValue());
    }
  }
}
