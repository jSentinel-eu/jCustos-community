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

import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * The bounded map behind the in-memory login throttles.
 *
 * <p>JS-SEC-122 (CWE-307, CWE-770): the keys are user names and client addresses an attacker
 * chooses freely, so the map needs a bound - and the bound must not become the way around the
 * throttle. Two earlier shapes failed in opposite directions: evicting the oldest entry dropped
 * a victim's live lockout as soon as enough new keys arrived, and sparing every locked entry
 * left no bound at all once only locked entries remained. This table keeps both promises:
 *
 * <ul>
 *   <li><strong>hard bound</strong> - {@link #size()} never exceeds the configured capacity;</li>
 *   <li><strong>a protected entry is never evicted</strong> - an entry is protected until the
 *       instant its owner names (a live lockout, an attempt in flight);</li>
 *   <li><strong>expired entries go first</strong> - every access drops what has expired, driven
 *       by an expiry index, not by a scan;</li>
 *   <li>when room is still needed, the unprotected entry written longest ago is evicted;</li>
 *   <li>when every entry is protected, a new key is <strong>refused</strong> -
 *       {@link #put} returns {@code false} and the caller denies the attempt.</li>
 * </ul>
 *
 * <p>All operations are O(log n). The table is <strong>not</strong> thread-safe; its owner
 * serialises access, which is also what makes "check the counter, reserve the attempt" one step.
 *
 * @param <K> key type
 * @param <S> state type; owned and mutated by the caller, who reports the entry's deadlines on
 *            every {@link #put}
 */
final class BoundedAttemptTable<K, S> {

  private static final class Node<K, S> {
    private final K key;
    private final long sequence;
    private S state;
    private Instant expiresAt;
    /** {@code null} when the entry is not protected. */
    private Instant protectedUntil;

    private Node(K key, long sequence) {
      this.key = key;
      this.sequence = sequence;
    }
  }

  private final int maxEntries;
  private final Consumer<K> removalListener;
  private final Map<K, Node<K, S>> nodes = new HashMap<>();
  private final TreeSet<Node<K, S>> byExpiry = new TreeSet<>(
      Comparator.<Node<K, S>, Instant>comparing(node -> node.expiresAt)
          .thenComparingLong(node -> node.sequence));
  private final TreeSet<Node<K, S>> byProtection = new TreeSet<>(
      Comparator.<Node<K, S>, Instant>comparing(node -> node.protectedUntil)
          .thenComparingLong(node -> node.sequence));
  /** Unprotected entries, least recently written first. */
  private final LinkedHashSet<Node<K, S>> evictable = new LinkedHashSet<>();
  private long nextSequence;

  /**
   * @param maxEntries      hard upper bound on the number of entries
   * @param removalListener told about every key that leaves the table for any reason, or
   *                        {@code null}
   */
  BoundedAttemptTable(int maxEntries, Consumer<K> removalListener) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.removalListener = removalListener;
  }

  int size() {
    return nodes.size();
  }

  /**
   * Returns the state stored under {@code key}, after dropping everything that has expired at
   * {@code now}.
   *
   * @return the state, or {@code null} when the key is unknown or its entry had expired
   */
  S get(K key, Instant now) {
    dropExpired(now);
    Node<K, S> node = nodes.get(key);
    return node == null ? null : node.state;
  }

  /** Returns the state stored under {@code key} without consulting a clock. */
  S peek(K key) {
    Node<K, S> node = nodes.get(key);
    return node == null ? null : node.state;
  }

  /**
   * Stores {@code state} under {@code key} with fresh deadlines.
   *
   * @param expiresAt      the instant from which the entry carries no information any more
   * @param protectedUntil the instant until which the entry must not be evicted, or
   *                       {@code null} when it may be evicted at once
   * @return {@code false} when {@code key} is new, the table is full and every entry is
   *         protected - nothing was stored
   */
  boolean put(K key, S state, Instant expiresAt, Instant protectedUntil, Instant now) {
    dropExpired(now);
    Node<K, S> node = nodes.get(key);
    if (node == null) {
      if (nodes.size() >= maxEntries && !evictOne(now)) {
        return false;
      }
      node = new Node<>(key, nextSequence++);
      nodes.put(key, node);
    } else {
      unindex(node);
    }
    node.state = state;
    node.expiresAt = expiresAt;
    node.protectedUntil = protectedUntil != null && protectedUntil.isAfter(now) ? protectedUntil : null;
    byExpiry.add(node);
    if (node.protectedUntil != null) {
      byProtection.add(node);
    } else {
      evictable.add(node);
    }
    return true;
  }

  /** Removes {@code key}; unknown keys are ignored. */
  void remove(K key) {
    Node<K, S> node = nodes.get(key);
    if (node != null) {
      drop(node);
    }
  }

  /**
   * The instant at which the first protected entry stops being protected - the earliest moment
   * a refused key can find room.
   */
  Optional<Instant> earliestProtectionEnd() {
    return byProtection.isEmpty() ? Optional.empty() : Optional.of(byProtection.first().protectedUntil);
  }

  /** Visits every entry; the visitor must not modify the table. */
  void forEach(BiConsumer<K, S> visitor) {
    nodes.forEach((key, node) -> visitor.accept(key, node.state));
  }

  private void dropExpired(Instant now) {
    while (!byExpiry.isEmpty() && !byExpiry.first().expiresAt.isAfter(now)) {
      drop(byExpiry.first());
    }
  }

  /** Makes room for one entry by evicting the unprotected entry written longest ago. */
  private boolean evictOne(Instant now) {
    // a lockout or reservation that has run out since its entry was written no longer protects it
    while (!byProtection.isEmpty() && !byProtection.first().protectedUntil.isAfter(now)) {
      Node<K, S> lapsed = byProtection.pollFirst();
      lapsed.protectedUntil = null;
      evictable.add(lapsed);
    }
    var candidates = evictable.iterator();
    if (!candidates.hasNext()) {
      return false;
    }
    drop(candidates.next());
    return true;
  }

  private void drop(Node<K, S> node) {
    unindex(node);
    nodes.remove(node.key);
    if (removalListener != null) {
      removalListener.accept(node.key);
    }
  }

  private void unindex(Node<K, S> node) {
    byExpiry.remove(node);
    if (node.protectedUntil != null) {
      byProtection.remove(node);
    } else {
      evictable.remove(node);
    }
  }
}
