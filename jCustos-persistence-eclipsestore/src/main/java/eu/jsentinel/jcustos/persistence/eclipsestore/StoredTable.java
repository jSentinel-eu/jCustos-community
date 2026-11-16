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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * A persistent map whose mutations write the changed part only (JS-SEC-125,
 * CWE-770, CWE-400).
 *
 * <p>Eclipse Store writes a {@code java.util} map as one unit: every key and
 * value reference, on every {@code store(map)}. With one map per store a
 * single failed login or a single new rate-limit key rewrote the whole map —
 * 16 bytes per entry, under the write lock all security stores share. This
 * table spreads its entries over {@value #SEGMENTS} segments and gives each
 * entry a {@link Slot} of its own:</p>
 *
 * <ul>
 *   <li>a new or a removed key writes one segment — a
 *       {@value #SEGMENTS}th of the table;</li>
 *   <li>a changed value writes its slot, a constant amount.</li>
 * </ul>
 *
 * <p>Eclipse Store offers no way to store a single entry of a
 * {@code java.util} map, and its own {@code LazyHashMap} loads and unloads
 * its segments while it is read, which the read lock of the storage does not
 * allow; hence a segmentation of our own, with everything in memory.</p>
 *
 * <p><strong>What is persisted</strong> is the directory of segments — in
 * {@value #GROUPS} groups that are created when their first segment is, so
 * that an empty table costs next to nothing — and, through it, the slots.
 * <strong>What is rebuilt</strong> by {@link #attach} after a restart is the
 * index — one map over all slots in insertion order, which serves every read
 * and every iteration; the SPIs promise insertion order and the slots carry
 * a sequence number to restore it.</p>
 *
 * <p>This class and {@link Slot} are stored types: their names and their
 * non-transient fields are part of the stored format. Renaming either needs
 * an Eclipse-Store refactoring mapping.</p>
 *
 * <p>The table does not write. It reports the objects that have to be stored
 * to the sink handed to {@link #attach} —
 * {@link EclipseStoreJCustosStorage} collects them and stores them in one
 * transaction at the end of the write operation. It is not thread-safe
 * either: readers hold the storage's read lock, writers the write lock.</p>
 *
 * @param <K> key type; {@code equals}/{@code hashCode} as for any map key
 * @param <V> value type
 */
final class StoredTable<K, V> {

  /** Number of segment groups; a group is allocated with the first of its segments. */
  static final int GROUPS = 32;

  /** Segments per group. */
  static final int SEGMENTS_PER_GROUP = 32;

  /** Number of segments; a key insert or removal writes one of them. */
  static final int SEGMENTS = GROUPS * SEGMENTS_PER_GROUP;

  /** One log line for the first eviction and for every further block of this many. */
  static final long EVICTIONS_PER_LOG_LINE = 1_000;

  /**
   * One entry. The value is replaced in place, so that an update stores this
   * object instead of the segment that holds it.
   *
   * @param <V> value type
   */
  static final class Slot<V> {
    /** Position in insertion order; ascending, never reused while the entry exists. */
    private final long sequence;
    private V value;
    /** Index of the segment that holds this slot; rebuilt by {@link StoredTable#attach}. */
    private transient int segment;

    Slot(long sequence, V value) {
      this.sequence = sequence;
      this.value = value;
    }
  }

  /** {@code [group][segment in group]}; a group and a segment are {@code null} until used. */
  private final HashMap<K, Slot<V>>[][] segments;

  // ── working state: not persisted, rebuilt by attach ────────────────
  private transient LinkedHashMap<K, Slot<V>> index;
  private transient long nextSequence;
  private transient Consumer<Object> changed;
  private transient Function<V, Instant> deadline;
  /** No entry has a deadline before this instant; {@code null} when that is not known. */
  private transient Instant noDeadlineBefore;
  private transient long evictions;
  private transient boolean evictionLogDue;
  private transient long refusals;

  @SuppressWarnings("unchecked")
  StoredTable() {
    this.segments = new HashMap[GROUPS][];
  }

  /**
   * Builds the working state. Called once per opened storage, before the
   * table is used; a table created in this process is attached the same way.
   *
   * @param changedSink receives every object that has to be stored
   * @param deadlineOf  the instant from which a value is dead and may be
   *                    dropped by {@link #dropDead}; {@code null} for a table
   *                    whose values do not expire
   */
  void attach(Consumer<Object> changedSink, Function<V, Instant> deadlineOf) {
    this.changed = changedSink;
    this.deadline = deadlineOf;
    this.noDeadlineBefore = null;
    List<Map.Entry<K, Slot<V>>> all = new ArrayList<>();
    for (int segment = 0; segment < SEGMENTS; segment++) {
      HashMap<K, Slot<V>> entries = segment(segment);
      if (entries == null) {
        continue;
      }
      for (Map.Entry<K, Slot<V>> entry : entries.entrySet()) {
        entry.getValue().segment = segment;
        all.add(entry);
      }
    }
    all.sort(Comparator.comparingLong(entry -> entry.getValue().sequence));
    this.index = new LinkedHashMap<>(Math.max(16, all.size() * 2));
    for (Map.Entry<K, Slot<V>> entry : all) {
      index.put(entry.getKey(), entry.getValue());
    }
    this.nextSequence = all.isEmpty() ? 0L : all.get(all.size() - 1).getValue().sequence + 1;
  }

  /** @return the segment with that number, or {@code null} when it was never used */
  private HashMap<K, Slot<V>> segment(int number) {
    HashMap<K, Slot<V>>[] group = segments[number / SEGMENTS_PER_GROUP];
    return group == null ? null : group[number % SEGMENTS_PER_GROUP];
  }

  /** @return the segment with that number, created - and reported with its group - on first use */
  @SuppressWarnings("unchecked")
  private HashMap<K, Slot<V>> segmentForInsert(int number) {
    int groupNumber = number / SEGMENTS_PER_GROUP;
    HashMap<K, Slot<V>>[] group = segments[groupNumber];
    if (group == null) {
      group = new HashMap[SEGMENTS_PER_GROUP];
      segments[groupNumber] = group;
      changed.accept(segments);
    }
    HashMap<K, Slot<V>> entries = group[number % SEGMENTS_PER_GROUP];
    if (entries == null) {
      entries = new HashMap<>(4);
      group[number % SEGMENTS_PER_GROUP] = entries;
      changed.accept(group);
    }
    return entries;
  }

  // ── reads ──────────────────────────────────────────────────────────

  int size() {
    return index.size();
  }

  boolean containsKey(K key) {
    return index.containsKey(key);
  }

  V get(K key) {
    Slot<V> slot = index.get(key);
    return slot == null ? null : slot.value;
  }

  /** @return the values in insertion order; a live view for the holder of a lock */
  Iterable<V> values() {
    return () -> {
      Iterator<Slot<V>> slots = index.values().iterator();
      return new Iterator<>() {
        @Override
        public boolean hasNext() {
          return slots.hasNext();
        }

        @Override
        public V next() {
          return slots.next().value;
        }
      };
    };
  }

  /** @return a copy of the keys in iteration order */
  List<K> keys() {
    return new ArrayList<>(index.keySet());
  }

  /** @return the key at the head of the iteration order, or {@code null} for an empty table */
  K eldestKey() {
    Iterator<K> keys = index.keySet().iterator();
    return keys.hasNext() ? keys.next() : null;
  }

  // ── writes ─────────────────────────────────────────────────────────

  /**
   * Stores {@code value} under {@code key}. A known key keeps its place in the
   * order and writes its slot; a new key goes to the end and writes one segment.
   *
   * @return the previous value, or {@code null}
   */
  V put(K key, V value) {
    noteDeadline(value);
    Slot<V> slot = index.get(key);
    if (slot != null) {
      V previous = slot.value;
      slot.value = value;
      changed.accept(slot);
      return previous;
    }
    slot = new Slot<>(nextSequence++, value);
    slot.segment = (int) (slot.sequence % SEGMENTS); // round robin: every segment gets its share
    HashMap<K, Slot<V>> entries = segmentForInsert(slot.segment);
    entries.put(key, slot);
    index.put(key, slot);
    changed.accept(entries);
    return null;
  }

  /** @return the removed value, or {@code null} when the key was unknown */
  V remove(K key) {
    Slot<V> slot = index.remove(key);
    if (slot == null) {
      return null;
    }
    HashMap<K, Slot<V>> entries = segment(slot.segment);
    entries.remove(key);
    changed.accept(entries);
    return slot.value;
  }

  /** @return number of entries removed because {@code filter} accepted them */
  int removeIf(BiPredicate<K, V> filter) {
    int removed = 0;
    Iterator<Map.Entry<K, Slot<V>>> entries = index.entrySet().iterator();
    while (entries.hasNext()) {
      Map.Entry<K, Slot<V>> entry = entries.next();
      Slot<V> slot = entry.getValue();
      if (filter.test(entry.getKey(), slot.value)) {
        entries.remove();
        HashMap<K, Slot<V>> segment = segment(slot.segment);
        segment.remove(entry.getKey());
        changed.accept(segment);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Moves {@code key} to the end of the iteration order, so that
   * {@link #eldestKey()} names the key that was used least recently. The order
   * of use is working state: nothing is written, and after a restart the order
   * is the insertion order again.
   */
  void touch(K key) {
    Slot<V> slot = index.remove(key);
    if (slot != null) {
      index.put(key, slot);
    }
  }

  // ── expiry and bound ───────────────────────────────────────────────

  /**
   * Tells the table that a value it holds was changed in place and is now dead
   * from {@code instant} on. Values handed to {@link #put} are noted by the
   * table itself.
   */
  void noteDeadline(Instant instant) {
    if (noDeadlineBefore != null && instant.isBefore(noDeadlineBefore)) {
      noDeadlineBefore = instant;
    }
  }

  private void noteDeadline(V value) {
    if (deadline != null && noDeadlineBefore != null) {
      noteDeadline(deadline.apply(value));
    }
  }

  /**
   * Removes every entry whose deadline is at or before {@code now}. The scan is
   * skipped while the earliest deadline seen by the last scan lies ahead, so a
   * caller that hammers a full table does not buy a scan per call.
   *
   * @return number of entries removed
   */
  int dropDead(Instant now) {
    if (deadline == null || (noDeadlineBefore != null && now.isBefore(noDeadlineBefore))) {
      return 0;
    }
    Instant[] earliest = {Instant.MAX};
    int removed = removeIf((key, value) -> {
      Instant deadAt = deadline.apply(value);
      if (!now.isBefore(deadAt)) {
        return true;
      }
      if (deadAt.isBefore(earliest[0])) {
        earliest[0] = deadAt;
      }
      return false;
    });
    noDeadlineBefore = earliest[0];
    return removed;
  }

  /**
   * Makes room for {@code incoming} in a table bounded to {@code maxEntries}:
   * nothing happens for a known key or below the bound; otherwise dead entries
   * go first and then, while the table is still full, the entry at the head of
   * the iteration order.
   *
   * @return number of entries that were evicted although they were not dead
   */
  int makeRoomFor(K incoming, int maxEntries, Instant now) {
    if (hasRoomFor(incoming, maxEntries)) {
      return 0;
    }
    dropDead(now);
    int evicted = evictEldest(incoming, maxEntries, value -> true);
    recordEvictions(evicted);
    return evicted;
  }

  /**
   * @return {@code true} when {@code key} can be stored in a table bounded to
   *     {@code maxEntries}: the key is known, or the table is below the bound
   */
  boolean hasRoomFor(K key, int maxEntries) {
    return index.size() < maxEntries || index.containsKey(key);
  }

  /**
   * Makes room for {@code incoming} in a table whose entries are not all equally expendable
   * (JS-SEC-131, CWE-613): nothing happens for a known key or below the bound; otherwise the
   * entries {@code evictable} accepts are evicted from the head of the iteration order until
   * the table is below the bound. An entry the predicate refuses is never evicted, so the table
   * can stay full - {@link #hasRoomFor} tells the caller, who has to refuse the new key then.
   * The evictions are not counted; report them with {@link #recordEvictions(int)}.
   *
   * @return number of entries evicted
   */
  int evictEldest(K incoming, int maxEntries, Predicate<? super V> evictable) {
    int evicted = 0;
    Iterator<Map.Entry<K, Slot<V>>> entries = index.entrySet().iterator();
    while (!hasRoomFor(incoming, maxEntries) && entries.hasNext()) {
      Map.Entry<K, Slot<V>> entry = entries.next();
      Slot<V> slot = entry.getValue();
      if (evictable.test(slot.value)) {
        entries.remove();
        HashMap<K, Slot<V>> segment = segment(slot.segment);
        segment.remove(entry.getKey());
        changed.accept(segment);
        evicted++;
      }
    }
    return evicted;
  }

  /**
   * Counts {@code evicted} entries that were evicted although they were not dead and decides
   * {@link #evictionLogDue()} for the operation that evicted them.
   */
  void recordEvictions(int evicted) {
    long before = evictions;
    evictions += evicted;
    evictionLogDue = evicted > 0
        && (before == 0 || before / EVICTIONS_PER_LOG_LINE != evictions / EVICTIONS_PER_LOG_LINE);
  }

  /**
   * @return {@code true} when the last {@link #makeRoomFor} call evicted the first live entry
   *     since the storage was opened or crossed a further {@value #EVICTIONS_PER_LOG_LINE} -
   *     the moments at which the caller logs, so that a flood of keys is not a flood of lines
   */
  boolean evictionLogDue() {
    return evictionLogDue;
  }

  /**
   * Counts a new key the caller refused because the table is full of entries it must keep.
   *
   * @return {@code true} for the first refusal since the storage was opened and for every
   *     further {@value #EVICTIONS_PER_LOG_LINE}th - the moments at which the caller logs
   */
  boolean recordRefusal() {
    refusals++;
    return refusals == 1 || refusals % EVICTIONS_PER_LOG_LINE == 0;
  }
}
