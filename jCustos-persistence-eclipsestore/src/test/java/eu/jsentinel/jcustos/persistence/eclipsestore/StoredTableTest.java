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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-125 (CWE-770, CWE-400): what a mutation of a {@link StoredTable} hands to the storage
 * to be written. The table is used without a storage here; the sink records the objects.
 */
@DisplayName("StoredTable - a mutation reports the changed part, never the table")
class StoredTableTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private final List<Object> reported = new ArrayList<>();

  private StoredTable<String, String> table() {
    StoredTable<String, String> table = new StoredTable<>();
    table.attach(reported::add, null);
    return table;
  }

  @Test
  @DisplayName("a new key reports one segment, a changed value its slot, a removal one segment")
  void whatAMutationReports() {
    StoredTable<String, String> table = table();
    for (int i = 0; i < 50_000; i++) {
      table.put("key-" + i, "v");
    }
    reported.clear();

    assertNull(table.put("new", "1"));
    assertEquals(1, reported.size());
    HashMap<?, ?> segment = assertInstanceOf(HashMap.class, reported.get(0));
    assertTrue(segment.size() <= 50_001 / StoredTable.SEGMENTS + 1,
        "one segment holds a " + StoredTable.SEGMENTS + "th of the table, it held " + segment.size());
    assertTrue(segment.containsKey("new"));

    reported.clear();
    assertEquals("1", table.put("new", "2"));
    assertEquals(1, reported.size());
    assertInstanceOf(StoredTable.Slot.class, reported.get(0),
        "an update writes the entry's own slot, not the segment around it");

    reported.clear();
    assertEquals("2", table.remove("new"));
    assertEquals(1, reported.size());
    assertSame(segment, reported.get(0));
    assertFalse(segment.containsKey("new"));

    reported.clear();
    assertNull(table.remove("unknown"));
    assertTrue(reported.isEmpty(), "nothing changed, nothing to write");
  }

  @Test
  @DisplayName("the entries are spread evenly over the segments")
  void entriesAreSpreadEvenly() {
    StoredTable<String, String> table = table();
    int entries = StoredTable.SEGMENTS * 10;
    for (int i = 0; i < entries; i++) {
      table.put("key-" + i, "v");
    }
    assertEquals(entries, table.size());
    int largest = 0;
    for (Object object : reported) {
      if (object instanceof HashMap<?, ?> segment) {
        largest = Math.max(largest, segment.size());
      }
    }
    assertEquals(10, largest, "a key insert must never have to write more than its share");
  }

  @Test
  @DisplayName("an empty table holds no segments; the first keys create theirs and report the directory once per group")
  void segmentsAreCreatedOnFirstUse() {
    StoredTable<String, String> table = table();
    table.put("first", "v");
    assertEquals(3, reported.size(), "the directory, the new group and the new segment");
    assertInstanceOf(Object[].class, reported.get(0));
    assertInstanceOf(Object[].class, reported.get(1));
    assertInstanceOf(HashMap.class, reported.get(2));

    reported.clear();
    table.put("second", "v");
    assertEquals(2, reported.size(), "the same group, a further segment");

    for (int i = 0; i < StoredTable.SEGMENTS; i++) {
      table.put("fill-" + i, "v");
    }
    reported.clear();
    table.put("late", "v");
    assertEquals(1, reported.size(), "every segment exists by now: the insert writes its segment only");
  }

  @Test
  @DisplayName("iteration is in insertion order, an update keeps its place, and the order survives a rebuild of the index")
  void insertionOrderSurvivesReattach() {
    StoredTable<String, String> table = table();
    table.put("b", "1");
    table.put("a", "1");
    table.put("c", "1");
    table.put("a", "2");
    assertEquals(List.of("b", "a", "c"), table.keys());
    table.remove("b");
    table.put("b", "3");
    assertEquals(List.of("a", "c", "b"), table.keys());
    assertEquals("a", table.eldestKey());

    // what a restart does: the index is rebuilt from the segments and the sequence numbers
    table.attach(reported::add, null);
    assertEquals(List.of("a", "c", "b"), table.keys());
    List<String> values = new ArrayList<>();
    table.values().forEach(values::add);
    assertEquals(List.of("2", "1", "3"), values);
    table.put("d", "4");
    assertEquals(List.of("a", "c", "b", "d"), table.keys(), "new keys continue behind the highest sequence");
  }

  @Test
  @DisplayName("touch moves a key to the end without writing; a rebuild returns to insertion order")
  void touchIsWorkingStateOnly() {
    StoredTable<String, String> table = table();
    table.put("a", "1");
    table.put("b", "1");
    table.put("c", "1");
    reported.clear();
    table.touch("a");
    table.touch("unknown");
    assertTrue(reported.isEmpty());
    assertEquals(List.of("b", "c", "a"), table.keys());
    assertEquals("b", table.eldestKey());
    table.attach(reported::add, null);
    assertEquals(List.of("a", "b", "c"), table.keys());
  }

  @Test
  @DisplayName("makeRoomFor leaves a table below its bound and a known key alone, drops dead entries first and the eldest last")
  void makeRoomDropsDeadEntriesFirst() {
    StoredTable<String, Instant> table = new StoredTable<>();
    table.attach(reported::add, deadline -> deadline);
    table.put("live-old", T0.plusSeconds(1_000));
    table.put("dead", T0.plusSeconds(10));
    table.put("live-new", T0.plusSeconds(1_000));

    assertEquals(0, table.makeRoomFor("anything", 4, T0.plusSeconds(20)), "below the bound");
    assertEquals(0, table.makeRoomFor("dead", 3, T0.plusSeconds(20)), "a known key needs no room");
    assertEquals(3, table.size());

    assertEquals(0, table.makeRoomFor("incoming", 3, T0.plusSeconds(20)),
        "the dead entry made room; nothing live was evicted");
    assertEquals(List.of("live-old", "live-new"), table.keys());
    assertFalse(table.evictionLogDue());

    table.put("incoming", T0.plusSeconds(1_000));
    assertEquals(1, table.makeRoomFor("one-more", 3, T0.plusSeconds(20)));
    assertEquals(List.of("live-new", "incoming"), table.keys(), "the entry stored first went");
    assertTrue(table.evictionLogDue(), "the first eviction is worth a log line");
    table.put("one-more", T0.plusSeconds(1_000));
    assertEquals(1, table.makeRoomFor("yet-another", 3, T0.plusSeconds(20)));
    assertFalse(table.evictionLogDue(), "the second one is not");
  }

  @Test
  @DisplayName("dropDead does not scan while the earliest deadline lies ahead")
  void dropDeadSkipsPointlessScans() {
    AtomicInteger deadlineLookups = new AtomicInteger();
    StoredTable<String, Instant> table = new StoredTable<>();
    table.attach(reported::add, deadline -> {
      deadlineLookups.incrementAndGet();
      return deadline;
    });
    for (int i = 0; i < 1_000; i++) {
      table.put("key-" + i, T0.plusSeconds(1_000 + i));
    }
    assertEquals(0, table.dropDead(T0), "the first call scans to learn the earliest deadline");
    deadlineLookups.set(0);

    for (int i = 0; i < 100; i++) {
      assertEquals(0, table.dropDead(T0.plusSeconds(999)));
    }
    assertEquals(0, deadlineLookups.get(), "a caller hammering a full table must not buy a scan per call");

    table.put("short-lived", T0.plusSeconds(5));
    assertEquals(1, table.dropDead(T0.plusSeconds(5)), "a deadline that came in later is not missed");
    assertEquals(1, table.dropDead(T0.plusSeconds(1_000)), "at its deadline an entry is dead");
    assertEquals(999, table.size());
  }
}
