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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("BoundedExpiringMap — bounded, never rejects, evicts the earliest expiry (JS-SEC-150)")
class BoundedExpiringMapTest {

  private static final Instant T0 = Instant.parse("2026-11-10T12:00:00Z");

  @Test
  @DisplayName("put + remove round-trip; remove is single-use")
  void roundTrip() {
    BoundedExpiringMap<String> map = new BoundedExpiringMap<>(10);
    map.put("a", "va", T0.plusSeconds(60), T0);
    assertTrue(map.containsKey("a"));
    BoundedExpiringMap.Expiring<String> entry = map.remove("a").orElseThrow();
    assertEquals("va", entry.value());
    assertFalse(entry.isExpiredAt(T0.plusSeconds(60)), "valid up to and including expiresAt");
    assertTrue(entry.isExpiredAt(T0.plusSeconds(61)));
    assertEquals(Optional.empty(), map.remove("a"));
    assertEquals(0, map.size());
  }

  @Test
  @DisplayName("a full map of live entries evicts the earliest-expiring entry, never the new one")
  void evictsEarliestExpiringWhenFull() {
    BoundedExpiringMap<String> map = new BoundedExpiringMap<>(3);
    map.put("long", "v", T0.plusSeconds(3600), T0);
    map.put("short", "v", T0.plusSeconds(10), T0);
    map.put("mid", "v", T0.plusSeconds(600), T0);

    map.put("new", "v", T0.plusSeconds(300), T0);

    assertEquals(3, map.size());
    assertFalse(map.containsKey("short"), "the earliest-expiring entry is the one evicted");
    assertTrue(map.containsKey("long"));
    assertTrue(map.containsKey("mid"));
    assertTrue(map.containsKey("new"));
  }

  @Test
  @DisplayName("entries with the same expiry are evicted in insertion order")
  void sameExpiryEvictsOldestFirst() {
    BoundedExpiringMap<String> map = new BoundedExpiringMap<>(2);
    Instant exp = T0.plusSeconds(600);
    map.put("first", "v", exp, T0);
    map.put("second", "v", exp, T0);
    map.put("third", "v", exp, T0);
    assertFalse(map.containsKey("first"));
    assertTrue(map.containsKey("second"));
    assertTrue(map.containsKey("third"));
  }

  @Test
  @DisplayName("expired entries are reclaimed on later inserts although the map is not full")
  void expiredEntriesAreReclaimedIncrementally() {
    BoundedExpiringMap<String> map = new BoundedExpiringMap<>(1000);
    for (int i = 0; i < 100; i++) {
      map.put("old-" + i, "v", T0.plusSeconds(1), T0);
    }
    Instant later = T0.plusSeconds(60);
    // each insert reclaims a bounded batch; a handful of inserts clears all hundred
    for (int i = 0; i < 20; i++) {
      map.put("new-" + i, "v", later.plusSeconds(600), later);
    }
    assertEquals(20, map.size(), "all expired entries are gone, all live ones kept");
  }

  @Test
  @DisplayName("replacing a key keeps one entry and uses the new expiry for eviction")
  void replaceUpdatesExpiry() {
    BoundedExpiringMap<String> map = new BoundedExpiringMap<>(2);
    map.put("a", "v1", T0.plusSeconds(10), T0);
    map.put("b", "v", T0.plusSeconds(100), T0);
    map.put("a", "v2", T0.plusSeconds(1000), T0);
    assertEquals(2, map.size());

    map.put("c", "v", T0.plusSeconds(500), T0);
    assertFalse(map.containsKey("b"), "b now expires earliest");
    assertEquals("v2", map.remove("a").orElseThrow().value());
  }

  @Test
  @DisplayName("a flood of inserts never throws and never grows past the bound")
  void floodStaysBounded() {
    BoundedExpiringMap<Integer> map = new BoundedExpiringMap<>(50);
    for (int i = 0; i < 10_000; i++) {
      map.put("k-" + i, i, T0.plusSeconds(600), T0);
    }
    assertEquals(50, map.size());
    assertTrue(map.containsKey("k-9999"), "the newest entry is always retained");
    map.clear();
    assertEquals(0, map.size());
  }

  @Test
  @DisplayName("a capacity below one is refused")
  void capacityGuard() {
    assertThrows(IllegalArgumentException.class, () -> new BoundedExpiringMap<String>(0));
  }
}
