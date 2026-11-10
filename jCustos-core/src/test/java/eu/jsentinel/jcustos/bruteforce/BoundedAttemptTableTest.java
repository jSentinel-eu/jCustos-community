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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JS-SEC-122 (CWE-307, CWE-770): the bounded map behind the in-memory login throttles. */
@DisplayName("BoundedAttemptTable")
class BoundedAttemptTableTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private final List<String> removed = new ArrayList<>();
  private final BoundedAttemptTable<String, String> table = new BoundedAttemptTable<>(3, removed::add);

  @Test
  @DisplayName("an expired entry is dropped by the next access, through the expiry index")
  void expiredEntriesAreDropped() {
    assertTrue(table.put("a", "A", T0.plusSeconds(10), null, T0));
    assertTrue(table.put("b", "B", T0.plusSeconds(20), null, T0));

    assertEquals("A", table.get("a", T0.plusSeconds(9)));
    assertNull(table.get("a", T0.plusSeconds(10)), "expiresAt is exclusive");
    assertEquals(1, table.size());
    assertEquals(List.of("a"), removed);

    assertNull(table.get("unrelated", T0.plusSeconds(20)), "any access sweeps");
    assertEquals(0, table.size());
  }

  @Test
  @DisplayName("at capacity the unprotected entry written longest ago makes room")
  void evictsLeastRecentlyWrittenUnprotectedEntry() {
    Instant far = T0.plusSeconds(3600);
    table.put("a", "A", far, null, T0);
    table.put("b", "B", far, null, T0);
    table.put("c", "C", far, null, T0);
    table.put("a", "A2", far, null, T0);   // rewritten: now the most recent

    assertTrue(table.put("d", "D", far, null, T0));

    assertEquals(3, table.size());
    assertNull(table.peek("b"), "b was written longest ago");
    assertEquals("A2", table.peek("a"));
    assertEquals(List.of("b"), removed);
  }

  @Test
  @DisplayName("a protected entry is never evicted; a table full of them refuses a new key")
  void protectedEntriesAreKeptAndNewKeysRefused() {
    Instant far = T0.plusSeconds(3600);
    table.put("a", "A", far, T0.plusSeconds(60), T0);
    table.put("b", "B", far, T0.plusSeconds(30), T0);
    table.put("c", "C", far, T0.plusSeconds(90), T0);

    assertFalse(table.put("d", "D", far, null, T0), "nothing may be evicted");
    assertEquals(3, table.size());
    assertNull(table.peek("d"));
    assertEquals(Optional.of(T0.plusSeconds(30)), table.earliestProtectionEnd());
    assertTrue(removed.isEmpty());

    assertTrue(table.put("a", "A2", far, T0.plusSeconds(60), T0), "a known key is always updated");

    // b's protection has run out: it is the one that makes room
    assertTrue(table.put("d", "D", far, null, T0.plusSeconds(30)));
    assertNull(table.peek("b"));
    assertEquals("A2", table.peek("a"));
    assertEquals("C", table.peek("c"));
    assertEquals(3, table.size());
  }

  @Test
  @DisplayName("the size never exceeds the bound, whatever mix of entries arrives")
  void hardBound() {
    Instant far = T0.plusSeconds(3600);
    for (int i = 0; i < 200; i++) {
      Instant now = T0.plusSeconds(i);
      Instant protectedUntil = i % 3 == 0 ? now.plusSeconds(5) : null;
      table.put("k" + i, "v", i % 5 == 0 ? now.plusSeconds(2) : far, protectedUntil, now);
      assertTrue(table.size() <= 3, "size " + table.size() + " after " + i);
    }
  }

  @Test
  @DisplayName("remove tells the listener and forgets the key in every index")
  void removeForgetsTheKey() {
    Instant far = T0.plusSeconds(3600);
    table.put("a", "A", far, T0.plusSeconds(60), T0);
    table.remove("a");
    table.remove("never-there");

    assertEquals(0, table.size());
    assertEquals(List.of("a"), removed);
    assertTrue(table.earliestProtectionEnd().isEmpty());
  }
}
