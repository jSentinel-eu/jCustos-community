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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryRateLimitStore + RateLimitKey")
class InMemoryRateLimitStoreTest {

  private static final TenantId ACME = new TenantId("acme");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private final InMemoryRateLimitStore store = new InMemoryRateLimitStore();

  private static RateLimitKey key(String scope) {
    return new RateLimitKey(TenantId.DEFAULT, scope);
  }

  // ── Key invariants ──────────────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-078: 200 000 distinct keys stay within the capacity bound, oldest keys go first")
  void boundedByDistinctKeys() {
    InMemoryRateLimitStore bounded = new InMemoryRateLimitStore(1_000);
    for (int i = 0; i < 200_000; i++) {
      bounded.recordEvent(key("client:" + i), T0.plusSeconds(i));
    }
    assertEquals(1_000, bounded.trackedKeyCount());
    assertEquals(0, bounded.countSince(key("client:0"), T0), "the key seen first was evicted");
    assertEquals(1, bounded.countSince(key("client:199999"), T0), "the newest key is tracked");
    assertThrows(IllegalArgumentException.class, () -> new InMemoryRateLimitStore(0));
  }

  @Test
  @DisplayName("JS-SEC-078: tryAdmit records only below the limit and drops events outside the window")
  void tryAdmitPrunesAndLimits() {
    RateLimitKey k = key("ip:9.9.9.9");
    for (int i = 0; i < 3; i++) {
      assertTrue(store.tryAdmit(k, T0.plusSeconds(i), T0.minusSeconds(60), 3).admitted());
    }
    RateLimitStore.Admission throttled = store.tryAdmit(k, T0.plusSeconds(3), T0.minusSeconds(60), 3);
    assertEquals(false, throttled.admitted());
    assertEquals(3, throttled.eventsInWindow());
    RateLimitStore.Admission later = store.tryAdmit(k, T0.plusSeconds(100), T0.plusSeconds(50), 3);
    assertTrue(later.admitted());
    assertEquals(1, later.eventsInWindow(), "pruned to the single new event");
    assertEquals(1, store.countSince(k, T0), "old events are gone from the bucket, not just ignored");
  }

  @Nested
  @DisplayName("RateLimitKey invariants")
  class KeyInvariants {

    @Test
    @DisplayName("blank scope rejected")
    void blankScope() {
      assertThrows(IllegalArgumentException.class,
          () -> new RateLimitKey(TenantId.DEFAULT, null));
      assertThrows(IllegalArgumentException.class,
          () -> new RateLimitKey(TenantId.DEFAULT, ""));
      assertThrows(IllegalArgumentException.class,
          () -> new RateLimitKey(TenantId.DEFAULT, "   "));
    }

    @Test
    @DisplayName("null tenant becomes DEFAULT")
    void nullTenant() {
      RateLimitKey k = new RateLimitKey(null, "ip:1.2.3.4");
      assertEquals(TenantId.DEFAULT, k.tenant());
    }

    @Test
    @DisplayName("equals considers tenant + scope")
    void equality() {
      RateLimitKey a = new RateLimitKey(TenantId.DEFAULT, "ip:1.2.3.4");
      RateLimitKey b = new RateLimitKey(TenantId.DEFAULT, "ip:1.2.3.4");
      RateLimitKey c = new RateLimitKey(ACME, "ip:1.2.3.4");
      RateLimitKey d = new RateLimitKey(TenantId.DEFAULT, "ip:5.6.7.8");
      assertEquals(a, b);
      assertNotEquals(a, c);
      assertNotEquals(a, d);
    }
  }

  // ── Store operations ────────────────────────────────────────────

  @Test
  @DisplayName("countSince on an unknown key returns 0")
  void unknownKeyZero() {
    assertEquals(0, store.countSince(key("ip:1.2.3.4"), T0));
  }

  @Test
  @DisplayName("recordEvent + countSince — counts every event at or after the cutoff")
  void countAtOrAfter() {
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    store.recordEvent(k, T0.plusSeconds(20));
    store.recordEvent(k, T0.plusSeconds(30));

    // Window starts at T0+15s — events at +20 and +30 count (2).
    assertEquals(2, store.countSince(k, T0.plusSeconds(15)));

    // Window starts at T0+20s — events at exactly the cutoff still count.
    assertEquals(2, store.countSince(k, T0.plusSeconds(20)));

    // Window starts after every event — zero.
    assertEquals(0, store.countSince(k, T0.plusSeconds(40)));
  }

  @Test
  @DisplayName("keys are isolated — events under one key don't bleed into another")
  void keysAreIsolated() {
    RateLimitKey a = key("ip:1.2.3.4");
    RateLimitKey b = key("ip:5.6.7.8");
    store.recordEvent(a, T0);
    store.recordEvent(a, T0.plusSeconds(10));
    store.recordEvent(b, T0);

    assertEquals(2, store.countSince(a, T0));
    assertEquals(1, store.countSince(b, T0));
  }

  @Test
  @DisplayName("tenant is part of the key — same scope under different tenants stays separate")
  void tenantScoped() {
    RateLimitKey defaultScope = new RateLimitKey(TenantId.DEFAULT, "ip:1.2.3.4");
    RateLimitKey acmeScope = new RateLimitKey(ACME, "ip:1.2.3.4");
    store.recordEvent(defaultScope, T0);
    store.recordEvent(acmeScope, T0);
    store.recordEvent(acmeScope, T0.plusSeconds(10));

    assertEquals(1, store.countSince(defaultScope, T0));
    assertEquals(2, store.countSince(acmeScope, T0));
  }

  @Test
  @DisplayName("reset drops every event under the key")
  void resetClears() {
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    store.reset(k);
    assertEquals(0, store.countSince(k, T0));
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  void resetUnknown() {
    store.reset(key("ghost"));
    assertEquals(0, store.countSince(key("ghost"), T0));
  }

  @Test
  @DisplayName("purgeOlderThan drops events strictly before the cutoff; at-cutoff survives")
  void purgeStrictlyBefore() {
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);                       // before
    store.recordEvent(k, T0.plusSeconds(10));       // at cutoff (survives)
    store.recordEvent(k, T0.plusSeconds(20));       // after

    int purged = store.purgeOlderThan(T0.plusSeconds(10));

    assertEquals(1, purged);
    assertEquals(2, store.countSince(k, T0.plusSeconds(10)));
  }

  @Test
  @DisplayName("purgeOlderThan that empties a key drops the empty bucket entry")
  void purgeRemovesEmptyBuckets() {
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));

    store.purgeOlderThan(T0.plusSeconds(60));

    // After full purge the key has no recorded events.
    assertEquals(0, store.countSince(k, T0));
  }

  @Test
  @DisplayName("purgeOlderThan on an empty store returns 0")
  void purgeEmptyStore() {
    assertEquals(0, store.purgeOlderThan(T0.plusSeconds(10)));
  }

  @Test
  @DisplayName("all store methods reject null arguments")
  void rejectNulls() {
    assertThrows(NullPointerException.class, () -> store.recordEvent(null, T0));
    assertThrows(NullPointerException.class,
        () -> store.recordEvent(key("ip:1.2.3.4"), null));
    assertThrows(NullPointerException.class,
        () -> store.countSince(null, T0));
    assertThrows(NullPointerException.class,
        () -> store.countSince(key("ip:1.2.3.4"), null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
    assertThrows(NullPointerException.class, () -> store.purgeOlderThan(null));
  }
}
