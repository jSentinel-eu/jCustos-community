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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.credential.token.TokenDigestRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryResetTokenStore (JS-SEC-074)")
class InMemoryResetTokenStoreTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static ResetTokenRecord record(String selector, String username, Instant issuedAt, ResetTokenStatus status) {
    return new ResetTokenRecord(new TokenDigestRecord(selector, new byte[] {1, 2, 3}), username,
        issuedAt, issuedAt.plus(Duration.ofMinutes(15)), status, 1L);
  }

  @Test
  @DisplayName("findByUsername lists every record of the user regardless of status")
  void findByUsername() {
    InMemoryResetTokenStore store = new InMemoryResetTokenStore();
    store.save(record("a1", "alice", T0, ResetTokenStatus.ISSUED));
    store.save(record("a2", "alice", T0, ResetTokenStatus.CONSUMED));
    store.save(record("b1", "bob", T0, ResetTokenStatus.ISSUED));
    assertEquals(2, store.findByUsername("alice").size());
    assertEquals(1, store.findByUsername("bob").size());
    assertTrue(store.findByUsername("carol").isEmpty());
  }

  @Test
  @DisplayName("capacity: dead records are purged first, then a further live save is refused with the capacity code")
  void capacityBound() {
    Instant[] now = {T0};
    Clock clock = new Clock() {
      @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
      @Override public Clock withZone(java.time.ZoneId zone) { return this; }
      @Override public Instant instant() { return now[0]; }
    };
    InMemoryResetTokenStore store = new InMemoryResetTokenStore(2, clock);
    store.save(record("a1", "alice", T0, ResetTokenStatus.ISSUED));
    store.save(record("a2", "alice", T0, ResetTokenStatus.CONSUMED));
    assertEquals(2, store.size());

    // the consumed record is dead and makes room
    store.save(record("b1", "bob", T0, ResetTokenStatus.ISSUED));
    assertEquals(2, store.size());
    assertTrue(store.findBySelector("a2").isEmpty(), "consumed records are purged under pressure");

    // two live records: a third live one is refused
    IllegalStateException full = assertThrows(IllegalStateException.class,
        () -> store.save(record("c1", "carol", T0, ResetTokenStatus.ISSUED)));
    assertTrue(full.getMessage().startsWith(InMemoryResetTokenStore.CAPACITY_NAMESPACE + "-capacity-exceeded"),
        full.getMessage());

    // once time passes the expired ones are purged and the save succeeds
    now[0] = T0.plus(Duration.ofMinutes(16));
    store.save(record("c1", "carol", now[0], ResetTokenStatus.ISSUED));
    assertEquals(1, store.size());
  }

  @Test
  @DisplayName("configuration rejects a non-positive capacity")
  void capacityValidation() {
    assertThrows(IllegalArgumentException.class, () -> new InMemoryResetTokenStore(0, Clock.systemUTC()));
  }
}
