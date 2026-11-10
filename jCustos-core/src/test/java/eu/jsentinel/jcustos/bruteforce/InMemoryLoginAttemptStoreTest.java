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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryLoginAttemptStore")
class InMemoryLoginAttemptStoreTest {

  private final InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();

  private static LoginAttemptKey key(String user, String ip) {
    return new LoginAttemptKey(TenantId.DEFAULT, user, ip);
  }

  @Test
  @DisplayName("JS-SEC-048: a distinct-key spray stays bounded (least-recently-written unprotected entry goes first)")
  void sprayBounded() {
    int cap = 20;
    InMemoryLoginAttemptStore bounded = new InMemoryLoginAttemptStore(cap);
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    for (int i = 0; i < cap * 3; i++) {
      bounded.recordFailure(key("spray-" + i, "10.0.0.9"), t0.plusSeconds(i));
    }
    assertTrue(bounded.trackedKeyCount() <= cap,
        "ledger map must stay bounded, was " + bounded.trackedKeyCount());
  }

  @Test
  @DisplayName("recordFailure increments the counter and stores the timestamp")
  void recordFailureIncrements() {
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");

    store.recordFailure(k, t0);
    assertEquals(1, store.failureCount(k));
    assertEquals(Optional.of(t0), store.lastFailureAt(k));

    Instant t1 = t0.plusSeconds(30);
    store.recordFailure(k, t1);
    assertEquals(2, store.failureCount(k));
    assertEquals(Optional.of(t1), store.lastFailureAt(k),
        "lastFailureAt must reflect the most recent failure");
  }

  @Test
  @DisplayName("failureCount returns 0 for an unknown key")
  void unknownKeyCountZero() {
    assertEquals(0, store.failureCount(key("ghost", "1.1.1.1")));
  }

  @Test
  @DisplayName("lastFailureAt returns empty for an unknown key")
  void unknownKeyTimestampEmpty() {
    assertTrue(store.lastFailureAt(key("ghost", "1.1.1.1")).isEmpty());
  }

  @Test
  @DisplayName("reset drops the counter and the timestamp")
  void resetClears() {
    LoginAttemptKey k = key("alice", "1.1.1.1");
    store.recordFailure(k, Instant.now());
    store.reset(k);
    assertEquals(0, store.failureCount(k));
    assertTrue(store.lastFailureAt(k).isEmpty());
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  void resetUnknownKeyIsNoOp() {
    store.reset(key("ghost", "1.1.1.1"));
    assertEquals(0, store.failureCount(key("ghost", "1.1.1.1")));
  }

  @Test
  @DisplayName("counters are keyed independently per (tenant, userId, ip) triple")
  void countersAreKeyIndependent() {
    Instant t = Instant.now();
    store.recordFailure(key("alice", "1.1.1.1"), t);
    store.recordFailure(key("alice", "1.1.1.1"), t);
    store.recordFailure(key("alice", "2.2.2.2"), t);
    store.recordFailure(key("bob", "1.1.1.1"), t);

    assertEquals(2, store.failureCount(key("alice", "1.1.1.1")));
    assertEquals(1, store.failureCount(key("alice", "2.2.2.2")));
    assertEquals(1, store.failureCount(key("bob", "1.1.1.1")));
  }

  @Test
  @DisplayName("tenant is part of the key — same (user,ip) under different tenants are independent")
  void tenantPartOfKey() {
    Instant t = Instant.now();
    LoginAttemptKey defaultScope = new LoginAttemptKey(TenantId.DEFAULT, "alice", "1.1.1.1");
    LoginAttemptKey acmeScope = new LoginAttemptKey(new TenantId("acme"), "alice", "1.1.1.1");

    store.recordFailure(defaultScope, t);
    store.recordFailure(defaultScope, t);
    store.recordFailure(acmeScope, t);

    assertEquals(2, store.failureCount(defaultScope));
    assertEquals(1, store.failureCount(acmeScope));
  }

  @Test
  @DisplayName("all methods reject null arguments")
  void rejectNulls() {
    Instant t = Instant.now();
    assertThrows(NullPointerException.class, () -> store.recordFailure(null, t));
    assertThrows(NullPointerException.class,
        () -> store.recordFailure(key("alice", "1.1.1.1"), null));
    assertThrows(NullPointerException.class, () -> store.failureCount(null));
    assertThrows(NullPointerException.class, () -> store.lastFailureAt(null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
  }
}
