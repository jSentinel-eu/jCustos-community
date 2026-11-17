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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryAuditEventStore")
class InMemoryAuditEventStoreTest {

  private final InMemoryAuditEventStore store = new InMemoryAuditEventStore();

  private static AuditEvent loginSucceededAt(Instant t, String userId) {
    return new LoginSucceeded(t, userId, "127.0.0.1", "sid-" + userId);
  }

  // ── append ──────────────────────────────────────────────────────

  @Test
  @DisplayName("append assigns a non-blank id and keeps the supplied tenant + event")
  void appendReturnsEnvelopeWithId() {
    AuditEvent event = loginSucceededAt(Instant.now(), "alice");
    AuditEnvelope env = store.append(TenantId.DEFAULT, event);
    assertTrue(env.id() != null && !env.id().isBlank());
    assertEquals(TenantId.DEFAULT, env.tenant());
    assertEquals(event, env.event());
  }

  @Test
  @DisplayName("append generates a fresh id for every event")
  void appendIdsAreUnique() {
    AuditEnvelope a = store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "alice"));
    AuditEnvelope b = store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "alice"));
    assertNotEquals(a.id(), b.id());
  }

  @Test
  @DisplayName("R039: query honours AuditQuery.limit (was silently ignored)")
  void queryHonoursLimit() {
    for (int i = 0; i < 5; i++) {
      store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "u" + i));
    }
    AuditQuery limited = new AuditQuery(Set.of(), null, null, null, 2);
    assertEquals(2, store.query(TenantId.DEFAULT, limited).size(),
        "limit=2 must cap the result at 2 envelopes");
    // limit=0 means unlimited
    assertEquals(5, store.query(TenantId.DEFAULT, AuditQuery.all()).size());
  }

  @Test
  @DisplayName("append rejects null arguments")
  void appendRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> store.append(null, loginSucceededAt(Instant.now(), "alice")));
    assertThrows(NullPointerException.class,
        () -> store.append(TenantId.DEFAULT, null));
  }

  // ── query ───────────────────────────────────────────────────────

  @Test
  @DisplayName("query(all) returns every envelope under the given tenant in insertion order")
  void queryAllReturnsInsertionOrder() {
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    AuditEnvelope first = store.append(TenantId.DEFAULT, loginSucceededAt(t0, "alice"));
    AuditEnvelope second = store.append(TenantId.DEFAULT, loginSucceededAt(t0.plusSeconds(1), "bob"));

    List<AuditEnvelope> all = store.query(TenantId.DEFAULT, AuditQuery.all());

    assertEquals(List.of(first, second), all);
  }

  @Test
  @DisplayName("query is tenant-scoped — events under another tenant do not leak in")
  void queryIsolatesTenants() {
    TenantId acme = new TenantId("acme");
    store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "alice"));
    AuditEnvelope acmeEnv = store.append(acme, loginSucceededAt(Instant.now(), "bob"));

    List<AuditEnvelope> acmeOnly = store.query(acme, AuditQuery.all());

    assertEquals(List.of(acmeEnv), acmeOnly);
  }

  @Test
  @DisplayName("query honours AuditQuery.forSubject")
  void queryFiltersBySubject() {
    store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "alice"));
    AuditEnvelope bobEnv = store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "bob"));

    List<AuditEnvelope> bobOnly =
        store.query(TenantId.DEFAULT, AuditQuery.forSubject("bob"));

    assertEquals(List.of(bobEnv), bobOnly);
  }

  @Test
  @DisplayName("query returns an empty immutable list when no envelope matches")
  void queryEmptyResultIsImmutable() {
    List<AuditEnvelope> empty = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertTrue(empty.isEmpty());
    assertThrows(UnsupportedOperationException.class,
        () -> empty.add(new AuditEnvelope("x", TenantId.DEFAULT,
            loginSucceededAt(Instant.now(), "alice"))));
  }

  @Test
  @DisplayName("query rejects null arguments")
  void queryRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> store.query(null, AuditQuery.all()));
    assertThrows(NullPointerException.class,
        () -> store.query(TenantId.DEFAULT, null));
  }

  // ── purgeOlderThan ──────────────────────────────────────────────

  @Test
  @DisplayName("purgeOlderThan drops envelopes whose event timestamp is strictly before the cutoff")
  void purgeOlderThanDropsBefore() {
    Instant cutoff = Instant.parse("2026-01-02T00:00:00Z");
    store.append(TenantId.DEFAULT,
        loginSucceededAt(Instant.parse("2026-01-01T12:00:00Z"), "alice")); // before
    store.append(TenantId.DEFAULT,
        loginSucceededAt(cutoff, "bob"));                                    // at cutoff (kept)
    store.append(TenantId.DEFAULT,
        loginSucceededAt(cutoff.plusSeconds(60), "carol"));                  // after (kept)

    int purged = store.purgeOlderThan(cutoff);

    assertEquals(1, purged);
    assertEquals(2, store.size(),
        "events at the cutoff and after must survive");
  }

  @Test
  @DisplayName("purgeOlderThan returns zero on an already-empty store")
  void purgeOlderThanZeroForEmpty() {
    assertEquals(0, store.purgeOlderThan(Instant.now()));
  }

  @Test
  @DisplayName("purgeOlderThan rejects null cutoff")
  void purgeOlderThanRejectsNull() {
    assertThrows(NullPointerException.class, () -> store.purgeOlderThan(null));
  }

  // ── correlation id (R5, JS-SEC-066) ─────────────────────────────

  @Test
  @DisplayName("R5: append keeps the correlation id; the two-argument append keeps none")
  void appendKeepsCorrelationId() {
    AuditEnvelope withId = store.append(TenantId.DEFAULT,
        loginSucceededAt(Instant.now(), "alice"), "req-42");
    AuditEnvelope without = store.append(TenantId.DEFAULT, loginSucceededAt(Instant.now(), "bob"));

    assertEquals("req-42", withId.correlationId());
    assertEquals(null, without.correlationId());
    assertEquals(List.of(withId, without), store.query(TenantId.DEFAULT, AuditQuery.all()));
  }

  @Test
  @DisplayName("R5: a malformed correlation id is refused and nothing is stored")
  void appendRefusesMalformedCorrelationId() {
    assertThrows(IllegalArgumentException.class, () -> store.append(TenantId.DEFAULT,
        loginSucceededAt(Instant.now(), "alice"), "bad id"));
    assertEquals(0, store.size());
  }
}
