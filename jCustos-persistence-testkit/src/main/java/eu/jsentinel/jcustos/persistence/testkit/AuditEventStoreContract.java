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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link AuditEventStore} implementation must satisfy.
 * <p>
 * Test classes implement this interface and supply a fresh store from
 * {@link #newStore()}; JUnit picks up the {@code @Test default}
 * methods as test methods on the implementing class. The contract
 * does not assume anything about the storage technology — both the
 * in-memory default and a future Eclipse-Store-backed implementation
 * use exactly the same set of assertions.
 * <p>
 * Since 00.84.00 the contract includes the correlation id (R5, JS-SEC-066): a
 * store must keep the id handed to
 * {@link AuditEventStore#append(TenantId, AuditEvent, String)}. A store that
 * inherits the default of that method drops it and fails
 * {@link #appendKeepsTheCorrelationId()}.
 */
@DisplayName("AuditEventStore — contract")
public interface AuditEventStoreContract {

  /** Correlation id the R5 tests append with; the form Caddy's {@code {http.request.uuid}} has. */
  String CORRELATION_ID = "4f1c2b9e-77aa-4c3e-9d0b-6a1f0c2d3e4f";

  /** Failure message when a store inherits the dropping default of the three-argument append. */
  String DROPPED_CORRELATION_ID = "the store dropped the correlation id - override "
      + "AuditEventStore.append(TenantId, AuditEvent, String) instead of inheriting the default "
      + "(R5, JS-SEC-066)";

  /**
   * Builds a fresh, empty store instance. Implementations should
   * return a new instance on every call so test methods are isolated.
   *
   * @return a new {@code AuditEventStore}
   */
  AuditEventStore newStore();

  /**
   * Builds a sample audit event at the supplied instant.
   *
   * @param at       event instant
   * @param username subject identifier
   * @return a {@link LoginSucceeded} record
   */
  default AuditEvent sampleEvent(Instant at, String username) {
    return new LoginSucceeded(at, username, "127.0.0.1", "sid-" + username);
  }

  @Test
  @DisplayName("append assigns a non-blank id and preserves tenant + event")
  default void appendReturnsEnvelopeWithId() {
    AuditEventStore store = newStore();
    AuditEvent event = sampleEvent(Instant.now(), "alice");
    AuditEnvelope envelope = store.append(TenantId.DEFAULT, event);
    assertTrue(envelope.id() != null && !envelope.id().isBlank());
    assertEquals(TenantId.DEFAULT, envelope.tenant());
    assertEquals(event, envelope.event());
  }

  @Test
  @DisplayName("R5: append with a correlation id keeps it in the envelope and in the query result")
  default void appendKeepsTheCorrelationId() {
    AuditEventStore store = newStore();
    AuditEnvelope envelope = store.append(TenantId.DEFAULT,
        sampleEvent(Instant.parse("2026-01-01T00:00:00Z"), "alice"), CORRELATION_ID);

    assertEquals(CORRELATION_ID, envelope.correlationId(), DROPPED_CORRELATION_ID);
    List<AuditEnvelope> stored = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, stored.size());
    assertEquals(CORRELATION_ID, stored.getFirst().correlationId(), DROPPED_CORRELATION_ID);
    assertEquals(envelope, stored.getFirst());
  }

  @Test
  @DisplayName("R5: an event recorded outside a request has no correlation id")
  default void appendWithoutCorrelationIdKeepsNone() {
    AuditEventStore store = newStore();
    AuditEnvelope twoArguments = store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "alice"));
    AuditEnvelope explicitNull = store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "bob"),
        null);

    assertNull(twoArguments.correlationId());
    assertNull(explicitNull.correlationId());
    assertEquals(List.of(twoArguments, explicitNull),
        store.query(TenantId.DEFAULT, AuditQuery.all()));
  }

  @Test
  @DisplayName("R5: append refuses a malformed correlation id")
  default void appendRejectsMalformedCorrelationId() {
    AuditEventStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.append(TenantId.DEFAULT,
        sampleEvent(Instant.now(), "alice"), "id with\nline break"));
    assertThrows(IllegalArgumentException.class, () -> store.append(TenantId.DEFAULT,
        sampleEvent(Instant.now(), "alice"),
        "x".repeat(AuditEnvelope.MAX_CORRELATION_ID_LENGTH + 1)));
  }

  @Test
  @DisplayName("append assigns a fresh id per call")
  default void appendIdsAreUnique() {
    AuditEventStore store = newStore();
    AuditEnvelope a = store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "alice"));
    AuditEnvelope b = store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "alice"));
    assertNotEquals(a.id(), b.id());
  }

  @Test
  @DisplayName("append rejects null tenant / event")
  default void appendRejectsNulls() {
    AuditEventStore store = newStore();
    assertThrows(NullPointerException.class,
        () -> store.append(null, sampleEvent(Instant.now(), "alice")));
    assertThrows(NullPointerException.class,
        () -> store.append(TenantId.DEFAULT, null));
  }

  @Test
  @DisplayName("query(all) returns every envelope under the given tenant in insertion order")
  default void queryAllReturnsInsertionOrder() {
    AuditEventStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    AuditEnvelope first = store.append(TenantId.DEFAULT, sampleEvent(t0, "alice"));
    AuditEnvelope second = store.append(TenantId.DEFAULT, sampleEvent(t0.plusSeconds(1), "bob"));

    List<AuditEnvelope> all = store.query(TenantId.DEFAULT, AuditQuery.all());

    assertEquals(List.of(first, second), all);
  }

  @Test
  @DisplayName("query is tenant-scoped — events of other tenants are invisible")
  default void queryIsolatesTenants() {
    AuditEventStore store = newStore();
    TenantId acme = new TenantId("acme");
    store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "alice"));
    AuditEnvelope acmeEnv = store.append(acme, sampleEvent(Instant.now(), "bob"));

    assertEquals(List.of(acmeEnv), store.query(acme, AuditQuery.all()));
  }

  @Test
  @DisplayName("query honours AuditQuery.forSubject")
  default void queryFiltersBySubject() {
    AuditEventStore store = newStore();
    store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "alice"));
    AuditEnvelope bobEnv = store.append(TenantId.DEFAULT, sampleEvent(Instant.now(), "bob"));

    assertEquals(List.of(bobEnv),
        store.query(TenantId.DEFAULT, AuditQuery.forSubject("bob")));
  }

  @Test
  @DisplayName("query returns an immutable empty list when no envelope matches")
  default void queryEmptyResultIsImmutable() {
    AuditEventStore store = newStore();
    List<AuditEnvelope> empty = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertTrue(empty.isEmpty());
    assertThrows(UnsupportedOperationException.class,
        () -> empty.add(new AuditEnvelope("x", TenantId.DEFAULT,
            sampleEvent(Instant.now(), "alice"))));
  }

  @Test
  @DisplayName("query rejects null tenant / query")
  default void queryRejectsNulls() {
    AuditEventStore store = newStore();
    assertThrows(NullPointerException.class,
        () -> store.query(null, AuditQuery.all()));
    assertThrows(NullPointerException.class,
        () -> store.query(TenantId.DEFAULT, null));
  }

  @Test
  @DisplayName("purgeOlderThan drops events strictly before the cutoff; at-cutoff survives")
  default void purgeOlderThanDropsBefore() {
    AuditEventStore store = newStore();
    Instant cutoff = Instant.parse("2026-01-02T00:00:00Z");
    store.append(TenantId.DEFAULT, sampleEvent(
        Instant.parse("2026-01-01T12:00:00Z"), "alice"));   // before
    store.append(TenantId.DEFAULT, sampleEvent(cutoff, "bob"));               // at cutoff
    store.append(TenantId.DEFAULT, sampleEvent(cutoff.plusSeconds(60), "carol")); // after

    int purged = store.purgeOlderThan(cutoff);

    assertEquals(1, purged);
    assertEquals(2, store.query(TenantId.DEFAULT, AuditQuery.all()).size(),
        "events at the cutoff and after must survive");
  }

  @Test
  @DisplayName("purgeOlderThan on an empty store returns 0")
  default void purgeOlderThanZeroForEmpty() {
    AuditEventStore store = newStore();
    assertEquals(0, store.purgeOlderThan(Instant.now()));
  }

  @Test
  @DisplayName("purgeOlderThan rejects null cutoff")
  default void purgeOlderThanRejectsNull() {
    AuditEventStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.purgeOlderThan(null));
  }
}
