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
import org.slf4j.event.Level;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StoreBackedJCustosAuditService")
class StoreBackedJCustosAuditServiceTest {

  private static AuditEvent loginSucceededAt(Instant t, String user) {
    return new LoginSucceeded(t, user, "127.0.0.1", "sid-" + user);
  }

  @Test
  @DisplayName("publish appends to the backing store; query returns the events")
  void publishAndQueryRoundtrip() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJCustosAuditService service = new StoreBackedJCustosAuditService(store);

    AuditEvent event = loginSucceededAt(Instant.now(), "alice");
    service.publish(event);

    List<AuditEvent> all = service.query(AuditQuery.all());
    assertEquals(List.of(event), all);
  }

  @Test
  @DisplayName("publish on a null event is a silent no-op (audit failure must not break the flow)")
  void publishNullSilent() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJCustosAuditService service = new StoreBackedJCustosAuditService(store);
    service.publish(null);
    assertTrue(service.query(AuditQuery.all()).isEmpty());
  }

  @Test
  @DisplayName("publish swallows store failures — audit must never break the security flow")
  void publishSwallowsStoreFailures() {
    StoreBackedJCustosAuditService service =
        new StoreBackedJCustosAuditService(new ThrowingAuditEventStore());
    service.publish(loginSucceededAt(Instant.now(), "alice"));
    // no exception escaped — that is the contract
  }

  @Test
  @DisplayName("R10: a swallowed store failure is logged at WARN as audit/store-append-failure "
      + "without event field values")
  void publishLogsSwallowedStoreFailureAtWarn() {
    ThrowingAuditEventStore failingStore = new ThrowingAuditEventStore();
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    StoreBackedJCustosAuditService service =
        new StoreBackedJCustosAuditService(failingStore, TenantId.DEFAULT, logger);

    service.publish(loginSucceededAt(Instant.now(), "alice"));

    String line = logger.firstMessage();
    assertEquals(Level.WARN, logger.levels.getFirst());
    assertTrue(line.contains("audit/store-append-failure"), line);
    assertTrue(line.contains(ThrowingAuditEventStore.class.getName()), line);
    assertTrue(line.contains("LoginSucceeded"), line);
    assertTrue(line.contains("IllegalStateException: simulated store failure"), line);
    // no secrets / PII: event field values must never reach the log line
    assertFalse(line.contains("alice"), line);
    assertFalse(line.contains("127.0.0.1"), line);
  }

  /** Hand-written failing-store double (no mock framework). */
  private static final class ThrowingAuditEventStore implements AuditEventStore {
    @Override public AuditEnvelope append(TenantId tenant, AuditEvent event) {
      throw new IllegalStateException("simulated store failure");
    }
    @Override public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
      return List.of();
    }
    @Override public int purgeOlderThan(Instant cutoff) { return 0; }
  }

  @Test
  @DisplayName("query passes the tenant through to the store")
  void queryIsTenantScoped() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    TenantId acme = new TenantId("acme");
    StoreBackedJCustosAuditService defaultService = new StoreBackedJCustosAuditService(store);
    StoreBackedJCustosAuditService acmeService =
        new StoreBackedJCustosAuditService(store, acme);

    defaultService.publish(loginSucceededAt(Instant.now(), "alice"));
    acmeService.publish(loginSucceededAt(Instant.now(), "bob"));

    assertEquals(1, defaultService.query(AuditQuery.all()).size());
    assertEquals(1, acmeService.query(AuditQuery.all()).size());
    assertEquals("bob",
        ((LoginSucceeded) acmeService.query(AuditQuery.all()).getFirst()).username());
  }

  @Test
  @DisplayName("two-arg constructor null tenant normalises to DEFAULT")
  void nullTenantBecomesDefault() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJCustosAuditService service =
        new StoreBackedJCustosAuditService(store, null);
    assertSame(TenantId.DEFAULT, service.tenant());
  }

  @Test
  @DisplayName("query returns an immutable result")
  void queryReturnsImmutable() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJCustosAuditService service = new StoreBackedJCustosAuditService(store);
    service.publish(loginSucceededAt(Instant.now(), "alice"));

    List<AuditEvent> result = service.query(AuditQuery.all());
    assertThrows(UnsupportedOperationException.class,
        () -> result.add(loginSucceededAt(Instant.now(), "intruder")));
  }

  @Test
  @DisplayName("null store / logger / query is rejected")
  void rejectNulls() {
    assertThrows(NullPointerException.class,
        () -> new StoreBackedJCustosAuditService(null));
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    assertThrows(NullPointerException.class,
        () -> new StoreBackedJCustosAuditService(store, TenantId.DEFAULT, null));
    StoreBackedJCustosAuditService service = new StoreBackedJCustosAuditService(store);
    assertThrows(NullPointerException.class, () -> service.query(null));
  }

  @Test
  @DisplayName("R5: publish appends with the current correlation id, and without one outside a scope")
  void publishPassesTheCurrentCorrelationId() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJCustosAuditService service = new StoreBackedJCustosAuditService(store);

    try (AuditCorrelation.Scope ignored = AuditCorrelation.open("req-7")) {
      service.publish(loginSucceededAt(Instant.now(), "alice"));
    }
    service.publish(loginSucceededAt(Instant.now(), "bob"));

    List<AuditEnvelope> envelopes = store.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals("req-7", envelopes.get(0).correlationId());
    assertEquals(null, envelopes.get(1).correlationId());
  }

  @Test
  @DisplayName("R5: a store that only implements the two-argument append still persists, without the id")
  void legacyStoreKeepsWorkingWithoutTheId() {
    InMemoryAuditEventStore backing = new InMemoryAuditEventStore();
    AuditEventStore legacy = new AuditEventStore() {
      @Override
      public AuditEnvelope append(TenantId tenant, AuditEvent event) {
        return backing.append(tenant, event);
      }

      @Override
      public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
        return backing.query(tenant, query);
      }

      @Override
      public int purgeOlderThan(Instant cutoff) {
        return backing.purgeOlderThan(cutoff);
      }
    };
    try (AuditCorrelation.Scope ignored = AuditCorrelation.open("req-8")) {
      new StoreBackedJCustosAuditService(legacy).publish(loginSucceededAt(Instant.now(), "alice"));
    }
    List<AuditEnvelope> envelopes = backing.query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(1, envelopes.size());
    assertEquals(null, envelopes.getFirst().correlationId(),
        "the default method drops the id - the store contract makes that visible");
  }
}
