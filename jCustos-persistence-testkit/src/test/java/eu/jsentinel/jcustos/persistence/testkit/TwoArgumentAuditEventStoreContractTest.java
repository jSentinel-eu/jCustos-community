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
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R5 (JS-SEC-066): {@link AuditEventStoreContract} must expose a store written before 00.84.00 —
 * one that implements only {@code append(TenantId, AuditEvent)} and inherits the default of the
 * three-argument {@code append}, which drops the correlation id. This class runs the contract's
 * correlation tests against such a store and expects the round trip to fail, while the tests the
 * default can satisfy still pass.
 */
@DisplayName("AuditEventStoreContract — detects a store that drops the correlation id (R5)")
class TwoArgumentAuditEventStoreContractTest {

  private final AuditEventStoreContract contract = TwoArgumentOnlyStore::new;

  @Test
  @DisplayName("the round trip fails with the instruction to override the three-argument append")
  void roundTripFailsForTheInheritedDefault() {
    AssertionError failure = assertThrows(AssertionError.class,
        contract::appendKeepsTheCorrelationId);
    assertTrue(failure.getMessage().startsWith(AuditEventStoreContract.DROPPED_CORRELATION_ID),
        failure.getMessage());
  }

  @Test
  @DisplayName("the default still stores the event, still refuses a malformed id, and has no id outside a request")
  void whatTheDefaultDeliversStillPasses() {
    contract.appendWithoutCorrelationIdKeepsNone();
    contract.appendRejectsMalformedCorrelationId();
    contract.appendReturnsEnvelopeWithId();
    AuditEventStore store = contract.newStore();
    store.append(TenantId.DEFAULT,
        contract.sampleEvent(Instant.now(), "alice"), AuditEventStoreContract.CORRELATION_ID);
    assertEquals(1, store.query(TenantId.DEFAULT, AuditQuery.all()).size(),
        "the event itself is persisted; only the id is lost");
  }

  /** A store as written before 00.84.00: the three-argument append is inherited. */
  private static final class TwoArgumentOnlyStore implements AuditEventStore {

    private final InMemoryAuditEventStore delegate = new InMemoryAuditEventStore();

    @Override
    public AuditEnvelope append(TenantId tenant, AuditEvent event) {
      return delegate.append(tenant, event);
    }

    @Override
    public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
      return delegate.query(tenant, query);
    }

    @Override
    public int purgeOlderThan(Instant cutoff) {
      return delegate.purgeOlderThan(cutoff);
    }
  }
}
