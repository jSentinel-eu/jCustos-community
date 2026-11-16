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

import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link AuditEventStore}. Operates on the
 * shared {@link EclipseStoreJCustosRoot.Tables#auditEnvelopes} log under
 * the storage's read-write lock.
 *
 * <p>JS-SEC-125 (CWE-770, CWE-400): an append writes the envelope and the
 * last chunk of the log — at most {@value StoredLog#CHUNK_SIZE} references —
 * where it rewrote a map over every envelope before. The log itself is not
 * bounded: an audit trail is not shortened behind the operator's back, and
 * {@link #purgeOlderThan(Instant)} is the retention the application has to
 * schedule.</p>
 */
final class EclipseStoreAuditEventStore implements AuditEventStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreAuditEventStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public AuditEnvelope append(TenantId tenant, AuditEvent event) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(event, "event must not be null");
    AuditEnvelope envelope = new AuditEnvelope(UUID.randomUUID().toString(), tenant, event);
    storage.update(() -> storage.tables().auditEnvelopes.append(envelope));
    return envelope;
  }

  @Override
  public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(query, "query must not be null");
    return storage.read(() -> {
      List<AuditEnvelope> result = new ArrayList<>();
      int limit = query.limit();
      for (AuditEnvelope envelope : storage.tables().auditEnvelopes.elements()) {
        if (envelope.tenant().equals(tenant) && query.matches(envelope.event())) {
          result.add(envelope);
          // R039: honour AuditQuery.limit (0 = unlimited) — previously ignored.
          if (limit > 0 && result.size() >= limit) {
            break;
          }
        }
      }
      return List.copyOf(result);
    });
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    return storage.write(() -> storage.tables().auditEnvelopes
        .removeIf(envelope -> envelope.event().timestamp().isBefore(cutoff)));
  }
}
