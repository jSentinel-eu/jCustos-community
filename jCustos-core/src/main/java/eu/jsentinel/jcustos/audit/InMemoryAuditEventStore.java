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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link AuditEventStore} backed by a single tenant-scoped
 * list. Suitable for tests, demos, and single-tenant single-process
 * applications.
 * <p>
 * Thread-safety: a {@link ReentrantReadWriteLock} serialises writes
 * and lets concurrent queries proceed in parallel.
 * <p>
 * Identifiers are random UUIDs; query results are returned in
 * insertion order (oldest first); retention is implemented via
 * {@link #purgeOlderThan(Instant)}.
 */
@ExperimentalJCustosApi
public final class InMemoryAuditEventStore implements AuditEventStore {

  private final List<AuditEnvelope> envelopes = new ArrayList<>();
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

  /** Creates an empty store. */
  public InMemoryAuditEventStore() {
  }

  @Override
  public AuditEnvelope append(TenantId tenant, AuditEvent event) {
    return append(tenant, event, null);
  }

  /**
   * Stores the correlation id with the envelope (R5, JS-SEC-066).
   *
   * @since 00.84.00
   */
  @Override
  public AuditEnvelope append(TenantId tenant, AuditEvent event, String correlationId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(event, "event must not be null");
    AuditEnvelope envelope =
        new AuditEnvelope(UUID.randomUUID().toString(), tenant, event, correlationId);
    lock.writeLock().lock();
    try {
      envelopes.add(envelope);
    } finally {
      lock.writeLock().unlock();
    }
    return envelope;
  }

  @Override
  public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(query, "query must not be null");
    lock.readLock().lock();
    try {
      List<AuditEnvelope> result = new ArrayList<>();
      int limit = query.limit();
      for (AuditEnvelope envelope : envelopes) {
        if (envelope.tenant().equals(tenant) && query.matches(envelope.event())) {
          result.add(envelope);
          // R039: honour AuditQuery.limit (0 = unlimited), matching
          // RingBufferAuditSink — previously the limit was silently ignored.
          if (limit > 0 && result.size() >= limit) {
            break;
          }
        }
      }
      return List.copyOf(result);
    } finally {
      lock.readLock().unlock();
    }
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    lock.writeLock().lock();
    try {
      int before = envelopes.size();
      envelopes.removeIf(envelope -> envelope.event().timestamp().isBefore(cutoff));
      return before - envelopes.size();
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Returns the current store size (across every tenant). Test seam.
   *
   * @return number of envelopes
   */
  public int size() {
    lock.readLock().lock();
    try {
      return envelopes.size();
    } finally {
      lock.readLock().unlock();
    }
  }
}
