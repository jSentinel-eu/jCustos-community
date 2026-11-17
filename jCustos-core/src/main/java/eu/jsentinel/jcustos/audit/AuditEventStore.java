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
import java.util.List;

/**
 * Persistent counterpart to {@link AuditSink}.
 * <p>
 * A {@link AuditSink} is a write-side fanout into logs and ring
 * buffers — fire-and-forget, geared at real-time diagnostics. An
 * {@code AuditEventStore} is a query-side persistence boundary —
 * events are appended with a tenant scope, get a stable id, and can
 * be retrieved later through an {@link AuditQuery} or a time window.
 *
 * <p>The two SPIs are independent on purpose: an application can ship
 * audit events to both a fast in-memory ring buffer and a durable
 * store without coupling either implementation to the other.
 *
 * <p>Implementations must be thread-safe; concurrent {@code append}
 * and {@code query} calls happen on every request that produces an
 * audit event.
 */
@ExperimentalJCustosApi
public interface AuditEventStore {

  /**
   * Persists an audit event under the given tenant scope and returns
   * the resulting envelope (including the store-assigned identifier).
   *
   * @param tenant tenant scope; must not be {@code null}
   * @param event  audit event; must not be {@code null}
   * @return the persisted envelope, never {@code null}
   */
  AuditEnvelope append(TenantId tenant, AuditEvent event);

  /**
   * Persists an audit event together with the correlation id of the request
   * it was recorded in (R5, JS-SEC-066, CWE-778) and returns the resulting
   * envelope, whose {@link AuditEnvelope#correlationId()} is that id.
   * {@link StoreBackedJCustosAuditService} calls this method with
   * {@link AuditCorrelation#current()}.
   * <p>
   * <strong>Implementations must override it.</strong> The default exists
   * only so stores written before 00.84.00 keep compiling: it checks the id,
   * then delegates to {@link #append(TenantId, AuditEvent)} and
   * <em>drops</em> the id, so the envelope carries none.
   * {@code AuditEventStoreContract} of {@code jCustos-persistence-testkit}
   * fails for a store that inherits it.
   *
   * @param tenant        tenant scope; must not be {@code null}
   * @param event         audit event; must not be {@code null}
   * @param correlationId the request's correlation id, or {@code null} when
   *                      the event was recorded outside a request
   * @return the persisted envelope, never {@code null}
   * @throws IllegalArgumentException when {@code correlationId} is not
   *                                  {@code null} and fails
   *                                  {@link AuditEnvelope#isValidCorrelationId(String)}
   * @since 00.84.00
   */
  default AuditEnvelope append(TenantId tenant, AuditEvent event, String correlationId) {
    if (correlationId != null && !AuditEnvelope.isValidCorrelationId(correlationId)) {
      throw new IllegalArgumentException("correlationId must be 1 to "
          + AuditEnvelope.MAX_CORRELATION_ID_LENGTH + " characters from [A-Za-z0-9._:-]");
    }
    return append(tenant, event);
  }

  /**
   * Returns every persisted envelope under {@code tenant} that
   * matches {@code query}, in insertion order (oldest first).
   *
   * @param tenant tenant scope; must not be {@code null}
   * @param query  match filter; must not be {@code null}.
   *               {@link AuditQuery#all()} returns every event.
   * @return immutable list of matching envelopes; empty when none match
   */
  List<AuditEnvelope> query(TenantId tenant, AuditQuery query);

  /**
   * Drops every persisted envelope whose underlying event predates
   * {@code cutoff}, for retention purposes. Implementations that do
   * not support retention may treat this as a no-op (and document
   * it).
   *
   * @param cutoff retention boundary; events with
   *               {@code event.timestamp().isBefore(cutoff)} are
   *               removed
   * @return number of envelopes purged
   */
  int purgeOlderThan(Instant cutoff);
}
