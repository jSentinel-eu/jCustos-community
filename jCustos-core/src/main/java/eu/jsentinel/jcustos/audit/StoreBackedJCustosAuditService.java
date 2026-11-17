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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * {@link JCustosAuditService} that persists events through an
 * {@link AuditEventStore} (Phase 2). Complementary to
 * {@link CompositeAuditService}, which writes to a
 * {@link RingBufferAuditSink} and any extra {@link AuditSink}s but
 * never persists.
 * <p>
 * The service is bound to one {@link TenantId} at construction time —
 * single-tenant applications use the no-argument constructor and the
 * resolved tenant defaults to {@link TenantId#DEFAULT}. Multi-tenant
 * applications instantiate one service per tenant or wrap this class
 * with a tenant-resolving facade.
 *
 * <p>Failures propagating from the underlying store are swallowed in
 * {@link #publish(AuditEvent)} so audit failure cannot break the
 * security flow that emitted the event — but they are logged at
 * {@code WARN} ({@code audit/store-append-failure}) because a failing
 * store is a persistent-audit-trail gap. {@link #query(AuditQuery)}
 * does propagate them — read-side failures are an explicit caller
 * concern. The {@code (Logger)} constructor is a test / injection seam
 * mirroring {@link LoggingAuditSink}.
 *
 * <p>R5 (JS-SEC-066, CWE-778): every event is appended with the correlation id
 * of the request it was recorded in ({@link AuditCorrelation#current()}), or
 * without one outside a request.
 */
@ExperimentalJCustosApi
public final class StoreBackedJCustosAuditService implements JCustosAuditService {

  private static final Logger DEFAULT_LOGGER = HasLogger.staticLogger();

  private final AuditEventStore store;
  private final TenantId tenant;
  private final Logger logger;

  /**
   * Builds a service that operates against {@link TenantId#DEFAULT}.
   *
   * @param store backing store; must not be {@code null}
   */
  public StoreBackedJCustosAuditService(AuditEventStore store) {
    this(store, TenantId.DEFAULT);
  }

  /**
   * Builds a service that operates against the supplied tenant.
   *
   * @param store  backing store; must not be {@code null}
   * @param tenant tenant scope for every published / queried event;
   *               {@code null} becomes {@link TenantId#DEFAULT}
   */
  public StoreBackedJCustosAuditService(AuditEventStore store, TenantId tenant) {
    this(store, tenant, DEFAULT_LOGGER);
  }

  /**
   * Test / injection seam mirroring the {@link LoggingAuditSink}
   * {@code (Logger)} constructor: routes the
   * {@code audit/store-append-failure} WARN through the supplied logger.
   *
   * @param store  backing store; must not be {@code null}
   * @param tenant tenant scope for every published / queried event;
   *               {@code null} becomes {@link TenantId#DEFAULT}
   * @param logger receiver of the store-failure WARN; must not be {@code null}
   */
  public StoreBackedJCustosAuditService(AuditEventStore store, TenantId tenant, Logger logger) {
    this.store = requireNonNull(store, "store must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.logger = requireNonNull(logger, "logger must not be null");
  }

  @Override
  public void publish(AuditEvent event) {
    if (event == null) {
      return;
    }
    try {
      store.append(tenant, event, AuditCorrelation.current().orElse(null));
    } catch (RuntimeException ex) {
      // R036: never propagate — audit failure must not interrupt the security
      // flow — but a failing store is a persistent-audit-trail gap, so log it
      // at WARN. No secrets: only the store class, the event type and the
      // exception summary — never event field values.
      logger.warn(
          "audit/store-append-failure: store {} threw on a {} event; the event was not persisted ({})",
          store.getClass().getName(), event.getClass().getSimpleName(), ex.toString(), ex);
    }
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    requireNonNull(query, "query must not be null");
    List<AuditEnvelope> envelopes = store.query(tenant, query);
    List<AuditEvent> events = new ArrayList<>(envelopes.size());
    for (AuditEnvelope envelope : envelopes) {
      events.add(envelope.event());
    }
    return List.copyOf(events);
  }

  /**
   * Returns the tenant this service is bound to. Test seam / debug
   * accessor.
   *
   * @return tenant scope
   */
  public TenantId tenant() {
    return tenant;
  }
}
