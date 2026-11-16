package eu.jsentinel.jcustos.events.store;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.util.List;
import java.util.Optional;

/**
 * Envelope store (Konzept §726) for resume, diagnostics and operational
 * processing. <strong>Not</strong> an audit store — revision-grade persistence
 * is an audit listener's job (Konzept §720).
 *
 * <p>The store guarantees a stable append order so the SSE bridge can resume
 * from a {@link JCustosEventCursor}.
 *
 * <p><strong>Retention (R07, V00.76.10): unbounded by design.</strong> A
 * {@link JCustosEventCursor} is a stable append position, and {@link
 * #findAfter(JCustosEventCursor, int)} resumes from it — so the store is an
 * append-only log and cannot purge old entries without invalidating outstanding
 * cursors. Bounding it is therefore an <em>operational</em> concern: tier the
 * persistent store behind an external retention/archival job (it is "not an
 * audit store" — see above; audit-grade durability is an audit listener's job),
 * or front it with a bounded-window implementation that advances cursors. The
 * shipped in-memory store is for development / single-process use and grows with
 * the event volume; do not use it as a long-lived sink.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventEnvelopeStore {

  /**
   * Appends an envelope, assigning it the next position in the stable order.
   *
   * <p><strong>Atomic (JS-SEC-108):</strong> the method either stores the
   * envelope and returns its position, or throws and has stored nothing — no
   * entry, no position, nothing a restart could bring back. The
   * {@link eu.jsentinel.jcustos.events.bus.DefaultJCustosEventBus} relies on
   * this: when {@code append} throws, it hands the envelope's sequence back to
   * the publish pipeline, and the next publish reuses it. An implementation
   * that persisted the envelope and then threw would leave two envelopes with
   * the same sequence, one of which every consumer rejects as a repeat. The
   * shipped stores roll the entry back before they throw.
   *
   * @param envelope the envelope to store
   * @return the assigned cursor position
   * @throws RuntimeException if the envelope could not be stored; nothing was
   *     stored then
   */
  JCustosEventCursor append(SignedJCustosEventEnvelope envelope);

  /**
   * Returns up to {@code limit} envelopes stored after the given cursor, in
   * append order.
   *
   * @param cursor the exclusive lower bound
   * @param limit the maximum number of envelopes to return
   * @return the next page of stored envelopes
   */
  List<StoredEnvelope> findAfter(JCustosEventCursor cursor, int limit);

  /**
   * @param envelopeId the envelope identity
   * @return the stored envelope, if present
   */
  Optional<SignedJCustosEventEnvelope> findByEnvelopeId(EventEnvelopeId envelopeId);

  /**
   * @return the number of stored envelopes
   */
  long count();
}
