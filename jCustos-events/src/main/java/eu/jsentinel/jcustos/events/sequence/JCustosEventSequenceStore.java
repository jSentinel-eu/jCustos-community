package eu.jsentinel.jcustos.events.sequence;

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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;

import java.util.Objects;
import java.util.Optional;

/**
 * Sequence store (Konzept §652): tracks the last accepted monotone sequence per
 * {@code tenantId + producerId}, so a consumer can detect gaps, repeats and
 * roll-backs.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventSequenceStore {

  /**
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @return the last accepted sequence for the scope, if any
   */
  Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId);

  /**
   * Atomically updates the last accepted sequence for the scope.
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @param sequence the new last-accepted sequence
   */
  void updateSequence(TenantId tenantId, EventProducerId producerId, EventSequence sequence);

  /**
   * Atomically reserves and returns the next sequence for the scope: reads the
   * current last sequence, advances it ({@link EventSequence#next()}, or
   * {@link EventSequence#FIRST} for a fresh scope), persists it and returns the
   * reserved value — as one indivisible step.
   *
   * <p>The {@code default} implementation is <strong>not</strong> atomic: it
   * composes {@link #lastSequence} and {@link #updateSequence}, so two threads
   * publishing for the same {@code (tenant, producer)} can read the same last
   * value and reserve the same next one. Concurrent implementations
   * <strong>must</strong> override this method so a reserved sequence is always
   * scope-unique (R011). The shipped in-memory and Eclipse-Store stores
   * override it atomically.</p>
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @return the freshly reserved, scope-unique next sequence
   * @since 00.75.20
   */
  default EventSequence reserveNext(TenantId tenantId, EventProducerId producerId) {
    EventSequence next = lastSequence(tenantId, producerId)
        .map(EventSequence::next)
        .orElse(EventSequence.FIRST);
    updateSequence(tenantId, producerId, next);
    return next;
  }

  /**
   * Atomically advances the last accepted sequence from {@code expectedLast} to
   * {@code newSequence} for the scope — the <em>consume-side</em> counterpart to
   * {@link #reserveNext}. If the current last sequence still equals
   * {@code expectedLast}, it is replaced by {@code newSequence} and {@code true}
   * is returned; otherwise (another thread advanced it in between) nothing is
   * changed and {@code false} is returned.
   *
   * <p>A consumer reads {@link #lastSequence}, validates the inbound sequence
   * against that observed value, then calls this method passing the same
   * observed value as {@code expectedLast}. A {@code false} result means the
   * read-validate-commit lost a race and the inbound envelope must be rejected
   * (R016, V00.76.10): there is no lost update, and the per-producer
   * monotonicity guarantee holds even when distinct envelopes claim the same
   * sequence concurrently.</p>
   *
   * <p>The {@code default} implementation is <strong>not</strong> atomic (it
   * composes {@link #lastSequence} + {@link #updateSequence}); concurrent
   * implementations <strong>must</strong> override it. The shipped in-memory and
   * Eclipse-Store stores override it atomically.</p>
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @param expectedLast the last sequence the caller observed ({@code empty} for a fresh scope)
   * @param newSequence the sequence to advance to
   * @return {@code true} iff the advance was applied atomically
   * @since 00.76.10
   */
  default boolean compareAndAdvance(TenantId tenantId, EventProducerId producerId,
      Optional<EventSequence> expectedLast, EventSequence newSequence) {
    Objects.requireNonNull(expectedLast, "expectedLast");
    Objects.requireNonNull(newSequence, "newSequence");
    if (!lastSequence(tenantId, producerId).equals(expectedLast)) {
      return false;
    }
    updateSequence(tenantId, producerId, newSequence);
    return true;
  }

  /**
   * Hands a reserved sequence back — the <em>publish-side</em> undo of
   * {@link #reserveNext} for a publish that failed after the reservation and
   * never produced an envelope (JS-SEC-108). Without it every such failure
   * leaves a hole in the producer's sequence, and a strict consumer rejects
   * everything behind a hole.
   *
   * <p>The reservation is only handed back while {@code reserved} is still the
   * last sequence of the scope. If another publish reserved a later sequence in
   * the meantime nothing is changed and {@code false} is returned — the hole
   * stays, because that later sequence may already be on its way.
   *
   * <p>The {@code default} implementation is <strong>not</strong> atomic (it
   * composes {@link #lastSequence} + {@link #updateSequence}) and writes the
   * predecessor value, which for {@link EventSequence#FIRST} is {@code 0} —
   * equivalent to a fresh scope for the next {@link #reserveNext}. Concurrent
   * implementations should override it; the shipped in-memory store does.
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @param reserved the sequence {@link #reserveNext} returned
   * @return {@code true} iff the reservation was handed back
   * @since 00.84.00
   */
  default boolean releaseReservation(TenantId tenantId, EventProducerId producerId,
      EventSequence reserved) {
    Objects.requireNonNull(reserved, "reserved");
    if (reserved.value() == 0
        || !lastSequence(tenantId, producerId).equals(Optional.of(reserved))) {
      return false;
    }
    updateSequence(tenantId, producerId, EventSequence.of(reserved.value() - 1));
    return true;
  }

  /**
   * Administrative reset of a scope (JS-SEC-105, JS-SEC-108): afterwards the
   * scope expects {@link EventSequence#FIRST} again. This is the operator's
   * way out of a scope whose stored sequence can no longer be met — a
   * poisoned or corrupted value, or a producer that restarted its counter. To
   * re-synchronise a consumer with a <em>running</em> producer instead, write
   * the last sequence known to be processed with {@link #updateSequence}.
   *
   * <p>Never call this from the consume path: resetting a scope deliberately
   * gives up the replay and loss detection the sequence provides for
   * everything sent before the reset.
   *
   * <p>The {@code default} implementation stores the sequence {@code 0}, which
   * every implementation can express and which makes {@code FIRST} the next
   * expected value. Stores that can drop the entry override it.
   *
   * @param tenantId the tenant scope
   * @param producerId the producer scope
   * @since 00.84.00
   */
  default void resetSequence(TenantId tenantId, EventProducerId producerId) {
    updateSequence(tenantId, producerId, EventSequence.of(0L));
  }
}
