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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory {@link JCustosEventSequenceStore}. The per-scope counter is held
 * in a {@link ConcurrentHashMap}; updates are atomic per
 * {@code (tenantId, producerId)} key.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class InMemorySequenceStore implements JCustosEventSequenceStore {

  private record Scope(TenantId tenantId, EventProducerId producerId) {
  }

  private final ConcurrentMap<Scope, EventSequence> sequences = new ConcurrentHashMap<>();

  @Override
  public Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId) {
    return Optional.ofNullable(sequences.get(key(tenantId, producerId)));
  }

  @Override
  public void updateSequence(TenantId tenantId, EventProducerId producerId,
      EventSequence sequence) {
    Objects.requireNonNull(sequence, "sequence");
    sequences.put(key(tenantId, producerId), sequence);
  }

  // R011: read-advance-write must be one indivisible step, else two publishers
  // for the same scope can reserve the same sequence. ConcurrentHashMap#compute
  // applies the remapping atomically per key.
  @Override
  public EventSequence reserveNext(TenantId tenantId, EventProducerId producerId) {
    return sequences.compute(key(tenantId, producerId),
        (scope, last) -> last == null ? EventSequence.FIRST : last.next());
  }

  // R016: consume-side compare-and-advance. ConcurrentHashMap#replace (present)
  // and #putIfAbsent (fresh scope) are atomic per key, so a read-validate-commit
  // that lost a race to a concurrent advance fails the CAS rather than clobbering.
  @Override
  public boolean compareAndAdvance(TenantId tenantId, EventProducerId producerId,
      Optional<EventSequence> expectedLast, EventSequence newSequence) {
    Objects.requireNonNull(expectedLast, "expectedLast");
    Objects.requireNonNull(newSequence, "newSequence");
    Scope scope = key(tenantId, producerId);
    return expectedLast
        .map(prev -> sequences.replace(scope, prev, newSequence))
        .orElseGet(() -> sequences.putIfAbsent(scope, newSequence) == null);
  }

  // JS-SEC-108: hand the reservation back only while it is still the last
  // value — ConcurrentHashMap#remove(key, value) / #replace(key, old, new) make
  // the check and the write one atomic step.
  @Override
  public boolean releaseReservation(TenantId tenantId, EventProducerId producerId,
      EventSequence reserved) {
    Objects.requireNonNull(reserved, "reserved");
    Scope scope = key(tenantId, producerId);
    if (reserved.value() <= EventSequence.FIRST.value()) {
      return reserved.equals(EventSequence.FIRST) && sequences.remove(scope, reserved);
    }
    return sequences.replace(scope, reserved, EventSequence.of(reserved.value() - 1));
  }

  // JS-SEC-105: dropping the entry returns the scope to its fresh state.
  @Override
  public void resetSequence(TenantId tenantId, EventProducerId producerId) {
    sequences.remove(key(tenantId, producerId));
  }

  private static Scope key(TenantId tenantId, EventProducerId producerId) {
    return new Scope(
        Objects.requireNonNull(tenantId, "tenantId"),
        Objects.requireNonNull(producerId, "producerId"));
  }
}
