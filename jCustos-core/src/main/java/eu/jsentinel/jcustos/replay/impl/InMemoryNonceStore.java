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
package eu.jsentinel.jcustos.replay.impl;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.replay.api.NonceStore;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * In-memory {@link NonceStore} (V00.79): per-request-key nonce binding with TTL and
 * single-use consume. For a single JVM only. Thread-safe.
 *
 * <p><strong>JS-SEC-150 (CWE-770):</strong> the store is bounded and <em>never rejects a
 * binding</em>. When it is full the binding that expires earliest is evicted; expired bindings are
 * reclaimed a few at a time on every {@link #bind}, without a scan over the whole map. Up to
 * 00.83.x a full store threw {@code replay/nonce-store-capacity-exceeded}, so an anonymous caller
 * who started flows without finishing them could block every flow of every user — the behaviour
 * {@link InMemoryJtiStore} has always avoided as a trivial full denial of service.
 */
@ExperimentalJCustosApi
public final class InMemoryNonceStore implements NonceStore {

  private final Supplier<Instant> clock;
  private final BoundedExpiringMap<String> bindings;

  public InMemoryNonceStore() {
    this(Instant::now);
  }

  public InMemoryNonceStore(Supplier<Instant> clock) {
    this(clock, CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * JS-SEC-051 (CWE-770): additionally bound the bindings map. {@code requestKey} is
   * attacker-controlled and an initiated-but-never-consumed binding persists for the process
   * lifetime, so an attacker repeatedly initiating flows without completing the callback would leak
   * one entry per un-completed flow without limit. JS-SEC-150: on a full map {@link #bind} evicts
   * the binding that expires earliest instead of throwing.
   *
   * @param maxEntries binding cap (shared default {@link CapacityBound#DEFAULT_MAX_ENTRIES})
   */
  public InMemoryNonceStore(Supplier<Instant> clock, int maxEntries) {
    this.clock = Objects.requireNonNull(clock, "clock");
    this.bindings = new BoundedExpiringMap<>(maxEntries);
  }

  /** Package-visible for tests: number of tracked bindings (JS-SEC-051 bound). */
  int trackedKeyCount() {
    return bindings.size();
  }

  @Override
  public void bind(String requestKey, String nonce, Duration ttl) {
    Objects.requireNonNull(requestKey, "requestKey");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(ttl, "ttl");
    // JS-SEC-150 (CWE-770): never throw on a full store — evict the earliest-expiring binding.
    Instant now = clock.get();
    bindings.put(requestKey, nonce, now.plus(ttl), now);
  }

  @Override
  public Optional<String> consume(String requestKey) {
    Objects.requireNonNull(requestKey, "requestKey");
    Instant now = clock.get();
    return bindings.remove(requestKey)
        .filter(bound -> !bound.isExpiredAt(now))
        .map(BoundedExpiringMap.Expiring::value);
  }
}
