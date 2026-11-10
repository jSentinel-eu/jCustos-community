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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import eu.jsentinel.jcustos.oauth2.api.StateEntry;
import eu.jsentinel.jcustos.oauth2.api.StateStore;
import eu.jsentinel.jcustos.replay.impl.BoundedExpiringMap;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * In-process {@link StateStore} (V00.77) for stateless REST / Standalone RPs:
 * a map keyed by the {@code state} value, with per-entry TTL and
 * <strong>single-use</strong> {@link #consume(String)} (the entry is
 * atomically removed, so a replayed callback cannot succeed twice). A hard cap bounds memory.
 *
 * <p><strong>JS-SEC-150 (CWE-770):</strong> the store <em>never rejects a new login</em>. When it
 * is full the entry that expires earliest is evicted; expired entries are reclaimed a few at a
 * time on every {@link #bind}, without a scan over the whole map. Up to 00.83.x a full store threw
 * {@code oauth2/state-store-capacity-exceeded} out of {@code startRequest}: the start of a login
 * is reachable anonymously, so a script that kept the store full (some 170 requests per second at
 * the defaults) made every login of every user fail with an HTTP 500 — and each failed attempt
 * paid for a scan over all entries. A flood can now at most displace the oldest logins still in
 * flight. Put a rate limit in front of the login start all the same.
 *
 * @since 00.77.00
 */
public final class JdkInMemoryStateStore implements StateStore {

  /** Default upper bound on retained (unconsumed) entries. */
  public static final int DEFAULT_CAPACITY = 100_000;

  private final BoundedExpiringMap<StateEntry> entries;
  private final Supplier<Instant> clock;

  public JdkInMemoryStateStore() {
    this(DEFAULT_CAPACITY, Instant::now);
  }

  public JdkInMemoryStateStore(int capacity, Supplier<Instant> clock) {
    if (capacity < 1) {
      throw new IllegalArgumentException("capacity must be >= 1, was " + capacity);
    }
    this.entries = new BoundedExpiringMap<>(capacity);
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public void bind(String stateKey, StateEntry entry, Duration ttl) {
    Objects.requireNonNull(stateKey, "stateKey");
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(ttl, "ttl");
    // JS-SEC-150 (CWE-770): never throw on a full store — evict the earliest-expiring entry.
    Instant now = clock.get();
    entries.put(stateKey, entry, now.plus(ttl), now);
  }

  @Override
  public Optional<StateEntry> consume(String stateKey) {
    Objects.requireNonNull(stateKey, "stateKey");
    Instant now = clock.get();
    return entries.remove(stateKey)
        .filter(bound -> !bound.isExpiredAt(now))
        .map(BoundedExpiringMap.Expiring::value);
  }

  @Override
  public void clear() {
    entries.clear();
  }

  /** @return the number of retained entries (test/diagnostic aid). */
  public int size() {
    return entries.size();
  }
}
