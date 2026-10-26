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
package eu.jsentinel.jcustos.oauth2.vaadin;

/*-
 * #%L
 * jCustos OAuth2 — Vaadin callback adapter
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
import com.vaadin.flow.server.VaadinSession;

import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The Vaadin {@link StateStore} (Konzept §10.3, V00.77): the OAuth2 {@code state}
 * + PKCE verifier live in the {@link VaadinSession} for the duration between the
 * authorization redirect and the callback, surviving the browser round-trip
 * without a server-side cross-request map. All entries are kept in a single
 * session attribute (a {@link ConcurrentHashMap}), so {@link #clear()} is exact.
 * {@link #consume(String)} is single-use (removes the entry) and TTL-checked
 * against the injected clock.
 */
public final class VaadinSessionStateStore implements StateStore {

  private static final String ATTRIBUTE = VaadinSessionStateStore.class.getName() + ".entries";

  /** Default upper bound on pending states per Vaadin session. */
  public static final int DEFAULT_MAX_ENTRIES_PER_SESSION = 32;

  private final Supplier<Instant> clock;
  private final int maxEntriesPerSession;

  public VaadinSessionStateStore() {
    this(Instant::now);
  }

  public VaadinSessionStateStore(Supplier<Instant> clock) {
    this(clock, DEFAULT_MAX_ENTRIES_PER_SESSION);
  }

  /**
   * @param clock                time source for expiry
   * @param maxEntriesPerSession upper bound on pending states held per Vaadin
   *                             session (JS-SEC-078, CWE-770): a client can start
   *                             any number of authorisation flows without ever
   *                             finishing one; expired entries are dropped on
   *                             every {@code bind} and, at the bound, the entry
   *                             expiring soonest goes first
   * @since 00.84.00
   */
  public VaadinSessionStateStore(Supplier<Instant> clock, int maxEntriesPerSession) {
    this.clock = Objects.requireNonNull(clock, "clock");
    this.maxEntriesPerSession = CapacityBound.requirePositiveCapacity(maxEntriesPerSession);
  }

  private record Stored(StateEntry entry, Instant expiresAt) {
  }

  @Override
  public void bind(String stateKey, StateEntry entry, Duration ttl) {
    Objects.requireNonNull(stateKey, "stateKey");
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(ttl, "ttl");
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      throw new IllegalStateException(
          "No active VaadinSession — bind must run on a Vaadin request thread");
    }
    Map<String, Stored> entries = entries(session);
    Instant now = clock.get();
    // JS-SEC-078 (CWE-770): expired states never consume; drop them instead of keeping them
    entries.values().removeIf(stored -> now.isAfter(stored.expiresAt()));
    while (entries.size() >= maxEntriesPerSession && !entries.containsKey(stateKey)) {
      // at the bound the state expiring soonest is the least likely to be completed
      entries.entrySet().stream()
          .min(Map.Entry.comparingByValue(java.util.Comparator.comparing(Stored::expiresAt)))
          .map(Map.Entry::getKey)
          .ifPresent(entries::remove);
    }
    entries.put(stateKey, new Stored(entry, now.plus(ttl)));
  }

  /**
   * @return number of pending states in the current Vaadin session, or 0 without one
   * @since 00.84.00
   */
  public int pendingCount() {
    VaadinSession session = VaadinSession.getCurrent();
    return session == null ? 0 : entries(session).size();
  }

  @Override
  public Optional<StateEntry> consume(String stateKey) {
    Objects.requireNonNull(stateKey, "stateKey");
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return Optional.empty();
    }
    Stored stored = entries(session).remove(stateKey); // single-use
    if (stored == null || clock.get().isAfter(stored.expiresAt())) {
      return Optional.empty();
    }
    return Optional.of(stored.entry());
  }

  @Override
  public void clear() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) {
      session.setAttribute(ATTRIBUTE, null);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Stored> entries(VaadinSession session) {
    Object existing = session.getAttribute(ATTRIBUTE);
    if (existing instanceof Map<?, ?> map) {
      return (Map<String, Stored>) map;
    }
    Map<String, Stored> created = new ConcurrentHashMap<>();
    session.setAttribute(ATTRIBUTE, created);
    return created;
  }
}
