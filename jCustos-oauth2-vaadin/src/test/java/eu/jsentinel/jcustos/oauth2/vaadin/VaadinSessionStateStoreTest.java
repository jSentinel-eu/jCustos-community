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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oauth2.api.StateEntry;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("VaadinSessionStateStore — no-active-session guard paths (no mocks)")
class VaadinSessionStateStoreTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  /** Minimal VaadinSession that keeps attributes in a map and needs no lock (JS-SEC-078 tests). */
  private static final class InMemoryVaadinSession extends com.vaadin.flow.server.VaadinSession {
    private final Map<Object, Object> attributes = new java.util.HashMap<>();
    InMemoryVaadinSession() { super(null); }
    @Override public void setAttribute(String name, Object value) {
      if (value == null) { attributes.remove(name); } else { attributes.put(name, value); }
    }
    @Override public Object getAttribute(String name) { return attributes.get(name); }
    @Override public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) { attributes.remove(type); } else { attributes.put(type, value); }
    }
    @Override public <T> T getAttribute(Class<T> type) { return type.cast(attributes.get(type)); }
  }

  private static StateEntry entry(int i) {
    return new StateEntry("verifier-" + i, Optional.empty(), Optional.empty(), Map.of(), T0);
  }

  @Test
  @DisplayName("JS-SEC-078: pending states per session are bounded and expired ones are dropped on bind")
  void boundedPerSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    com.vaadin.flow.server.VaadinSession.setCurrent(session);
    try {
      Instant[] now = {T0};
      VaadinSessionStateStore store = new VaadinSessionStateStore(() -> now[0], 5);
      for (int i = 0; i < 100; i++) {
        store.bind("state-" + i, entry(i), Duration.ofMinutes(10));
      }
      assertEquals(5, store.pendingCount(), "a client starting flows without finishing cannot grow the session");
      assertTrue(store.consume("state-99").isPresent(), "the newest state survives");
      assertTrue(store.consume("state-0").isEmpty(), "the oldest was evicted");

      store.bind("short", entry(1), Duration.ofSeconds(1));
      now[0] = T0.plus(Duration.ofMinutes(1));
      store.bind("later", entry(2), Duration.ofMinutes(10));
      assertTrue(store.consume("short").isEmpty(), "expired entries are gone");
      assertEquals(5, store.pendingCount(), "the expired entry was dropped on bind; the four live ones and the new one remain");
      assertThrows(IllegalArgumentException.class, () -> new VaadinSessionStateStore(() -> T0, 0));
    } finally {
      com.vaadin.flow.server.VaadinSession.setCurrent(null);
    }
  }

  private final VaadinSessionStateStore store = new VaadinSessionStateStore();

  private static StateEntry entry() {
    return new StateEntry("pkce-verifier", Optional.empty(), Optional.<URI>empty(),
        Map.of(), Instant.parse("2026-06-26T10:00:00Z"));
  }

  @Test
  @DisplayName("bind without an active VaadinSession throws")
  void bindWithoutSessionThrows() {
    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> store.bind("state-1", entry(), Duration.ofMinutes(5)));
    assertTrue(ex.getMessage().contains("VaadinSession"));
  }

  @Test
  @DisplayName("consume without an active VaadinSession returns empty (never throws)")
  void consumeWithoutSessionEmpty() {
    assertTrue(store.consume("state-1").isEmpty());
  }

  @Test
  @DisplayName("clear without an active VaadinSession is a no-op")
  void clearWithoutSessionNoop() {
    assertDoesNotThrow(store::clear);
  }
}
