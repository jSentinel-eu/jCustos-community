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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemorySessionRegistry (JS-SEC-078)")
class InMemorySessionRegistryTest {

  private static final String ISSUER = "https://idp.example";

  @Test
  @DisplayName("unregister forgets one RP session; the registry is empty once every session is unregistered")
  void unregisterEmptiesRegistry() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sid-1"), "rp-1");
    registry.register(ISSUER, "alice", Optional.of("sid-2"), "rp-2");
    registry.register(ISSUER, "bob", Optional.empty(), "rp-3");
    assertEquals(3, registry.trackedSessionCount());

    registry.unregister("rp-1");
    assertEquals(Set.of("rp-2"), registry.terminate(ISSUER, Optional.of("alice"), Optional.empty()),
        "a forgotten session is not terminated again");
    registry.unregister("rp-3");
    registry.unregister("unknown");
    assertEquals(0, registry.trackedSessionCount(), "registry empty after unregister of every session");
    assertEquals(Set.of(), registry.terminate(ISSUER, Optional.of("bob"), Optional.empty()));
    assertEquals(Set.of(), registry.terminate(ISSUER, Optional.empty(), Optional.of("sid-1")));
  }

  @Test
  @DisplayName("200 000 registrations stay within the bound; the session registered first is forgotten")
  void boundedRegistrations() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry(1_000);
    for (int i = 0; i < 200_000; i++) {
      registry.register(ISSUER, "user-" + i, Optional.of("sid-" + i), "rp-" + i);
    }
    assertEquals(1_000, registry.trackedSessionCount());
    assertEquals(Set.of(), registry.terminate(ISSUER, Optional.of("user-0"), Optional.empty()), "oldest forgotten");
    assertEquals(Set.of("rp-199999"), registry.terminate(ISSUER, Optional.empty(), Optional.of("sid-199999")));
    assertEquals(999, registry.trackedSessionCount(), "terminate forgets the session too");
  }

  @Test
  @DisplayName("re-registering a session id under another subject moves it; terminate on the old subject misses it")
  void reregisterMoves() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sid-1"), "rp-1");
    registry.register(ISSUER, "bob", Optional.of("sid-2"), "rp-1");
    assertEquals(Set.of(), registry.terminate(ISSUER, Optional.of("alice"), Optional.empty()));
    assertEquals(Set.of("rp-1"), registry.terminate(ISSUER, Optional.of("bob"), Optional.empty()));
    assertEquals(0, registry.trackedSessionCount());
    assertThrows(IllegalArgumentException.class, () -> new InMemorySessionRegistry(0));
    assertTrue(new InMemorySessionRegistry().trackedSessionCount() == 0);
  }
}
