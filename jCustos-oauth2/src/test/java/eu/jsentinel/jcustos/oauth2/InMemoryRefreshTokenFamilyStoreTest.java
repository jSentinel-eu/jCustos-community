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

import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore.RotationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryRefreshTokenFamilyStore (JS-SEC-078)")
class InMemoryRefreshTokenFamilyStoreTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static final class MutableClock extends Clock {
    Instant now = T0;
    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    @Override public Instant instant() { return now; }
  }

  @Test
  @DisplayName("200 000 families stay within the bound; the family seen first is evicted")
  void boundedFamilies() {
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore(1_000, Duration.ofDays(7), Clock.systemUTC());
    for (int i = 0; i < 200_000; i++) {
      store.recordIssued("fam-" + i, "h-" + i);
    }
    assertEquals(1_000, store.trackedFamilyCount());
    assertEquals(RotationResult.ROTATED, store.detectReuse("fam-199999", "h-199999"), "newest family is current");
  }

  @Test
  @DisplayName("revoked family ids are bounded and forgotten after the retention")
  void revokedRetention() {
    MutableClock clock = new MutableClock();
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore(1_000, Duration.ofHours(1), clock);
    for (int i = 0; i < 200_000; i++) {
      store.revokeFamily("fam-" + i);
    }
    assertEquals(1_000, store.revokedFamilyCount(), "revoked ids are bounded too");
    assertTrue(store.isRevoked("fam-199999"));
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse("fam-199999", "any"));

    clock.now = T0.plus(Duration.ofHours(2));
    assertFalse(store.isRevoked("fam-199999"), "after the retention the id is forgotten");
    assertEquals(0, store.revokedFamilyCount());
  }

  @Test
  @DisplayName("rotation semantics are unchanged: rotate, then replay revokes the family")
  void rotationSemantics() {
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore();
    store.recordIssued("fam", "h1");
    assertEquals(RotationResult.ROTATED, store.consumeAndRotate("fam", "h1", "h2"));
    assertEquals(RotationResult.REUSE_DETECTED, store.consumeAndRotate("fam", "h1", "h3"), "replay of h1");
    assertTrue(store.isRevoked("fam"));
    assertEquals(RotationResult.REUSE_DETECTED, store.detectReuse("fam", "h2"), "the whole family is dead");
    assertEquals(0, store.trackedFamilyCount());
  }

  @Test
  @DisplayName("configuration rejects a non-positive capacity or retention")
  void configurationValidation() {
    assertThrows(IllegalArgumentException.class, () -> new InMemoryRefreshTokenFamilyStore(0, Duration.ofDays(1), Clock.systemUTC()));
    assertThrows(IllegalArgumentException.class, () -> new InMemoryRefreshTokenFamilyStore(10, Duration.ZERO, Clock.systemUTC()));
  }
}
