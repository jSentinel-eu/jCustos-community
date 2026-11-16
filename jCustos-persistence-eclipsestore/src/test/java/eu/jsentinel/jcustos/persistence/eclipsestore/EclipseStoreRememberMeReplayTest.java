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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService;
import eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService.IssuedToken;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-128 (CWE-613, CWE-294) with the Eclipse-Store store: the real
 * {@link StoreBackedRememberMeService} on a real storage. A remember-me token that was exchanged
 * and is presented again has been copied; the service can only tell with a store that remembers
 * the exchange - and a persistent store has to remember it across a restart.
 */
@DisplayName("EclipseStoreRememberMeTokenStore - a replayed remember-me token is recognised, also after a restart")
class EclipseStoreRememberMeReplayTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Duration TTL = Duration.ofDays(14);

  @TempDir
  Path tempDir;

  private final AtomicInteger tokens = new AtomicInteger();

  private StoreBackedRememberMeService service(RememberMeTokenStore store, Instant now) {
    return new StoreBackedRememberMeService(store, new Sha256TokenHasher(), TenantId.DEFAULT,
        Clock.fixed(now, ZoneOffset.UTC), () -> "synthetic-token-" + tokens.incrementAndGet());
  }

  @Test
  @DisplayName("the thief's copy is presented after a restart: refused, and every token of the subject is revoked")
  void replayAfterRestartRevokesTheSubject() {
    String stolen;
    String successor;
    String secondDevice;
    String bobs;
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      StoreBackedRememberMeService service = service(storage.rememberMeTokenStore(), T0);
      stolen = service.issue(ALICE, TTL).plainToken();
      secondDevice = service.issue(ALICE, TTL).plainToken();
      bobs = service.issue(BOB, TTL).plainToken();
      // the owner comes back: the token is exchanged, the copy in the thief's hands is now stale
      successor = service.rotate(stolen).map(IssuedToken::plainToken).orElseThrow();
    }

    Instant nextDay = T0.plus(Duration.ofDays(1));
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      StoreBackedRememberMeService service = service(reopened.rememberMeTokenStore(), nextDay);
      assertTrue(service.validate(successor).isPresent(), "precondition: the successor is live");

      assertEquals(Optional.empty(), service.rotate(stolen), "the consumed token is refused");

      assertTrue(service.validate(successor).isEmpty(),
          "the replay must revoke the successor - whoever holds it may be the thief");
      assertTrue(service.validate(secondDevice).isEmpty(), "and every other token of the subject");
      assertTrue(service.validate(bobs).isPresent(), "another subject is not affected");
    }

    try (EclipseStoreJCustosStorage again = EclipseStoreJCustosStorage.openAt(tempDir)) {
      StoreBackedRememberMeService service = service(again.rememberMeTokenStore(), nextDay);
      assertTrue(service.validate(successor).isEmpty(), "the revocation is on disk");
      assertTrue(service.validate(bobs).isPresent());
    }
  }

  @Test
  @DisplayName("a second presentation within the race tolerance is refused without revoking anything")
  void parallelRequestOfTheSameClientIsNotAReplay() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RememberMeTokenStore store = storage.rememberMeTokenStore();
      String presented = service(store, T0).issue(ALICE, TTL).plainToken();
      String successor = service(store, T0).rotate(presented).map(IssuedToken::plainToken).orElseThrow();

      Instant momentLater = T0.plus(StoreBackedRememberMeService.ROTATION_RACE_TOLERANCE).minusMillis(1);
      assertEquals(Optional.empty(), service(store, momentLater).rotate(presented));
      assertTrue(service(store, momentLater).validate(successor).isPresent(),
          "a browser sends parallel requests with one cookie; that is not a theft");

      Instant afterTolerance = T0.plus(StoreBackedRememberMeService.ROTATION_RACE_TOLERANCE);
      assertEquals(Optional.empty(), service(store, afterTolerance).rotate(presented));
      assertTrue(service(store, afterTolerance).validate(successor).isEmpty());
    }
  }

  @Test
  @DisplayName("a token that was revoked, not rotated, is merely unknown when it is presented again")
  void revokedTokenIsNotAReplay() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RememberMeTokenStore store = storage.rememberMeTokenStore();
      StoreBackedRememberMeService service = service(store, T0);
      String revoked = service.issue(ALICE, TTL).plainToken();
      String other = service.issue(ALICE, TTL).plainToken();
      assertTrue(service.revoke(revoked));

      StoreBackedRememberMeService later = service(store, T0.plus(Duration.ofHours(1)));
      assertEquals(Optional.empty(), later.rotate(revoked));
      assertTrue(later.validate(other).isPresent(), "a logout on one device does not sign out the others");
    }
  }
}
