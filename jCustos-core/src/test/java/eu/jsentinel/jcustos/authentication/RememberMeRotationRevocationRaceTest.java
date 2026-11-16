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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.CredentialTestKit.MutableClock;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-129 (CWE-367, CWE-613) for remember-me tokens: a {@code revokeAll}
 * that lands during a rotation or an issue is not undone, and the trail of
 * rotated tokens in the in-memory store is bounded (JS-SEC-125, CWE-770).
 * Real stores; the hooks only let a second request run at one chosen point.
 */
@DisplayName("JS-SEC-129 — a revocation during a remember-me rotation is not undone; the trail is bounded")
class RememberMeRotationRevocationRaceTest {

  private static final SubjectId ALICE = SubjectId.of("alice");
  private static final Instant T0 = Instant.parse("2026-11-16T10:00:00Z");
  private static final Duration TTL = Duration.ofDays(14);

  private final MutableClock clock = new MutableClock(T0);
  private final AtomicLong counter = new AtomicLong();

  private StoreBackedRememberMeService service(RememberMeTokenStore store) {
    return new StoreBackedRememberMeService(store, new Sha256TokenHasher(),
        TenantId.DEFAULT, clock, () -> "plainvalue-" + counter.incrementAndGet());
  }

  /**
   * The real store with hooks. {@code afterClaim} runs at the earliest moment
   * after the claim at which the store lets another request in - right after
   * {@code markRotated} for the two-step rotation of earlier releases, after
   * the whole atomic {@code rotate}. {@code beforeSave} runs before a new
   * token is stored by {@code issue}.
   */
  private static final class InterleavingStore implements RememberMeTokenStore {
    final InMemoryRememberMeTokenStore real = new InMemoryRememberMeTokenStore();
    final AtomicReference<Runnable> afterClaim = new AtomicReference<>();
    final AtomicReference<Runnable> beforeSave = new AtomicReference<>();

    private static void run(AtomicReference<Runnable> hook) {
      Runnable action = hook.getAndSet(null);
      if (action != null) {
        action.run();
      }
    }

    @Override
    public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
      return real.findByHash(tokenHash);
    }

    @Override
    public void save(RememberMeTokenRecord record) {
      real.save(record);
    }

    @Override
    public boolean saveUnlessInvalidated(RememberMeTokenRecord record) {
      run(beforeSave);
      return real.saveUnlessInvalidated(record);
    }

    @Override
    public boolean deleteByHash(String tokenHash) {
      return real.deleteByHash(tokenHash);
    }

    @Override
    public boolean markRotated(String tokenHash, Instant at) {
      boolean claimed = real.markRotated(tokenHash, at);
      run(afterClaim);
      return claimed;
    }

    @Override
    public boolean rotate(String oldHash, RememberMeTokenRecord successor, Instant now) {
      boolean rotated = real.rotate(oldHash, successor, now);
      run(afterClaim);
      return rotated;
    }

    @Override
    public Optional<RotatedToken> findRotated(String tokenHash) {
      return real.findRotated(tokenHash);
    }

    @Override
    public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
      return real.deleteBySubject(tenant, subjectId);
    }

    @Override
    public int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
      return real.deleteBySubject(tenant, subjectId, invalidBefore);
    }

    @Override
    public int purgeExpired(Instant now) {
      return real.purgeExpired(now);
    }
  }

  @Test
  @DisplayName("revokeAll right after the claim: the successor the rotation hands out is dead")
  void revokeAllAfterTheClaimIsNotUndone() {
    InterleavingStore store = new InterleavingStore();
    StoreBackedRememberMeService service = service(store);
    StoreBackedRememberMeService.IssuedToken first = service.issue(ALICE, TTL);
    clock.advance(Duration.ofMinutes(1));
    store.afterClaim.set(() -> service.revokeAll(ALICE));

    Optional<StoreBackedRememberMeService.IssuedToken> successor = service.rotate(first.plainToken());

    successor.ifPresent(issued -> assertTrue(service.validate(issued.plainToken()).isEmpty(),
        "the logout everywhere must not be undone by the successor"));
    assertTrue(store.real.findByHash(first.record().tokenHash()).isEmpty());
    assertEquals(0, service.revokeAll(ALICE), "nothing of alice is left to revoke");
  }

  @Test
  @DisplayName("revokeAll overtakes an issue: the issue is refused with the superseded code")
  void issueOvertakenByRevokeAllIsRefused() {
    InterleavingStore store = new InterleavingStore();
    StoreBackedRememberMeService service = service(store);
    store.beforeSave.set(() -> {
      clock.advance(Duration.ofMillis(1));
      service.revokeAll(ALICE);
    });

    IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> service.issue(ALICE, TTL));

    assertTrue(refused.getMessage().startsWith(StoreBackedRememberMeService.SUPERSEDED_CODE));
    assertFalse(refused.getMessage().contains("plainvalue-"), "no token value in the message");
    StoreBackedRememberMeService.IssuedToken later = service.issue(ALICE, TTL);
    assertTrue(service.rotate(later.plainToken()).isPresent(), "a sign-in after it is served");
  }

  @Test
  @DisplayName("revokeAll and a sign-in at the same instant: the sign-in counts as later")
  void issueAtTheInstantOfRevokeAll() {
    StoreBackedRememberMeService service = service(new InMemoryRememberMeTokenStore());
    service.issue(ALICE, TTL);
    service.revokeAll(ALICE);

    StoreBackedRememberMeService.IssuedToken again = service.issue(ALICE, TTL);

    assertTrue(service.rotate(again.plainToken()).isPresent());
  }

  @Test
  @DisplayName("JS-SEC-125: one cookie exchanged in a loop keeps the trail at its bound, and the latest replay is still recognised")
  void rotationTrailIsBounded() {
    int bound = 16;
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore(bound);
    StoreBackedRememberMeService service = service(store);
    StoreBackedRememberMeService.IssuedToken current = service.issue(ALICE, TTL);
    String previous = null;
    for (int i = 0; i < bound * 10; i++) {
      clock.advance(Duration.ofSeconds(10));
      previous = current.plainToken();
      current = service.rotate(previous).orElseThrow();
    }

    assertEquals(bound, store.trailCount(), "160 rotations, the trail holds the bound");
    clock.advance(StoreBackedRememberMeService.ROTATION_RACE_TOLERANCE.plusSeconds(1));
    assertTrue(service.rotate(previous).isEmpty());
    assertTrue(service.validate(current.plainToken()).isEmpty(),
        "the newest trail survived the bound, so the replay revoked the thief's successor");
  }

  @Test
  @DisplayName("JS-SEC-125: live tokens are bounded as well; at the bound the oldest goes")
  void liveTokensAreBounded() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore(3);
    StoreBackedRememberMeService service = service(store);
    StoreBackedRememberMeService.IssuedToken oldest = service.issue(SubjectId.of("u0"), TTL);
    for (int i = 1; i <= 3; i++) {
      clock.advance(Duration.ofSeconds(1));
      service.issue(SubjectId.of("u" + i), TTL);
    }
    assertTrue(service.validate(oldest.plainToken()).isEmpty());
    assertThrows(IllegalArgumentException.class, () -> new InMemoryRememberMeTokenStore(0));
  }
}
