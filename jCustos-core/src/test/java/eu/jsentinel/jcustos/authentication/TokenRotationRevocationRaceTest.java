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

import eu.jsentinel.jcustos.audit.CredentialVerificationFailed;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.CredentialTestKit.MutableClock;
import eu.jsentinel.jcustos.credential.CredentialTestKit.RecordingAudit;
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
 * JS-SEC-129 (CWE-367, CWE-613): a revocation that lands between the check,
 * the claim and the storing of the successor of a refresh-token rotation must
 * not be lost.
 *
 * <p>The interleavings are forced, not hoped for: the real in-memory store
 * sits behind a wrapper that runs a hook at one chosen point of the store
 * protocol. The hook is the concurrent request.</p>
 */
@DisplayName("JS-SEC-129 — revocation during a refresh-token rotation is not lost")
class TokenRotationRevocationRaceTest {

  private static final SubjectId ALICE = SubjectId.of("alice");
  private static final SubjectId BOB = SubjectId.of("bob");
  private static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");

  private final MutableClock clock = new MutableClock(T0);
  private final RecordingAudit audit = new RecordingAudit();
  private final AtomicLong counter = new AtomicLong();

  private TokenService service(RefreshTokenStore store) {
    return new TokenService(store, new Sha256TokenHasher(), audit, TenantId.DEFAULT, clock,
        () -> "plainvalue-" + counter.incrementAndGet(),
        Duration.ofMinutes(15), Duration.ofDays(30));
  }

  /**
   * The real store with hooks. {@code beforeClaim} runs after the service
   * checked the token and before the store judges it; {@code afterClaim} runs
   * at the earliest moment after the claim at which the store lets another
   * request in — for a non-atomic rotation that is before the successor is
   * saved, for the atomic rotation it is after both were written.
   */
  private static final class InterleavingStore implements RefreshTokenStore {
    final InMemoryRefreshTokenStore real = new InMemoryRefreshTokenStore();
    final AtomicReference<Runnable> beforeClaim = new AtomicReference<>();
    final AtomicReference<Runnable> afterClaim = new AtomicReference<>();
    final AtomicReference<Runnable> beforeSave = new AtomicReference<>();
    final AtomicReference<Runnable> beforeRevoke = new AtomicReference<>();

    private static void run(AtomicReference<Runnable> hook) {
      Runnable action = hook.getAndSet(null);
      if (action != null) {
        action.run();
      }
    }

    @Override
    public Optional<RefreshTokenRecord> findByHash(String tokenHash) {
      return real.findByHash(tokenHash);
    }

    @Override
    public void save(RefreshTokenRecord record) {
      run(afterClaim);
      real.save(record);
    }

    @Override
    public boolean saveUnlessInvalidated(RefreshTokenRecord record) {
      run(beforeSave);
      return real.saveUnlessInvalidated(record);
    }

    @Override
    public boolean markReplaced(String oldHash, String newHash, Instant at) {
      run(beforeClaim);
      return real.markReplaced(oldHash, newHash, at);
    }

    @Override
    public boolean rotate(String oldHash, RefreshTokenRecord successor, Instant now) {
      run(beforeClaim);
      boolean rotated = real.rotate(oldHash, successor, now);
      run(afterClaim);
      return rotated;
    }

    @Override
    public boolean markRevoked(String tokenHash, Instant at) {
      run(beforeRevoke);
      return real.markRevoked(tokenHash, at);
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

  /**
   * A store as a third party would have written it before 00.84.00: the
   * original operations only, the new ones inherited as defaults.
   */
  private static final class LegacyStore implements RefreshTokenStore {
    final InMemoryRefreshTokenStore real = new InMemoryRefreshTokenStore();
    final AtomicReference<Runnable> beforeClaim = new AtomicReference<>();

    @Override
    public Optional<RefreshTokenRecord> findByHash(String tokenHash) {
      return real.findByHash(tokenHash);
    }

    @Override
    public void save(RefreshTokenRecord record) {
      real.save(record);
    }

    @Override
    public boolean markReplaced(String oldHash, String newHash, Instant at) {
      Runnable hook = beforeClaim.getAndSet(null);
      if (hook != null) {
        hook.run();
      }
      return real.markReplaced(oldHash, newHash, at);
    }

    @Override
    public boolean markRevoked(String tokenHash, Instant at) {
      return real.markRevoked(tokenHash, at);
    }

    @Override
    public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
      return real.deleteBySubject(tenant, subjectId);
    }

    @Override
    public int purgeExpired(Instant now) {
      return real.purgeExpired(now);
    }
  }

  @Test
  @DisplayName("(a) a logout between the service's check and the claim refuses the rotation")
  void revokeBeforeClaim() {
    InterleavingStore store = new InterleavingStore();
    TokenService service = service(store);
    TokenService.TokenPair stolen = service.issue(ALICE);
    int records = recordCount(store, stolen);

    store.beforeClaim.set(() -> assertTrue(service.revoke(stolen.refreshToken())));
    Optional<TokenService.TokenPair> rotated = service.rotate(stolen.refreshToken());

    assertTrue(rotated.isEmpty(), "the token was revoked before the claim");
    assertEquals(records, recordCount(store, stolen), "a refused rotation stores no successor");
    assertTrue(audit.events.stream().noneMatch(CredentialVerificationFailed.class::isInstance),
        "a revoked token is refused; it is not a replay");
  }

  @Test
  @DisplayName("(b) revokeAll at the earliest point after the claim leaves no rotatable token of the subject")
  void revokeAllAfterClaim() {
    InterleavingStore store = new InterleavingStore();
    TokenService service = service(store);
    TokenService.TokenPair first = service.issue(BOB);
    TokenService.TokenPair alices = service.issue(ALICE);

    store.afterClaim.set(() -> service.revokeAll(BOB));
    Optional<TokenService.TokenPair> survivor = service.rotate(first.refreshToken());

    assertTrue(survivor.flatMap(pair -> service.rotate(pair.refreshToken())).isEmpty(),
        "the successor must not outlive the revokeAll that followed its claim");
    assertTrue(service.rotate(first.refreshToken()).isEmpty());
    assertTrue(service.rotate(alices.refreshToken()).isPresent(), "another subject is untouched");
  }

  @Test
  @DisplayName("(b) revokeAll before the claim refuses the rotation")
  void revokeAllBeforeClaim() {
    InterleavingStore store = new InterleavingStore();
    TokenService service = service(store);
    TokenService.TokenPair first = service.issue(BOB);

    store.beforeClaim.set(() -> service.revokeAll(BOB));

    assertTrue(service.rotate(first.refreshToken()).isEmpty());
  }

  @Test
  @DisplayName("a logout with a token that was rotated a moment earlier also ends the successor")
  void revokeAfterRotationReachesTheSuccessor() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    TokenService service = service(store);
    TokenService.TokenPair first = service.issue(ALICE);
    TokenService.TokenPair second = service.rotate(first.refreshToken()).orElseThrow();
    TokenService.TokenPair third = service.rotate(second.refreshToken()).orElseThrow();

    service.revoke(first.refreshToken());

    assertTrue(service.rotate(third.refreshToken()).isEmpty(),
        "the logout names the chain, not only the record the client happened to hold");
  }

  @Test
  @DisplayName("(c) the family walk reads a record again after revoking it and follows a link set in between")
  void familyWalkRereadsAfterRevoke() {
    InterleavingStore store = new InterleavingStore();
    TokenService service = service(store);
    TokenService.TokenPair first = service.issue(ALICE);
    TokenService.TokenPair second = service.rotate(first.refreshToken()).orElseThrow();

    // The replay of `first` starts the walk at `second`. Between the walk's read
    // of `second` and its revoke, the holder of `second` rotates it.
    AtomicReference<TokenService.TokenPair> third = new AtomicReference<>();
    store.beforeRevoke.set(() ->
        third.set(service.rotate(second.refreshToken()).orElseThrow()));
    assertTrue(service.rotate(first.refreshToken()).isEmpty());

    assertTrue(service.rotate(third.get().refreshToken()).isEmpty(),
        "the token minted during the walk belongs to the revoked family");
  }

  @Test
  @DisplayName("issue refuses to hand out a pair when revokeAll overtook it")
  void issueOvertakenByRevokeAll() {
    InterleavingStore store = new InterleavingStore();
    TokenService service = service(store);

    // issue read the clock at T0; the revocation happens later and completes first.
    store.beforeSave.set(() -> {
      clock.advance(Duration.ofMillis(1));
      service.revokeAll(ALICE);
    });
    IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> service.issue(ALICE));
    assertTrue(refused.getMessage().startsWith(TokenService.SUPERSEDED_CODE));
    assertFalse(refused.getMessage().contains("plainvalue-"), "no token value in the message");

    // A sign-in after the revocation is served.
    TokenService.TokenPair fresh = service.issue(ALICE);
    assertTrue(service.rotate(fresh.refreshToken()).isPresent());
  }

  @Test
  @DisplayName("revokeAll and a sign-in at the same instant: the sign-in counts as later")
  void issueAtTheInstantOfRevokeAll() {
    TokenService service = service(new InMemoryRefreshTokenStore());
    service.issue(ALICE);

    service.revokeAll(ALICE);
    TokenService.TokenPair again = service.issue(ALICE);

    assertTrue(service.rotate(again.refreshToken()).isPresent());
  }

  @Test
  @DisplayName("a store that keeps the default rotate still refuses a token revoked before the claim")
  void legacyStoreHonoursRevokeBeforeClaim() {
    LegacyStore store = new LegacyStore();
    TokenService service = service(store);
    TokenService.TokenPair stolen = service.issue(ALICE);

    store.beforeClaim.set(() -> service.revoke(stolen.refreshToken()));

    assertTrue(service.rotate(stolen.refreshToken()).isEmpty());
  }

  @Test
  @DisplayName("a store that keeps the defaults rotates, replays and revokes as before")
  void legacyStoreKeepsWorking() {
    LegacyStore store = new LegacyStore();
    TokenService service = service(store);
    TokenService.TokenPair first = service.issue(ALICE);

    TokenService.TokenPair second = service.rotate(first.refreshToken()).orElseThrow();
    assertTrue(service.rotate(first.refreshToken()).isEmpty(), "replay");
    assertTrue(service.rotate(second.refreshToken()).isEmpty(), "the family was revoked");

    TokenService.TokenPair again = service.issue(ALICE);
    assertEquals(3, service.revokeAll(ALICE));
    assertTrue(service.rotate(again.refreshToken()).isEmpty());
  }

  /** Number of records reachable for the subject of {@code pair} — one, unless a successor was stored. */
  private static int recordCount(InterleavingStore store, TokenService.TokenPair pair) {
    String hash = new Sha256TokenHasher().hash(pair.refreshToken().toCharArray());
    int count = 0;
    Optional<RefreshTokenRecord> current = store.real.findByHash(hash);
    while (current.isPresent()) {
      count++;
      current = current.get().replacedByHash().flatMap(store.real::findByHash);
    }
    return count;
  }
}
