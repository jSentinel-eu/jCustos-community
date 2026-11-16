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

import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.audit.TokenRotated;
import eu.jsentinel.jcustos.audit.CredentialVerificationFailed;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.token.TokenHasher;
import eu.jsentinel.jcustos.credential.token.TokenHashers;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * Access + rotating refresh token issuance on top of a
 * {@link RefreshTokenStore}.
 * <p>
 * Three operations:
 * <ol>
 *   <li>{@link #issue(SubjectId) issue(subject)} — issues a fresh
 *       {@link TokenPair} {@code (accessPlain, refreshPlain)}.
 *       Only the refresh token's hash reaches the store; the
 *       access token is returned to the caller verbatim and the
 *       framework does <strong>not</strong> persist it (apps that
 *       want stateless access tokens hand back a JWT, apps with
 *       a session-store cache it themselves).</li>
 *   <li>{@link #rotate(String) rotate(refreshPlain)} — claims the
 *       old refresh token and stores its successor in one store
 *       operation, {@link RefreshTokenStore#rotate rotate}, and then
 *       issues the fresh access + refresh pair, emitting
 *       {@link TokenRotated} (JS-SEC-071, CWE-367: two concurrent
 *       rotations of the same token yield exactly one pair;
 *       JS-SEC-129, CWE-367, CWE-613: a revocation cannot slip between
 *       the check, the claim and the storing of the successor).
 *       Returns empty on every failure mode
 *       (unknown, wrong tenant, revoked, replaced, expired) — the
 *       caller must <strong>not</strong> retry with a different
 *       reason. A token that was already consumed is a
 *       <em>replay</em> (CWE-294): the token family — every
 *       successor reachable through {@code replacedByHash} — is
 *       revoked and a {@link CredentialVerificationFailed} with
 *       {@link InternalAuditEventType#REFRESH_TOKEN_REPLAY} is
 *       emitted, so the legitimate holder is signed out and the
 *       incident is visible. Operators who prefer the broader
 *       response call {@link #revokeAll(SubjectId)}.</li>
 *   <li>{@link #revoke(String) revoke(refreshPlain)} — marks the
 *       refresh token revoked. When the token was already rotated,
 *       every successor reachable from it is revoked as well, so a
 *       logout that arrives just after a rotation still ends the
 *       chain (JS-SEC-129).</li>
 * </ol>
 *
 * <p>Replay defence: when {@link #rotate rotate} is called with a
 * refresh token that already has
 * {@link RefreshTokenRecord#replacedByHash() replacedByHash}, that
 * is a strong signal of replay — the token was already rotated.
 * The service refuses the request and revokes the chain of successors.
 *
 * <p>{@link #revokeAll(SubjectId)} leaves an "invalid before" mark in the
 * store. {@link #issue} and {@link #rotate} hand the store records stamped
 * with the instant they read at their start; a record older than the mark
 * is refused, so an operation that began before the revocation cannot
 * finish after it (JS-SEC-129, CWE-613). A record stamped with the instant
 * of the mark itself is kept: within one tick of the clock the order of the
 * two cannot be told, and a sign-in that follows a revocation must work. The guarantees hold with a store
 * that implements the atomic operations — both shipped stores do; see
 * {@link RefreshTokenStore} for the defaults a third-party store inherits.
 *
 * <p>Bound to one {@link TenantId} at construction.
 */
@ExperimentalJCustosApi
public final class TokenService {

  /** Default token entropy in bytes (256 bits). */
  public static final int DEFAULT_TOKEN_BYTES = 32;

  /**
   * Diagnostic code of the {@link IllegalStateException} that {@link #issue}
   * throws when a concurrent {@link #revokeAll} overtook it (JS-SEC-129).
   *
   * @since 00.84.00
   */
  public static final String SUPERSEDED_CODE = "authentication/refresh-token-superseded";

  private final RefreshTokenStore store;
  private final TokenHasher hasher;
  private final JCustosAuditService auditService;
  private final TenantId tenant;
  private final Clock clock;
  private final Supplier<String> tokenSource;
  private final Duration accessTtl;
  private final Duration refreshTtl;

  /**
   * Convenience constructor: tenant {@link TenantId#DEFAULT},
   * system clock, 256-bit token source, 15-min access TTL, 30-day
   * refresh TTL.
   *
   * @param store        backing store; non-null
   * @param hasher       deterministic token hasher; non-null
   * @param auditService audit sink; non-null
   */
  public TokenService(RefreshTokenStore store,
                      TokenHasher hasher,
                      JCustosAuditService auditService) {
    this(store, hasher, auditService, TenantId.DEFAULT, Clock.systemUTC(),
        defaultTokenSource(),
        Duration.ofMinutes(15), Duration.ofDays(30));
  }

  /**
   * Full constructor.
   *
   * @param store        backing store; non-null
   * @param hasher       deterministic token hasher used to hash refresh
   *                     tokens for lookup; non-null
   * @param auditService audit sink; non-null
   * @param tenant       tenant scope; {@code null} becomes
   *                     {@link TenantId#DEFAULT}
   * @param clock        time source; non-null
   * @param tokenSource  plain-token supplier; non-null
   * @param accessTtl    access-token lifetime; strictly positive
   * @param refreshTtl   refresh-token lifetime; strictly positive
   */
  public TokenService(RefreshTokenStore store,
                      TokenHasher hasher,
                      JCustosAuditService auditService,
                      TenantId tenant,
                      Clock clock,
                      Supplier<String> tokenSource,
                      Duration accessTtl,
                      Duration refreshTtl) {
    this.store = requireNonNull(store, "store must not be null");
    this.hasher = requireNonNull(hasher, "hasher must not be null");
    this.auditService = requireNonNull(auditService, "auditService must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.tokenSource = requireNonNull(tokenSource, "tokenSource must not be null");
    this.accessTtl = requirePositive(accessTtl, "accessTtl");
    this.refreshTtl = requirePositive(refreshTtl, "refreshTtl");
  }

  /**
   * @param store        backing store; non-null
   * @param hasher       <strong>deterministic</strong> password hasher; non-null
   * @param auditService audit sink; non-null
   * @deprecated since 00.75.10 — pass a {@link TokenHasher} (e.g.
   *     {@link eu.jsentinel.jcustos.credential.token.Sha256TokenHasher}).
   *     A {@link PasswordHasher} is accepted only when deterministic; a
   *     salted KDF is rejected at construction (CWE-208 / CWE-640).
   */
  @Deprecated(forRemoval = true)
  public TokenService(RefreshTokenStore store,
                      PasswordHasher hasher,
                      JCustosAuditService auditService) {
    this(store, TokenHashers.fromPasswordHasher(hasher), auditService);
  }

  /**
   * @param store        backing store; non-null
   * @param hasher       <strong>deterministic</strong> password hasher; non-null
   * @param auditService audit sink; non-null
   * @param tenant       tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param clock        time source; non-null
   * @param tokenSource  plain-token supplier; non-null
   * @param accessTtl    access-token lifetime; strictly positive
   * @param refreshTtl   refresh-token lifetime; strictly positive
   * @deprecated since 00.75.10 — pass a {@link TokenHasher}; a salted
   *     {@link PasswordHasher} is rejected at construction.
   */
  @Deprecated(forRemoval = true)
  public TokenService(RefreshTokenStore store,
                      PasswordHasher hasher,
                      JCustosAuditService auditService,
                      TenantId tenant,
                      Clock clock,
                      Supplier<String> tokenSource,
                      Duration accessTtl,
                      Duration refreshTtl) {
    this(store, TokenHashers.fromPasswordHasher(hasher), auditService, tenant, clock,
        tokenSource, accessTtl, refreshTtl);
  }

  /**
   * Issues a fresh access + refresh pair. The refresh token is
   * persisted (hash-only); the access token is returned verbatim
   * and not persisted.
   *
   * @param subjectId subject the new pair authenticates; non-null
   * @return issued pair
   * @throws IllegalStateException with the code
   *     {@value #SUPERSEDED_CODE} when {@link #revokeAll(SubjectId)} for the
   *     same subject completed after this call read its clock and before it
   *     stored the token (JS-SEC-129): the authentication that led here
   *     predates the revocation, so no pair is handed out. The caller treats
   *     it like a failed sign-in; the next attempt succeeds. "After" is
   *     judged by the clock: a revocation that read the same instant as this
   *     call does not refuse it - the store keeps a record created at the
   *     mark - so that a sign-in which follows a revocation within one clock
   *     tick is served. The window this leaves is one tick of the clock.
   */
  public TokenPair issue(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    Instant now = clock.instant();
    String accessPlain = nextToken();
    String refreshPlain = nextToken();
    RefreshTokenRecord record = newRecord(
        hasher.hash(refreshPlain.toCharArray()), subjectId, now);
    // JS-SEC-129 (CWE-613): the store refuses a record that is older than the
    // subject's "invalid before" mark — revokeAll overtook this call.
    if (!store.saveUnlessInvalidated(record)) {
      throw new IllegalStateException(SUPERSEDED_CODE
          + ": the subject's refresh tokens were revoked while this pair was being issued");
    }
    return pairOf(record, accessPlain, refreshPlain, now);
  }

  private RefreshTokenRecord newRecord(String refreshHash, SubjectId subjectId, Instant now) {
    return new RefreshTokenRecord(
        refreshHash, tenant, subjectId,
        now, now.plus(refreshTtl),
        Optional.empty(), Optional.empty());
  }

  private TokenPair pairOf(RefreshTokenRecord record, String accessPlain,
                           String refreshPlain, Instant now) {
    return new TokenPair(
        accessPlain, now.plus(accessTtl),
        refreshPlain, record.expiresAt(),
        record.subjectId());
  }

  /**
   * Rotates the supplied refresh token. The old token is claimed and its
   * successor stored by one store operation
   * ({@link RefreshTokenStore#rotate}), so of two concurrent rotations
   * exactly one receives a pair (JS-SEC-071, CWE-367), and a
   * {@link #revoke} or {@link #revokeAll} either precedes the rotation —
   * which is then refused — or follows it and removes the successor
   * (JS-SEC-129, CWE-367, CWE-613). Returns empty on every
   * failure (unknown, wrong tenant, revoked, replaced, expired).
   * <p>
   * Presenting a token that was already consumed — sequentially or by
   * losing the race — is treated as a replay (CWE-294): every successor
   * reachable from it is revoked and a {@link CredentialVerificationFailed}
   * with {@link InternalAuditEventType#REFRESH_TOKEN_REPLAY} is emitted.
   *
   * @param refreshPlain plain refresh token; null/blank yields empty
   * @return fresh pair on the successful transition
   */
  public Optional<TokenPair> rotate(String refreshPlain) {
    if (refreshPlain == null || refreshPlain.isBlank()) {
      return Optional.empty();
    }
    String oldHash = hasher.hash(refreshPlain.toCharArray());
    Optional<RefreshTokenRecord> match = store.findByHash(oldHash);
    if (match.isEmpty()) {
      return Optional.empty();
    }
    RefreshTokenRecord old = match.get();
    if (!old.tenant().equals(tenant)) {
      return Optional.empty();
    }
    Instant now = clock.instant();
    if (old.isReplaced()) {
      // JS-SEC-071 (CWE-294): a consumed token presented again is a replay.
      onReplay(old, now);
      return Optional.empty();
    }
    if (!old.isActive(now)) {
      return Optional.empty();
    }
    // JS-SEC-071 (CWE-367): claim the old token first. Nothing is persisted
    // until the claim succeeded, so a lost race leaves no orphan successor.
    // JS-SEC-129 (CWE-367, CWE-613): the check above ran on a record read
    // earlier. The store repeats it inside the claim — not replaced, not
    // revoked, not expired, successor not older than the subject's "invalid
    // before" mark — and stores the successor in the same critical section, so
    // neither a logout nor a revokeAll can land between check, claim and save.
    String refreshPlainNew = nextToken();
    String newHash = hasher.hash(refreshPlainNew.toCharArray());
    RefreshTokenRecord successor = newRecord(newHash, old.subjectId(), now);
    if (!store.rotate(oldHash, successor, now)) {
      // Look again to tell the cases apart. A concurrent rotation consumed the
      // token between findByHash and the claim: the second presentation of the
      // same token is a replay. A token that was revoked, expired or deleted in
      // the meantime is simply refused.
      Optional<RefreshTokenRecord> current = store.findByHash(oldHash);
      if (current.isPresent() && current.get().isReplaced()) {
        onReplay(current.get(), now);
      }
      return Optional.empty();
    }
    TokenPair pair = pairOf(successor, nextToken(), refreshPlainNew, now);
    publishRotated(now, old.subjectId().value(), oldHash, newHash);
    return Optional.of(pair);
  }

  /** Upper bound on the chain walk; protects against a corrupted, cyclic store. */
  private static final int MAX_FAMILY_HOPS = 10_000;
  /**
   * How often the walk re-reads a successor the winning rotation has claimed but
   * not yet persisted. Only a store that keeps the non-atomic default of
   * {@link RefreshTokenStore#rotate} can show a claim without its successor.
   */
  private static final int SUCCESSOR_LOOKUP_ATTEMPTS = 20;

  private void onReplay(RefreshTokenRecord replayed, Instant now) {
    revokeFamily(replayed, now);
    publishReplay(now, replayed.subjectId().value());
  }

  /**
   * Revokes every still-active successor reachable from {@code start} through
   * {@code replacedByHash}. With a store whose rotation is not atomic, a
   * successor that was claimed by a concurrent rotation a moment ago may not be
   * persisted yet; the lookup is retried a bounded number of times before the
   * walk gives up on that hop.
   *
   * <p>JS-SEC-129 (CWE-367): each record is read again <em>after</em> it was
   * revoked. A rotation that claimed it between the walk's read and the walk's
   * revoke has linked a further successor; the walk before 00.84.00 judged the
   * record by its first read, saw no successor and stopped one hop short of the
   * live token.</p>
   *
   * @return number of records revoked
   */
  private int revokeFamily(RefreshTokenRecord start, Instant now) {
    int revoked = 0;
    RefreshTokenRecord current = start;
    for (int hop = 0; hop < MAX_FAMILY_HOPS && current.replacedByHash().isPresent(); hop++) {
      Optional<RefreshTokenRecord> next = awaitSuccessor(current.replacedByHash().get());
      if (next.isEmpty()) {
        break;
      }
      RefreshTokenRecord successor = next.get();
      // The successor may have been persisted by a concurrent rotation whose clock
      // reading is later than ours; a revocation instant must not predate createdAt.
      Instant revokedAt = now.isBefore(successor.createdAt()) ? successor.createdAt() : now;
      if (successor.isActive(now) && store.markRevoked(successor.tokenHash(), revokedAt)) {
        revoked++;
      }
      // Re-read after the revoke: the link to a further successor may be newer
      // than the record this hop started from.
      current = store.findByHash(successor.tokenHash()).orElse(successor);
    }
    return revoked;
  }

  private Optional<RefreshTokenRecord> awaitSuccessor(String successorHash) {
    for (int attempt = 0; attempt < SUCCESSOR_LOOKUP_ATTEMPTS; attempt++) {
      Optional<RefreshTokenRecord> found = store.findByHash(successorHash);
      if (found.isPresent()) {
        return found;
      }
      LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
    }
    return Optional.empty();
  }

  private void publishReplay(Instant at, String subjectId) {
    try {
      auditService.publish(new CredentialVerificationFailed(
          at, subjectId, null, InternalAuditEventType.REFRESH_TOKEN_REPLAY));
    } catch (RuntimeException ignored) {
      // sinks must not block the refusal
    }
  }

  /**
   * Marks the refresh token revoked. No-op for unknown and already
   * revoked tokens.
   *
   * <p>When the token was rotated before the revocation reached the store,
   * the successors reachable from it are revoked too (JS-SEC-129, CWE-613):
   * a logout names the token the client held when it was sent, and a
   * rotation that completed a moment earlier must not leave the session's
   * newer token alive.</p>
   *
   * @param refreshPlain plain refresh token; null/blank → false
   * @return {@code true} when a not-yet-revoked record was just
   *         marked revoked
   */
  public boolean revoke(String refreshPlain) {
    if (refreshPlain == null || refreshPlain.isBlank()) {
      return false;
    }
    String hash = hasher.hash(refreshPlain.toCharArray());
    Instant now = clock.instant();
    boolean revoked = store.markRevoked(hash, now);
    // JS-SEC-129: read after the revoke, so a rotation that won the claim just
    // before is visible, and follow the chain it started.
    Optional<RefreshTokenRecord> current = store.findByHash(hash);
    if (current.isPresent() && current.get().isReplaced()
        && current.get().tenant().equals(tenant)) {
      revokeFamily(current.get(), now);
    }
    return revoked;
  }

  /**
   * Drops every refresh token issued to {@code subjectId} in this
   * service's tenant and marks the subject's tokens invalid before the
   * current instant (JS-SEC-129, CWE-613): an {@link #issue} or
   * {@link #rotate} that read its clock earlier cannot store a token for
   * the subject afterwards.
   *
   * @param subjectId subject; non-null
   * @return number of records removed
   */
  public int revokeAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    return store.deleteBySubject(tenant, subjectId, clock.instant());
  }

  /**
   * Purges every expired record. Spans all tenants.
   *
   * @return number of records purged
   */
  public int purgeExpired() {
    return store.purgeExpired(clock.instant());
  }

  private String nextToken() {
    String t = tokenSource.get();
    if (t == null || t.isBlank()) {
      throw new IllegalStateException("tokenSource produced a blank token");
    }
    return t;
  }

  private void publishRotated(Instant at, String subjectId,
                              String oldHash, String newHash) {
    try {
      auditService.publish(new TokenRotated(at, subjectId, oldHash, newHash));
    } catch (RuntimeException ignored) {
      // sinks must not block rotation
    }
  }

  private static Duration requirePositive(Duration d, String name) {
    requireNonNull(d, name + " must not be null");
    if (d.isZero() || d.isNegative()) {
      throw new IllegalArgumentException(name + " must be strictly positive");
    }
    return d;
  }

  private static Supplier<String> defaultTokenSource() {
    SecureRandom rng = new SecureRandom();
    return () -> {
      byte[] bytes = new byte[DEFAULT_TOKEN_BYTES];
      rng.nextBytes(bytes);
      return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    };
  }

  /**
   * Returned from {@link #issue issue} / {@link #rotate rotate}.
   * Apps deliver both plain tokens to the client (typically in a
   * JSON body) and discard them server-side.
   *
   * @param accessToken      plain access token
   * @param accessExpiresAt  access-token expiry
   * @param refreshToken     plain refresh token
   * @param refreshExpiresAt refresh-token expiry
   * @param subjectId        subject the pair authenticates
   */
  public record TokenPair(
      String accessToken,
      Instant accessExpiresAt,
      String refreshToken,
      Instant refreshExpiresAt,
      SubjectId subjectId
  ) {
    /** Validates the components. */
    public TokenPair {
      if (accessToken == null || accessToken.isBlank()) {
        throw new IllegalArgumentException("accessToken must not be blank");
      }
      requireNonNull(accessExpiresAt, "accessExpiresAt must not be null");
      if (refreshToken == null || refreshToken.isBlank()) {
        throw new IllegalArgumentException("refreshToken must not be blank");
      }
      requireNonNull(refreshExpiresAt, "refreshExpiresAt must not be null");
      requireNonNull(subjectId, "subjectId must not be null");
    }

    /**
     * Masks both plain tokens; the compiler-generated {@code toString()} would
     * print two reusable bearer credentials into any log line that stringifies
     * the pair (JS-SEC-127, CWE-532).
     *
     * @return a description without token values
     */
    @Override
    public String toString() {
      return "TokenPair[accessToken=***, accessExpiresAt=" + accessExpiresAt
          + ", refreshToken=***, refreshExpiresAt=" + refreshExpiresAt
          + ", subjectId=" + subjectId + "]";
    }
  }
}
