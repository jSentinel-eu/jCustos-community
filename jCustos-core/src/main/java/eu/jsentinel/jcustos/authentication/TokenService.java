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
 *       old refresh token atomically through
 *       {@link RefreshTokenStore#markReplaced markReplaced} and only
 *       then persists the successor and issues the fresh access +
 *       refresh pair, emitting {@link TokenRotated} (JS-SEC-071,
 *       CWE-367: two concurrent rotations of the same token yield
 *       exactly one pair). Returns empty on every failure mode
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
 *   <li>{@link #revoke(String) revoke(refreshPlain)} — marks a
 *       still-active refresh token revoked. No-op when already
 *       revoked / replaced / unknown.</li>
 * </ol>
 *
 * <p>Replay defense: when {@link #rotate rotate} is called with a
 * refresh token that already has
 * {@link RefreshTokenRecord#replacedByHash() replacedByHash}, that
 * is a strong signal of replay — the token was already rotated.
 * This service does not by itself chase the full chain (the
 * {@code RefreshTokenStore} contract leaves chain-revocation to the
 * application) but it does refuse the request and emits an audit
 * trail through the store's existing state.
 *
 * <p>Bound to one {@link TenantId} at construction.
 */
@ExperimentalJCustosApi
public final class TokenService {

  /** Default token entropy in bytes (256 bits). */
  public static final int DEFAULT_TOKEN_BYTES = 32;

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
   */
  public TokenPair issue(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    Instant now = clock.instant();
    String accessPlain = nextToken();
    String refreshPlain = nextToken();
    return persistPair(subjectId, accessPlain, refreshPlain,
        hasher.hash(refreshPlain.toCharArray()), now);
  }

  private TokenPair persistPair(SubjectId subjectId, String accessPlain,
                                String refreshPlain, String refreshHash, Instant now) {
    RefreshTokenRecord record = new RefreshTokenRecord(
        refreshHash, tenant, subjectId,
        now, now.plus(refreshTtl),
        Optional.empty(), Optional.empty());
    store.save(record);
    return new TokenPair(
        accessPlain, now.plus(accessTtl),
        refreshPlain, record.expiresAt(),
        subjectId);
  }

  /**
   * Rotates the supplied refresh token. The old token is claimed
   * atomically ({@link RefreshTokenStore#markReplaced}) <em>before</em>
   * the successor is persisted, so of two concurrent rotations exactly
   * one receives a pair (JS-SEC-071, CWE-367). Returns empty on every
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
    String refreshPlainNew = nextToken();
    String newHash = hasher.hash(refreshPlainNew.toCharArray());
    if (!store.markReplaced(oldHash, newHash, now)) {
      // A concurrent rotation consumed the token between findByHash and the
      // claim: the second presentation of the same token is a replay.
      onReplay(store.findByHash(oldHash).orElse(old), now);
      return Optional.empty();
    }
    TokenPair pair = persistPair(old.subjectId(), nextToken(), refreshPlainNew, newHash, now);
    publishRotated(now, old.subjectId().value(), oldHash, newHash);
    return Optional.of(pair);
  }

  /** Upper bound on the chain walk; protects against a corrupted, cyclic store. */
  private static final int MAX_FAMILY_HOPS = 10_000;
  /** How often the walk re-reads a successor the winning rotation has claimed but not yet persisted. */
  private static final int SUCCESSOR_LOOKUP_ATTEMPTS = 20;

  private void onReplay(RefreshTokenRecord replayed, Instant now) {
    revokeFamily(replayed, now);
    publishReplay(now, replayed.subjectId().value());
  }

  /**
   * Revokes every still-active successor reachable from {@code start} through
   * {@code replacedByHash}. A successor that was claimed by a concurrent
   * rotation a moment ago may not be persisted yet; the lookup is retried a
   * bounded number of times before the walk gives up on that hop.
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
      current = next.get();
      // The successor may have been persisted by a concurrent rotation whose clock
      // reading is later than ours; a revocation instant must not predate createdAt.
      Instant revokedAt = now.isBefore(current.createdAt()) ? current.createdAt() : now;
      if (current.isActive(now) && store.markRevoked(current.tokenHash(), revokedAt)) {
        revoked++;
      }
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
   * Marks the refresh token revoked. No-op for unknown / already
   * revoked / replaced / expired tokens.
   *
   * @param refreshPlain plain refresh token; null/blank → false
   * @return {@code true} when a still-active record was just
   *         marked revoked
   */
  public boolean revoke(String refreshPlain) {
    if (refreshPlain == null || refreshPlain.isBlank()) {
      return false;
    }
    String hash = hasher.hash(refreshPlain.toCharArray());
    return store.markRevoked(hash, clock.instant());
  }

  /**
   * Drops every refresh token issued to {@code subjectId} in this
   * service's tenant.
   *
   * @param subjectId subject; non-null
   * @return number of records removed
   */
  public int revokeAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    return store.deleteBySubject(tenant, subjectId);
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
  }
}
