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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
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
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * "Remember me" / persistent-login service built on top of a
 * {@link RememberMeTokenStore} and a {@link PasswordHasher}.
 * <p>
 * The plain token is generated server-side at {@link #issue} time,
 * returned to the caller exactly once (intended to ship in an
 * {@code HttpOnly; Secure} cookie or equivalent), and immediately
 * dropped — only the hash reaches the store. {@link #validate}
 * hashes the candidate the same way and queries the store by hash;
 * an attacker who exfiltrates the store cannot impersonate the
 * subject without the cookie value.
 *
 * <h2>Rotation and theft detection (JS-SEC-128, CWE-613)</h2>
 * <p>{@link #rotate(String)} is the way to redeem a token: it validates the
 * token, retires it and returns a successor, so that a cookie value works
 * exactly once. A token that was already exchanged and is presented again
 * has been copied — by whoever holds the other copy. The service answers
 * with the pattern of JS-SEC-071: it refuses the token and revokes every
 * remember-me token of the subject, which signs out the thief and the owner
 * alike and makes the incident visible. A second presentation within
 * {@link #ROTATION_RACE_TOLERANCE} of the rotation is refused without that
 * consequence, because a browser sends parallel requests with the same
 * cookie. Replay detection needs a store that keeps the trail of rotated
 * tokens ({@link RememberMeTokenStore#findRotated}); with a store that does
 * not, rotation still works and a replayed token is simply unknown.</p>
 *
 * <p>The replay is audited: a {@link SessionInvalidated} event with the reason
 * {@value #REASON_TOKEN_REPLAY} and the subject whose remembered logins were
 * revoked, without a session id - the event stands for every remembered login
 * of the subject, not for one servlet session. It goes to the audit service
 * handed to the constructor, or to
 * {@link JCustosServiceResolver#securityAuditService()} when none was.</p>
 *
 * <p>{@link #validate(String)} stays for callers that only need to look at a
 * token; it does not rotate.</p>
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one service per tenant.
 *
 * <p>Token entropy: 256 bits from a {@link SecureRandom}, encoded
 * as URL-safe base64 (no padding). Override via the
 * {@code tokenSource} constructor argument if a different format
 * is required by the carrier (cookie, header, query parameter).
 */
@ExperimentalJCustosApi
public final class StoreBackedRememberMeService implements HasLogger {

  /** Default token entropy in bytes (256 bits). */
  public static final int DEFAULT_TOKEN_BYTES = 32;

  /**
   * How long after a rotation a second presentation of the consumed token is
   * treated as a concurrent request of the same client rather than as a replay
   * (JS-SEC-128). The token is refused either way; within this window the
   * subject's other tokens are left alone.
   *
   * @since 00.84.00
   */
  public static final Duration ROTATION_RACE_TOLERANCE = Duration.ofSeconds(5);

  /**
   * Reason key of the {@link SessionInvalidated} event that records a replayed
   * remember-me token and the revocation that followed (JS-SEC-128, CWE-294).
   *
   * @since 00.84.00
   */
  public static final String REASON_TOKEN_REPLAY = "RememberMeTokenReplay";

  private final RememberMeTokenStore store;
  private final TokenHasher hasher;
  private final TenantId tenant;
  private final Clock clock;
  private final Supplier<String> tokenSource;
  /** Audit sink for replays; {@code null} resolves the registered service per event. */
  private final JCustosAuditService auditService;

  /**
   * Convenience constructor: binds to {@link TenantId#DEFAULT},
   * uses a system {@link Clock} and the default 256-bit token source.
   *
   * @param store  backing token store; non-null
   * @param hasher deterministic {@link TokenHasher} (e.g. {@code Sha256TokenHasher})
   *               used to hash tokens before persisting them; non-null
   */
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      TokenHasher hasher) {
    this(store, hasher, TenantId.DEFAULT, Clock.systemUTC(), defaultTokenSource());
  }

  /**
   * Full constructor.
   *
   * @param store       backing token store; non-null
   * @param hasher      deterministic {@link TokenHasher} used to hash tokens
   *                    before persisting them; non-null
   * @param tenant      tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param clock       time source; non-null
   * @param tokenSource supplier producing the plain token strings issued to
   *                    clients; non-null and must return non-blank values
   */
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      TokenHasher hasher,
                                      TenantId tenant,
                                      Clock clock,
                                      Supplier<String> tokenSource) {
    this(store, hasher, tenant, clock, tokenSource, null);
  }

  /**
   * Full constructor with an explicit audit sink.
   *
   * @param store        backing token store; non-null
   * @param hasher       deterministic {@link TokenHasher} used to hash tokens
   *                     before persisting them; non-null
   * @param tenant       tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param clock        time source; non-null
   * @param tokenSource  supplier producing the plain token strings issued to
   *                     clients; non-null and must return non-blank values
   * @param auditService sink for the replay event (see the class comment), or
   *                     {@code null} to resolve
   *                     {@link JCustosServiceResolver#securityAuditService()}
   *                     per event
   * @since 00.84.00
   */
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      TokenHasher hasher,
                                      TenantId tenant,
                                      Clock clock,
                                      Supplier<String> tokenSource,
                                      JCustosAuditService auditService) {
    this.store = requireNonNull(store, "store must not be null");
    this.hasher = requireNonNull(hasher, "hasher must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.tokenSource = requireNonNull(tokenSource, "tokenSource must not be null");
    this.auditService = auditService;
  }

  /**
   * JS-SEC-057 (CWE-665): deprecated {@link PasswordHasher} overload. A remember-me token is looked
   * up by its hash, so the hasher MUST be deterministic; a salted KDF would make {@code validate}
   * recompute a different hash and silently fail every cookie. This routes through
   * {@link TokenHashers#fromPasswordHasher(PasswordHasher)}, which rejects a non-deterministic hasher
   * loudly at construction instead of a silent runtime outage — bringing this service to parity with
   * the four V00.75.10 token services (ApiKey / Token / PasswordReset / EmailVerification).
   *
   * @deprecated pass a {@link TokenHasher} (e.g. {@code Sha256TokenHasher}) instead.
   */
  @Deprecated(since = "00.79.41", forRemoval = true)
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      PasswordHasher hasher) {
    this(store, TokenHashers.fromPasswordHasher(hasher),
        TenantId.DEFAULT, Clock.systemUTC(), defaultTokenSource());
  }

  /**
   * JS-SEC-057 (CWE-665): deprecated {@link PasswordHasher} full-constructor overload — see
   * {@link #StoreBackedRememberMeService(RememberMeTokenStore, PasswordHasher)}.
   *
   * @deprecated pass a {@link TokenHasher} instead.
   */
  @Deprecated(since = "00.79.41", forRemoval = true)
  public StoreBackedRememberMeService(RememberMeTokenStore store,
                                      PasswordHasher hasher,
                                      TenantId tenant,
                                      Clock clock,
                                      Supplier<String> tokenSource) {
    this(store, TokenHashers.fromPasswordHasher(hasher), tenant, clock, tokenSource);
  }

  /**
   * Issues a new token for {@code subjectId} with the given TTL.
   * The plain token is returned exactly once — callers ship it to
   * the client (cookie / header) and discard it.
   *
   * @param subjectId subject the token authenticates; non-null
   * @param ttl       lifetime; must be strictly positive
   * @return issued token (plain value + record metadata)
   */
  public IssuedToken issue(SubjectId subjectId, Duration ttl) {
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(ttl, "ttl must not be null");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be strictly positive");
    }
    String plain = tokenSource.get();
    if (plain == null || plain.isBlank()) {
      throw new IllegalStateException("tokenSource produced a blank token");
    }
    Instant now = clock.instant();
    String hash = hasher.hash(plain.toCharArray());
    RememberMeTokenRecord record = new RememberMeTokenRecord(
        hash, tenant, subjectId, now, now.plus(ttl));
    store.save(record);
    return new IssuedToken(plain, record);
  }

  /**
   * Validates the supplied plain token. Returns the matching
   * record only when the hash is known, the record is in the
   * configured tenant, and the token has not expired. Expired
   * matches are removed from the store as a side effect.
   *
   * @param plainToken plain token from the carrier; null/blank
   *                   yields {@code Optional.empty()}
   * @return matching record, if valid
   */
  public Optional<RememberMeTokenRecord> validate(String plainToken) {
    if (plainToken == null || plainToken.isBlank()) {
      return Optional.empty();
    }
    String hash = hasher.hash(plainToken.toCharArray());
    return findLive(hash, clock.instant());
  }

  /**
   * Redeems the supplied plain token: validates it like {@link #validate},
   * retires it and issues a successor for the same subject (JS-SEC-128,
   * CWE-613). The caller replaces the client's cookie with
   * {@link IssuedToken#plainToken()} of the result.
   *
   * <p>The successor keeps the expiry of the token it replaces; rotation
   * does not extend the lifetime of a remembered login. Of two concurrent
   * calls with the same token exactly one receives a successor. A token that
   * was rotated earlier and is presented again is a replay — see the class
   * comment for what follows.</p>
   *
   * @param plainToken plain token from the carrier; null/blank yields empty
   * @return the successor, or empty when the token is unknown, expired,
   *     from another tenant, already rotated or lost a concurrent rotation
   * @since 00.84.00
   */
  public Optional<IssuedToken> rotate(String plainToken) {
    if (plainToken == null || plainToken.isBlank()) {
      return Optional.empty();
    }
    String hash = hasher.hash(plainToken.toCharArray());
    Instant now = clock.instant();
    Optional<RememberMeTokenRecord> live = findLive(hash, now);
    if (live.isEmpty()) {
      return Optional.empty();
    }
    RememberMeTokenRecord old = live.get();
    // Claim first, issue second (the order of JS-SEC-071): nothing is stored
    // for a caller that lost the claim.
    if (!store.markRotated(hash, now)) {
      // Another presentation of the same token won a moment ago.
      onRotatedTokenPresented(hash, now);
      return Optional.empty();
    }
    String plain = tokenSource.get();
    if (plain == null || plain.isBlank()) {
      throw new IllegalStateException("tokenSource produced a blank token");
    }
    RememberMeTokenRecord successor = new RememberMeTokenRecord(
        hasher.hash(plain.toCharArray()), tenant, old.subjectId(), now, old.expiresAt());
    store.save(successor);
    return Optional.of(new IssuedToken(plain, successor));
  }

  /**
   * @return the live record for {@code hash} in this tenant; expired matches
   *     are removed, and a hash that was consumed by a rotation is handled as
   *     a replay
   */
  private Optional<RememberMeTokenRecord> findLive(String hash, Instant now) {
    Optional<RememberMeTokenRecord> match = store.findByHash(hash);
    if (match.isEmpty()) {
      onRotatedTokenPresented(hash, now);
      return Optional.empty();
    }
    RememberMeTokenRecord record = match.get();
    if (!record.tenant().equals(tenant)) {
      return Optional.empty();
    }
    if (record.isExpired(now)) {
      store.deleteByHash(hash);
      return Optional.empty();
    }
    return Optional.of(record);
  }

  /**
   * JS-SEC-128 (CWE-613, CWE-294): a hash that is not live but was consumed by
   * a rotation means the token exists in two places. Outside the tolerance for
   * parallel requests every remember-me token of the subject is revoked — the
   * successor the other holder obtained included — and the incident is audited.
   */
  private void onRotatedTokenPresented(String hash, Instant now) {
    Optional<RememberMeTokenStore.RotatedToken> trail = store.findRotated(hash);
    if (trail.isEmpty()) {
      return;
    }
    RememberMeTokenRecord consumed = trail.get().record();
    if (!consumed.tenant().equals(tenant)) {
      return;
    }
    if (now.isBefore(trail.get().rotatedAt().plus(ROTATION_RACE_TOLERANCE))) {
      return;
    }
    int revoked = store.deleteBySubject(tenant, consumed.subjectId());
    logger().warn("authentication/remember-me-replay: a remember-me token that was "
        + "already rotated was presented again; revoked {} token(s) of subject '{}'",
        revoked, consumed.subjectId().value());
    publishReplay(now, consumed.subjectId());
  }

  /**
   * JS-SEC-128 (CWE-778): a replay is a security incident and belongs in the
   * audit trail, not only in the application log - the log line above is not
   * what a SIEM or the audit view reads. Published after the revocation, so
   * the event states what has already happened.
   */
  private void publishReplay(Instant at, SubjectId subjectId) {
    try {
      JCustosAuditService sink = auditService != null
          ? auditService
          : JCustosServiceResolver.securityAuditService();
      sink.publish(new SessionInvalidated(at, subjectId.value(), null, REASON_TOKEN_REPLAY));
    } catch (RuntimeException sinkFailure) {
      // The tokens are revoked; a failing sink must not turn the refusal into an error.
      logger().warn("authentication/remember-me-replay-not-audited: the audit sink "
          + "failed for the replay event: {}", sinkFailure.toString());
    }
  }

  /**
   * Revokes the supplied plain token. Idempotent — unknown tokens
   * return {@code false} rather than throwing.
   *
   * @param plainToken plain token; null/blank returns {@code false}
   * @return {@code true} when a record was removed
   */
  public boolean revoke(String plainToken) {
    if (plainToken == null || plainToken.isBlank()) {
      return false;
    }
    return store.deleteByHash(hasher.hash(plainToken.toCharArray()));
  }

  /**
   * Revokes every token issued to {@code subjectId} in this
   * service's tenant.
   *
   * @param subjectId subject; non-null
   * @return number of tokens removed
   */
  public int revokeAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    return store.deleteBySubject(tenant, subjectId);
  }

  /**
   * Purges every expired token in the backing store. Spans all
   * tenants — call once globally rather than per-tenant.
   *
   * @return number of tokens purged
   */
  public int purgeExpired() {
    return store.purgeExpired(clock.instant());
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
   * Tuple returned from {@link #issue}: the plain token (caller
   * passes it to the client carrier and drops it) and the
   * persisted record (handy for tests / audit hooks).
   *
   * @param plainToken plain token value
   * @param record     persisted record (hash + metadata)
   */
  public record IssuedToken(String plainToken, RememberMeTokenRecord record) {
    /** Validates the components. */
    public IssuedToken {
      if (plainToken == null || plainToken.isBlank()) {
        throw new IllegalArgumentException("plainToken must not be blank");
      }
      requireNonNull(record, "record must not be null");
    }

    /**
     * Masks the plain token; the compiler-generated {@code toString()} would
     * print a reusable secret into any log line that stringifies the tuple
     * (JS-SEC-127, CWE-532). The record carries the hash only and stays readable.
     *
     * @return a description without the plain token
     */
    @Override
    public String toString() {
      return "IssuedToken[plainToken=***, record=" + record + "]";
    }
  }
}
