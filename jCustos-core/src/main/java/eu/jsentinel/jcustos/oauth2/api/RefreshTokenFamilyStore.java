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
package eu.jsentinel.jcustos.oauth2.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Objects;

/**
 * Tracks refresh-token families for rotation + reuse-detection (BCP 9700
 * §4.13.2, V00.77). On each successful refresh the rotator presents the old
 * token's hash and the new token's hash; if the presented hash is not the
 * family's current one (i.e. an already-rotated token is being replayed — a
 * sign of theft), the whole family is revoked.
 *
 * <p>Only token <em>hashes</em> are stored, never raw token values.
 *
 * <h2>Issued-hash history (00.84.10)</h2>
 *
 * <p>{@link #detectReuse} and {@link #consumeAndRotate} revoke on <em>any</em> hash
 * that is not the current one; they cannot tell a token the family really issued
 * and rotated away (reuse — a theft signal) from a secret nobody ever issued. Where
 * the family id is visible to others — an authorisation server whose refresh tokens
 * are {@code <family id>.<secret>} — anyone who learnt a family id could end the
 * family with a made-up secret. {@link #classify} closes that gap: a store that
 * remembers, per family, the last {@link #ISSUED_HASH_HISTORY} hashes it issued
 * (the current one included) tells the caller, without side effects, whether a
 * presented hash is {@link PresentedHash#CURRENT current},
 * {@link PresentedHash#PREVIOUSLY_ISSUED previously issued} or
 * {@link PresentedHash#UNKNOWN unknown}. A caller that must not let an unknown hash
 * revoke the family classifies first, refuses an unknown hash without calling
 * anything else, and leaves the current and previously issued hashes to
 * {@link #detectReuse} and {@link #consumeAndRotate} as before — those two keep
 * their semantics, so callers that do not classify (such as
 * {@code RefreshTokenRotator}) behave exactly as in earlier releases.
 *
 * <p>The history belongs in the store, not beside it, so that it survives a
 * restart together with the current hash: a store backed by durable storage keeps
 * it there. {@link #classify} is a {@code default} method that answers
 * {@link PresentedHash#UNDETERMINED}, which keeps every implementation written
 * before 00.84.10 correct — a caller then falls back to the revoke-on-anything
 * behaviour. <strong>A store should override it</strong>; the
 * {@code RefreshTokenFamilyStoreContract} of {@code jCustos-persistence-testkit}
 * proves the override, including across a restart.
 *
 * @since 00.77.00
 */
public interface RefreshTokenFamilyStore {

  /**
   * How many hashes per family a store that overrides {@link #classify} remembers
   * at least, the current one included: 16. An earlier token older than that is
   * {@link PresentedHash#UNKNOWN} — refused without revoking anything. Sixteen
   * rotations cover the retry of a lost refresh response many times over; a store
   * may keep more.
   *
   * @since 00.84.10
   */
  @ExperimentalJCustosApi
  int ISSUED_HASH_HISTORY = 16;

  /** Records a freshly-issued family with its first refresh-token hash. */
  void recordIssued(String familyId, String tokenHash);

  /**
   * Atomically rotates the family: if {@code presentedHash} is the current hash,
   * replaces it with {@code newHash} and returns {@link RotationResult#ROTATED};
   * otherwise revokes the family and returns {@link RotationResult#REUSE_DETECTED}.
   *
   * @param familyId      the token-family identifier
   * @param presentedHash the hash of the refresh token presented by the client
   * @param newHash       the hash of the newly-issued refresh token
   * @return the rotation outcome
   */
  RotationResult consumeAndRotate(String familyId, String presentedHash, String newHash);

  /**
   * Reuse pre-check (V00.77, R-EXIT-1): determines whether {@code presentedHash}
   * is the family's current token <em>before</em> the refresh is forwarded to the
   * authorization server. If it is not current (an already-rotated or unknown
   * token was replayed — a theft signal), the family is revoked and
   * {@link RotationResult#REUSE_DETECTED} is returned. This closes the gap where
   * a replayed token that the AS itself rejects would otherwise never trigger the
   * RP-side family revoke. Returns {@link RotationResult#ROTATED} (meaning
   * "current — safe to forward") without rotating; the actual rotation still goes
   * through {@link #consumeAndRotate} on success.
   *
   * @param familyId      the token-family identifier
   * @param presentedHash the hash of the refresh token presented by the client
   * @return {@link RotationResult#ROTATED} if current, else {@link RotationResult#REUSE_DETECTED}
   */
  RotationResult detectReuse(String familyId, String presentedHash);

  /** Revokes a whole family (e.g. on logout, or after reuse-detection). */
  void revokeFamily(String familyId);

  /**
   * Classifies {@code presentedHash} against the family's issued-hash history
   * <em>without any side effect</em>: nothing rotates, nothing is revoked, nothing
   * is recorded. See the type documentation for how a caller combines it with
   * {@link #detectReuse} and {@link #consumeAndRotate}.
   *
   * <p>A store that overrides this method answers:
   * <ul>
   *   <li>{@link PresentedHash#CURRENT} for the family's current hash;</li>
   *   <li>{@link PresentedHash#PREVIOUSLY_ISSUED} for a hash it recorded for the family
   *       ({@link #recordIssued}) or rotated to ({@link #consumeAndRotate}) and has since
   *       rotated away, as long as it is among the last {@link #ISSUED_HASH_HISTORY};</li>
   *   <li>{@link PresentedHash#UNKNOWN} for anything else: a hash never issued for the
   *       family, one older than the history, any hash of a family it does not know.
   *       A revoked family has no current hash; its hashes are {@code UNKNOWN} or, if
   *       the store keeps the history beyond the revocation, {@code PREVIOUSLY_ISSUED}
   *       — never {@code CURRENT}.</li>
   * </ul>
   *
   * <p>The default keeps no history and answers {@link PresentedHash#UNDETERMINED}
   * for every hash, which keeps implementations written before 00.84.10 correct.
   *
   * @param familyId      the token-family identifier
   * @param presentedHash the hash of the refresh token presented by the client
   * @return the classification, never {@code null}
   * @throws NullPointerException if an argument is {@code null}
   * @since 00.84.10
   */
  @ExperimentalJCustosApi
  default PresentedHash classify(String familyId, String presentedHash) {
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(presentedHash, "presentedHash");
    return PresentedHash.UNDETERMINED;
  }

  /** The outcome of {@link #consumeAndRotate}. */
  enum RotationResult {
    /** The presented token was current; the family rotated to the new token. */
    ROTATED,
    /** An already-rotated (or unknown) token was replayed; the family was revoked. */
    REUSE_DETECTED
  }

  /**
   * The outcome of {@link #classify}.
   *
   * @since 00.84.10
   */
  @ExperimentalJCustosApi
  enum PresentedHash {
    /** The family's current hash: a refresh may go ahead. */
    CURRENT,
    /** A hash the store issued for the family and has rotated away: reuse, revoke the family. */
    PREVIOUSLY_ISSUED,
    /** A hash the store never issued for the family (as far as its history reaches): refuse, revoke nothing. */
    UNKNOWN,
    /**
     * The store keeps no history (the {@code default} of {@link #classify}); the caller
     * falls back to {@link #detectReuse}, which revokes on anything that is not current.
     */
    UNDETERMINED
  }
}
