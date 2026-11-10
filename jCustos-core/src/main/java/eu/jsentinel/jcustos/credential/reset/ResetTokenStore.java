/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.credential.store.CredentialStatus;

import java.util.List;
import java.util.Optional;

/**
 * Persistence-neutral storage of password-reset tokens.
 *
 * <p>The store never logs verifier values or digests (CWE-209). It
 * supports CAS transitions on the {@link ResetTokenStatus} field so
 * tokens are guaranteed to be single-use even under concurrent
 * consume attempts (CWE-362, CWE-640).</p>
 */
public interface ResetTokenStore {

  /**
   * Inserts a freshly issued token. Implementations may throw when a
   * record with the same selector already exists; in practice the
   * selector entropy makes that impossible to hit by accident.
   */
  void save(ResetTokenRecord record);

  /**
   * Looks up a token by selector. Verifier digests are never compared
   * here; that is the reset service's job.
   */
  Optional<ResetTokenRecord> findBySelector(String selector);

  /**
   * Lists every token issued for {@code username}, regardless of status.
   * The reset service uses it to retire open siblings when a new token is
   * issued and when one is consumed (JS-SEC-074, CWE-640): an intercepted
   * older link must not reset the password a second time.
   *
   * @param username the credential's username; non-blank
   * @return the records in no particular order, empty when none exist
   * @since 00.84.00
   */
  List<ResetTokenRecord> findByUsername(String username);

  /**
   * Atomically marks the token CONSUMED if its current status still
   * matches {@code expectedStatus}.
   */
  ResetTokenUpdateResult markConsumedIfCurrent(
      String selector, ResetTokenStatus expectedStatus);

  /**
   * Atomically marks the token EXPIRED if its current status still
   * matches {@code expectedStatus}. Called lazily when verification
   * notices the expiry, so audit timelines stay accurate.
   */
  ResetTokenUpdateResult markExpiredIfCurrent(
      String selector, ResetTokenStatus expectedStatus);

  /**
   * Marks every still-{@link ResetTokenStatus#ISSUED} token of
   * {@code username} {@link ResetTokenStatus#EXPIRED}. Used when the
   * credential changed by another route — a password change with the
   * current password — so that a link issued earlier cannot replace the
   * new password afterwards (JS-SEC-128, CWE-613, CWE-640).
   *
   * <p>The default walks {@link #findByUsername(String)} and retires each
   * record through {@link #markExpiredIfCurrent}; a token that a
   * concurrent consume claims first is left alone. Stores may override it
   * with a single bulk statement.</p>
   *
   * @param username the credential's username; non-blank
   * @return number of tokens retired
   * @since 00.84.00
   */
  default int retireOpenTokens(String username) {
    int retired = 0;
    for (ResetTokenRecord record : findByUsername(username)) {
      if (record.status() != ResetTokenStatus.ISSUED) {
        continue;
      }
      if (markExpiredIfCurrent(record.selector(), ResetTokenStatus.ISSUED)
          instanceof ResetTokenUpdateResult.Updated) {
        retired++;
      }
    }
    return retired;
  }

  /**
   * Remembers the status a credential had before a reset moved it to
   * {@link CredentialStatus#RESET_PENDING}, so that the reset service can
   * return it to that status when the last open token lapses unused
   * (JS-SEC-121, CWE-645). The reset service only records this for the
   * path out of {@link CredentialStatus#COMPROMISED}; a usable credential
   * keeps its status while a reset is open.
   *
   * <p>The default does nothing. A store that keeps the default never
   * reports an origin, and the reset service then leaves such a credential
   * in {@code RESET_PENDING} until a new link is consumed — the behaviour
   * before 00.84.00. Persistent stores should keep the value next to the
   * tokens so that it survives a restart.</p>
   *
   * @param username the credential's username; non-blank
   * @param status   the status to return to; non-null
   * @since 00.84.00
   */
  default void rememberStatusBeforeReset(String username, CredentialStatus status) {
    // optional capability — see the method comment
  }

  /**
   * @param username the credential's username; non-blank
   * @return the status recorded by {@link #rememberStatusBeforeReset}, or
   *     empty when none is recorded or the store does not keep it
   * @since 00.84.00
   */
  default Optional<CredentialStatus> statusBeforeReset(String username) {
    return Optional.empty();
  }

  /**
   * Drops the status recorded by {@link #rememberStatusBeforeReset} — the
   * reset was consumed, or the credential was returned to that status.
   *
   * @param username the credential's username; non-blank
   * @since 00.84.00
   */
  default void forgetStatusBeforeReset(String username) {
    // optional capability — see rememberStatusBeforeReset
  }
}
