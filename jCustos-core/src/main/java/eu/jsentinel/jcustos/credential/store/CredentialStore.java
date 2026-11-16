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
package eu.jsentinel.jcustos.credential.store;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Persistence-neutral credential store.
 *
 * <p>The store is the only place that knows how credentials are
 * persisted — file, RDBMS, key-value store. The security-core uses it
 * exclusively through this interface so the core never gains a
 * production database dependency.</p>
 *
 * <p>Updates are <em>compare-and-swap</em>: the caller supplies a
 * witness (the encoded hash or status it just read) and the store only
 * applies the change if the witness still matches the persisted value
 * (CWE-362 / CWE-367 / CWE-667). Blind overwrites are not supported —
 * callers must re-read, decide and retry.</p>
 *
 * <h2>Rotation proof (JS-SEC-161, CWE-284, CWE-620)</h2>
 * <p>{@link CredentialRecord} carries {@code secretChangedAt} and
 * {@code compromisedSince} since 00.84.00, and
 * {@code CredentialLifecycleService} refuses to return a credential to
 * {@link CredentialStatus#ACTIVE} while its stored secret is the one that was
 * declared compromised. That needs a store which persists both components,
 * writes a new secret through {@link #replaceSecretIfCurrent}, compares the
 * whole record in {@link #updateStatusIfUnchanged} and says so in
 * {@link #recordsSecretRotation()}. The three operations are default methods
 * so that an existing store still compiles; the defaults record nothing,
 * and the lifecycle service then keeps a compromised credential on the way
 * through a reset - see {@link #recordsSecretRotation()}. The testkit's
 * {@code CredentialStoreContract} checks a store against all of this.</p>
 */
public interface CredentialStore {

  /**
   * Looks up the credential row for {@code username}. Returns
   * {@link Optional#empty()} when the username is unknown.
   */
  Optional<CredentialRecord> findByUsername(String username);

  /**
   * Atomically replaces the stored hash if it still matches
   * {@code expectedEncodedHash}.
   *
   * @param username             credential identifier
   * @param expectedEncodedHash  witness; usually the {@code encodedHash}
   *                             that {@code findByUsername} just returned
   * @param newEncodedHash       new envelope to persist
   * @param when                 timestamp for {@code updatedAt}; the
   *                             store does not call {@link Instant#now}
   *                             itself so callers can inject a clock
   */
  CredentialUpdateResult updateHashIfCurrent(
      String username,
      String expectedEncodedHash,
      String newEncodedHash,
      Instant when);

  /**
   * Atomically replaces the stored status if it still matches
   * {@code expectedStatus}.
   */
  CredentialUpdateResult updateStatusIfCurrent(
      String username,
      CredentialStatus expectedStatus,
      CredentialStatus newStatus,
      Instant when);

  /**
   * Atomically replaces the stored hash with the hash of a <em>new</em>
   * secret if the stored hash still matches {@code expectedEncodedHash} - a
   * password change or a consumed reset, not a rehash (JS-SEC-161). In the
   * same step the record's {@link CredentialRecord#secretChangedAt()} becomes
   * {@code when} and its compromise marker is cleared, as
   * {@link CredentialRecord#withNewSecret} does.
   *
   * <p>The default calls {@link #updateHashIfCurrent}: the hash is replaced,
   * the change is not recorded, and a compromise marker the store keeps stays
   * set - the credential then cannot return to {@code ACTIVE} until the store
   * implements this method.</p>
   *
   * @param username            credential identifier
   * @param expectedEncodedHash witness; the {@code encodedHash} just read
   * @param newEncodedHash      envelope of the new secret
   * @param when                instant of the change
   * @return the outcome of the compare-and-swap
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  default CredentialUpdateResult replaceSecretIfCurrent(
      String username,
      String expectedEncodedHash,
      String newEncodedHash,
      Instant when) {
    return updateHashIfCurrent(username, expectedEncodedHash, newEncodedHash, when);
  }

  /**
   * Atomically replaces the stored status if the stored record is still
   * {@code witness} - compared as a whole, version included, not only by its
   * status (JS-SEC-161). A caller that judged the record before it asks for
   * the change - is a rotation still outstanding? - is sure that the record it
   * judged is the one it changes; a status that went away and came back in
   * between ({@code DISABLED -> COMPROMISED -> DISABLED}) refuses the update
   * as {@link CredentialUpdateResult.Stale}.
   *
   * <p>The default compares the status only, through
   * {@link #updateStatusIfCurrent}; with it, such an interleaving is not
   * noticed.</p>
   *
   * @param witness   the record the caller read and judged; non-null
   * @param newStatus status to write; non-null
   * @param when      timestamp for {@code updatedAt}; non-null
   * @return the outcome of the compare-and-swap
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  default CredentialUpdateResult updateStatusIfUnchanged(
      CredentialRecord witness,
      CredentialStatus newStatus,
      Instant when) {
    Objects.requireNonNull(witness, "witness");
    return updateStatusIfCurrent(witness.username(), witness.status(), newStatus, when);
  }

  /**
   * Whether this store keeps the rotation proof of JS-SEC-161: it persists
   * {@link CredentialRecord#secretChangedAt()} and
   * {@link CredentialRecord#compromisedSince()}, moves statuses through
   * {@link CredentialRecord#withStatus} (or equivalent code) and implements
   * {@link #replaceSecretIfCurrent} and {@link #updateStatusIfUnchanged}.
   *
   * <p>The default is {@code false}. For such a store the lifecycle service
   * cannot carry the knowledge that a credential was compromised past the
   * status {@code COMPROMISED}, and therefore refuses the transitions that
   * would keep the compromised secret in place - {@code COMPROMISED -> DISABLED}
   * and {@code COMPROMISED -> MUST_CHANGE}; the way out is the reset
   * ({@code COMPROMISED -> RESET_PENDING}), which writes a new secret.</p>
   *
   * @return {@code true} when the store keeps the rotation proof
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  default boolean recordsSecretRotation() {
    return false;
  }
}
