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
package eu.jsentinel.jcustos.credential.change;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidationResult;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleDecision;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenStore;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Atomic, policy-driven password change.
 *
 * <h2>Flow</h2>
 * <ol>
 *   <li>Load the credential by username; missing → {@code NotFound}.</li>
 *   <li>Consult the lifecycle service; status that forbids change
 *       (LOCKED / COMPROMISED / DISABLED) → {@code Blocked}.</li>
 *   <li>Re-authenticate by verifying the supplied current password
 *       (CWE-620). Anything but {@code Verified} →
 *       {@code CurrentPasswordRejected}.</li>
 *   <li>Validate the proposed new password through the input policy.
 *       A rejection here surfaces the structural reason.</li>
 *   <li>Hash the new password through {@link PasswordHashingService}.</li>
 *   <li>Compare-and-swap the encoded hash with the original envelope as
 *       witness. Stale → {@code Conflict} (CWE-362).</li>
 *   <li>If the credential was {@code MUST_CHANGE}, clear it to
 *       {@code ACTIVE} through the lifecycle service. Failure to clear
 *       does <em>not</em> roll back the hash update — the password is
 *       already new; the next login will trigger the same clear.</li>
 *   <li>Retire every open reset link of the account when a
 *       {@link ResetTokenStore} is configured, and notify the
 *       {@link CredentialChangeListener} when one is configured
 *       (JS-SEC-128, CWE-613, CWE-640).</li>
 *   <li>Return {@code Succeeded(INVALIDATE_OTHER_SESSIONS)}.</li>
 * </ol>
 *
 * <h2>Optional collaborators</h2>
 * <p>{@link #withResetTokenStore(ResetTokenStore)} and
 * {@link #withCredentialChangeListener(CredentialChangeListener)} return a
 * copy of the service with the collaborator set. Without them the service
 * behaves as before 00.84.00: a reset link issued earlier stays valid after
 * the change, and no session or token is revoked — the returned
 * {@link SessionHandlingDecision} is then only a recommendation to the
 * adapter.</p>
 */
public final class PasswordChangeService implements HasLogger {

  private final CredentialStore store;
  private final PasswordHashingService hashingService;
  private final PasswordInputValidator inputValidator;
  private final PasswordInputPolicy inputPolicy;
  private final CredentialLifecycleService lifecycleService;
  private final Clock clock;
  /** Optional (JS-SEC-128): open reset links are retired after a change when present. */
  private final ResetTokenStore resetTokenStore;
  /** Optional (JS-SEC-128): notified after a change; never {@code null}. */
  private final CredentialChangeListener changeListener;

  public PasswordChangeService(
      CredentialStore store,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock) {
    this(store, hashingService, inputValidator, inputPolicy, lifecycleService, clock,
        null, CredentialChangeListener.noop());
  }

  private PasswordChangeService(
      CredentialStore store,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock,
      ResetTokenStore resetTokenStore,
      CredentialChangeListener changeListener) {
    this.store = Objects.requireNonNull(store, "store");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    this.inputValidator = Objects.requireNonNull(inputValidator, "inputValidator");
    this.inputPolicy = Objects.requireNonNull(inputPolicy, "inputPolicy");
    this.lifecycleService = Objects.requireNonNull(lifecycleService, "lifecycleService");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.resetTokenStore = resetTokenStore;
    this.changeListener = Objects.requireNonNull(changeListener, "changeListener");
  }

  /**
   * Returns a copy of this service that retires every open reset link of the
   * account after a successful change (JS-SEC-128, CWE-640): a link that was
   * issued — or intercepted — before the change must not replace the new
   * password afterwards.
   *
   * @param resetTokenStore the store the reset service issues its tokens into; non-null
   * @return a new service; this instance is unchanged
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public PasswordChangeService withResetTokenStore(ResetTokenStore resetTokenStore) {
    return new PasswordChangeService(store, hashingService, inputValidator, inputPolicy,
        lifecycleService, clock,
        Objects.requireNonNull(resetTokenStore, "resetTokenStore"), changeListener);
  }

  /**
   * Returns a copy of this service that notifies {@code listener} after every
   * successful change (JS-SEC-128, CWE-613).
   * {@link RevokingCredentialChangeListener} raises the subject's security
   * version and revokes remember-me and refresh tokens.
   *
   * @param listener the hook; non-null
   * @return a new service; this instance is unchanged
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public PasswordChangeService withCredentialChangeListener(CredentialChangeListener listener) {
    return new PasswordChangeService(store, hashingService, inputValidator, inputPolicy,
        lifecycleService, clock, resetTokenStore,
        Objects.requireNonNull(listener, "listener"));
  }

  public PasswordChangeResult change(PasswordChangeCommand command) {
    Objects.requireNonNull(command, "command");

    Optional<CredentialRecord> existing = store.findByUsername(command.username());
    if (existing.isEmpty()) {
      return PasswordChangeResult.NotFound.INSTANCE;
    }
    CredentialRecord record = existing.get();

    CredentialLifecycleDecision lifecycle = lifecycleService.decide(record.status());
    if (lifecycle instanceof CredentialLifecycleDecision.BlockedTemporary
        || lifecycle instanceof CredentialLifecycleDecision.BlockedPermanent) {
      return new PasswordChangeResult.Blocked(lifecycle);
    }

    CredentialVerificationResult verifyResult = hashingService.verify(
        command.currentPassword(), record.encodedHash());
    if (!(verifyResult instanceof CredentialVerificationResult.Verified)) {
      return PasswordChangeResult.CurrentPasswordRejected.INSTANCE;
    }

    PasswordInputValidationResult inputCheck =
        inputValidator.validate(command.newPassword(), inputPolicy);
    if (inputCheck instanceof PasswordInputValidationResult.Rejected rejected) {
      return new PasswordChangeResult.NewPasswordRejected(rejected.violation());
    }

    PasswordHashResult newHash = hashingService.hash(command.newPassword());

    Instant now = Instant.now(clock);
    CredentialUpdateResult update = store.updateHashIfCurrent(
        command.username(), record.encodedHash(), newHash.encodedHash(), now);
    if (!(update instanceof CredentialUpdateResult.Updated)) {
      return PasswordChangeResult.Conflict.INSTANCE;
    }

    // Clear MUST_CHANGE if applicable. Failure here is non-fatal:
    // the password update has already succeeded, and the next
    // verification will re-evaluate the lifecycle.
    if (record.status() == CredentialStatus.MUST_CHANGE) {
      lifecycleService.transition(command.username(),
          CredentialStatus.MUST_CHANGE, CredentialStatus.ACTIVE,
          "password-changed");
    }

    // JS-SEC-128 (CWE-640, CWE-613): the change is done. A reset link issued
    // before it must not write another password afterwards, and whatever was
    // obtained with the old password is handed to the listener for revocation.
    // Both steps run after the hash is stored, so a failure in them cannot
    // undo the change; it is logged instead of being lost.
    if (resetTokenStore != null) {
      try {
        resetTokenStore.retireOpenTokens(command.username());
      } catch (RuntimeException failure) {
        logger().warn("credential/change-reset-links-not-retired: open reset links of "
            + "user '{}' could not be retired after the password change: {}",
            command.username(), failure.toString());
      }
    }
    try {
      changeListener.credentialChanged(command.username(),
          CredentialChangeListener.Cause.PASSWORD_CHANGED, now);
    } catch (RuntimeException failure) {
      logger().warn("credential/change-listener-failed: listener failed after the "
          + "password change of user '{}': {}", command.username(), failure.toString());
    }

    return new PasswordChangeResult.Succeeded(
        SessionHandlingDecision.INVALIDATE_OTHER_SESSIONS);
  }
}
