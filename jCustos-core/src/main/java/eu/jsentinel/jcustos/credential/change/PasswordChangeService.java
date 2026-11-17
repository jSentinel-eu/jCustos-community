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
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.compromised.CheckFailurePolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordPolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordScreen;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidationResult;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.input.PasswordInputViolation;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleDecision;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.lifecycle.InvalidStatusTransitionException;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.DefaultPasswordHashingService;
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
 *   <li>A credential that still holds a secret declared compromised
 *       ({@link CredentialRecord#secretRotationRequired()}, typically
 *       {@code COMPROMISED -> MUST_CHANGE}) → {@code ResetRequired}: the
 *       leaked password must not authorise its own replacement, the reset
 *       is the only way out (JS-SEC-161, CWE-620, CWE-640).</li>
 *   <li>Validate the proposed new password through the input policy.
 *       A rejection here surfaces the structural reason.</li>
 *   <li>When a compromised-password check is configured
 *       ({@link #withCompromisedPasswordCheck}), ask it: a listed password →
 *       {@code NewPasswordRejected(COMPROMISED)}; a check that could not be
 *       carried out under {@link CheckFailurePolicy#BLOCK} →
 *       {@code VerificationUnavailable}.</li>
 *   <li>Re-authenticate by verifying the supplied current password
 *       (CWE-620). A verification that could not be carried out - shed by
 *       the KDF limiter - → {@code VerificationUnavailable}: "could not
 *       verify" is not "wrong" (JS-SEC-126, CWE-703). Anything else but
 *       {@code Verified} → {@code CurrentPasswordRejected}.</li>
 *   <li>Hash the new password through {@link PasswordHashingService}. A hash the
 *       KDF limiter sheds ({@link DefaultPasswordHashingService.KdfLimitExceededException})
 *       → {@code VerificationUnavailable}, the answer of a shed verification,
 *       so that it does not single out a right guess of the current password
 *       (since 00.84.00).</li>
 *   <li>Compare-and-swap the encoded hash with the original envelope as
 *       witness, through {@link CredentialStore#replaceSecretIfCurrent}: the
 *       change time is recorded and a compromise marker cleared in the same
 *       step (JS-SEC-161). Stale → {@code Conflict} (CWE-362).</li>
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
 * <h2>Cheap checks before the KDF</h2>
 * <p>Since 00.84.00 the new password is checked - structure, then the
 * compromised-password list - before the current password is verified. Up to
 * 00.83.00 the verification came first: whoever held a foreign session could
 * send a guess of the current password with a new password the policy refuses
 * and tell {@code CurrentPasswordRejected} from {@code NewPasswordRejected} - an
 * oracle for the current password that changed nothing - and every such call
 * took a KDF permit (CWE-203, CWE-400). A listed new password would have opened
 * the same oracle. Now a refused new password is reported without a KDF run,
 * whatever the current password is.</p>
 *
 * <h2>One key per account</h2>
 * <p>The {@link CredentialStore} decides which spellings of a user name are
 * the same account (JS-SEC-123, CWE-178). The reset links and the
 * {@link CredentialChangeListener} are therefore addressed with
 * {@link CredentialRecord#username()} of the record the store returned, not
 * with the spelling of the command: a change requested as {@code ALICE}
 * retires the links and revokes the tokens of the account {@code alice}.</p>
 *
 * <h2>Optional collaborators</h2>
 * <p>{@link #withResetTokenStore(ResetTokenStore)},
 * {@link #withCredentialChangeListener(CredentialChangeListener)} and
 * {@link #withCompromisedPasswordCheck(CompromisedPasswordChecker, CompromisedPasswordPolicy)}
 * return a copy of the service with the collaborator set. Without them the
 * service behaves as before 00.84.00: a reset link issued earlier stays valid
 * after the change, no session or token is revoked — the returned
 * {@link SessionHandlingDecision} is then only a recommendation to the
 * adapter — and no new password is checked against a list.</p>
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
  /** Optional: the compromised-password step for the new password; never {@code null}. */
  private final CompromisedPasswordScreen compromisedScreen;

  public PasswordChangeService(
      CredentialStore store,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock) {
    this(store, hashingService, inputValidator, inputPolicy, lifecycleService, clock,
        null, CredentialChangeListener.noop(), CompromisedPasswordScreen.none());
  }

  private PasswordChangeService(
      CredentialStore store,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock,
      ResetTokenStore resetTokenStore,
      CredentialChangeListener changeListener,
      CompromisedPasswordScreen compromisedScreen) {
    this.store = Objects.requireNonNull(store, "store");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    this.inputValidator = Objects.requireNonNull(inputValidator, "inputValidator");
    this.inputPolicy = Objects.requireNonNull(inputPolicy, "inputPolicy");
    this.lifecycleService = Objects.requireNonNull(lifecycleService, "lifecycleService");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.resetTokenStore = resetTokenStore;
    this.changeListener = Objects.requireNonNull(changeListener, "changeListener");
    this.compromisedScreen = Objects.requireNonNull(compromisedScreen, "compromisedScreen");
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
        Objects.requireNonNull(resetTokenStore, "resetTokenStore"), changeListener,
        compromisedScreen);
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
        Objects.requireNonNull(listener, "listener"), compromisedScreen);
  }

  /**
   * Returns a copy of this service that checks every new password against
   * {@code checker} before it is hashed (NIST SP 800-63B §5.1.1.2, CWE-521).
   *
   * <p>The check runs after the structural check and before the current
   * password is verified, so it costs no KDF run. A listed password is
   * answered with {@link PasswordChangeResult.NewPasswordRejected} carrying
   * {@link eu.jsentinel.jcustos.credential.input.PasswordInputViolation#COMPROMISED};
   * a check that could not be carried out is decided by
   * {@link CompromisedPasswordPolicy#onFailure()}: {@code ALLOW} and {@code WARN}
   * let the change proceed, {@code BLOCK} answers
   * {@link PasswordChangeResult.VerificationUnavailable}. With
   * {@link CompromisedPasswordPolicy#checkOnSetOrChange()} {@code false} the
   * checker is not asked. Typical checker: a
   * {@link eu.jsentinel.jcustos.credential.compromised.CompositeCompromisedPasswordChecker}
   * over a {@link eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker}
   * and the HaveIBeenPwned range query, built with the policy's
   * {@link CheckFailurePolicy}.</p>
   *
   * @param checker the checker; non-null
   * @param policy  when it runs and how a failed check counts; non-null
   * @return a new service; this instance is unchanged
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public PasswordChangeService withCompromisedPasswordCheck(
      CompromisedPasswordChecker checker, CompromisedPasswordPolicy policy) {
    return new PasswordChangeService(store, hashingService, inputValidator, inputPolicy,
        lifecycleService, clock, resetTokenStore, changeListener,
        new CompromisedPasswordScreen(checker, policy));
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
    // JS-SEC-161 (CWE-620, CWE-640): COMPROMISED -> MUST_CHANGE keeps the
    // compromised secret. Verified here, it would let whoever holds the leak set
    // a password of their own and take the account over - with the change then
    // counted as the rotation. Checked before the verification, so the answer
    // says nothing about the password.
    if (record.secretRotationRequired()) {
      return PasswordChangeResult.ResetRequired.INSTANCE;
    }

    // The free checks of the new password run before the KDF (CWE-203, CWE-400):
    // after the verification, a new password the policy refuses would tell a
    // caller who holds a foreign session whether the guessed current password
    // was right - without changing anything - and every such guess would take a
    // KDF permit. Structure first, so the list is never asked for an overlong or
    // empty input.
    PasswordInputValidationResult inputCheck =
        inputValidator.validate(command.newPassword(), inputPolicy);
    if (inputCheck instanceof PasswordInputValidationResult.Rejected rejected) {
      return new PasswordChangeResult.NewPasswordRejected(rejected.violation());
    }
    // NIST SP 800-63B §5.1.1.2 (CWE-521): a listed password is refused before it
    // is hashed. "Could not check" under BLOCK is "try again later", not "listed".
    CompromisedPasswordScreen.Outcome screened = compromisedScreen.screen(command.newPassword());
    if (screened == CompromisedPasswordScreen.Outcome.LISTED) {
      return new PasswordChangeResult.NewPasswordRejected(PasswordInputViolation.COMPROMISED);
    }
    if (screened == CompromisedPasswordScreen.Outcome.UNAVAILABLE) {
      return PasswordChangeResult.VerificationUnavailable.INSTANCE;
    }

    CredentialVerificationResult verifyResult = hashingService.verify(
        command.currentPassword(), record.encodedHash());
    // JS-SEC-126 (CWE-703, CWE-645): a verification the KDF limiter shed says
    // nothing about the password. Reported as "wrong", the adapter would count
    // a failed attempt and audit a rejected password for a user who typed the
    // right one - under load, that locks correct users out of the change.
    if (verifyResult.temporarilyUnavailable()) {
      return PasswordChangeResult.VerificationUnavailable.INSTANCE;
    }
    if (!(verifyResult instanceof CredentialVerificationResult.Verified)) {
      return PasswordChangeResult.CurrentPasswordRejected.INSTANCE;
    }

    PasswordHashResult newHash;
    try {
      newHash = hashingService.hash(command.newPassword());
    } catch (DefaultPasswordHashingService.KdfLimitExceededException shed) {
      // JS-SEC-126 (CWE-203, CWE-703): the limiter shed the hash of the new password after
      // the current one verified. Escaping as an exception, it told a caller who guessed the
      // current password that the guess was right - a wrong guess ends above as
      // CurrentPasswordRejected - while nothing changed. "Try again later" is the answer a
      // shed verification of any password gets; nothing is written, nobody is notified.
      return PasswordChangeResult.VerificationUnavailable.INSTANCE;
    }

    Instant now = Instant.now(clock);
    // JS-SEC-161 (CWE-620): a new secret, not a rehash - the store records the
    // change and clears the compromise marker together with the hash.
    CredentialUpdateResult update = store.replaceSecretIfCurrent(
        command.username(), record.encodedHash(), newHash.encodedHash(), now);
    if (!(update instanceof CredentialUpdateResult.Updated)) {
      return PasswordChangeResult.Conflict.INSTANCE;
    }

    // Clear MUST_CHANGE if applicable. Failure here is non-fatal:
    // the password update has already succeeded, and the next
    // verification will re-evaluate the lifecycle.
    if (record.status() == CredentialStatus.MUST_CHANGE) {
      try {
        lifecycleService.transition(command.username(),
            CredentialStatus.MUST_CHANGE, CredentialStatus.ACTIVE,
            "password-changed");
      } catch (InvalidStatusTransitionException refused) {
        // JS-SEC-161: the change is refused while a compromise is recorded, so
        // only a compromise recorded concurrently with this change gets here.
        // The password is new; the credential stays MUST_CHANGE.
        logger().warn("credential/rotation-not-recorded: the password of user '{}' was"
            + " changed, but the credential store did not record the new secret, so the"
            + " credential stays {}: {}", LogFieldScrubber.scrub(record.username()),
            CredentialStatus.MUST_CHANGE, refused.getMessage());
      }
    }

    // JS-SEC-128 (CWE-640, CWE-613): the change is done. A reset link issued
    // before it must not write another password afterwards, and whatever was
    // obtained with the old password is handed to the listener for revocation.
    // Both steps run after the hash is stored, so a failure in them cannot
    // undo the change; it is logged instead of being lost.
    // JS-SEC-123 (CWE-178): both are addressed with the record's own name. The
    // reset service keys its links on it, and with the spelling of the command
    // a change requested as "ALICE" would leave the links of "alice" open.
    final String account = record.username();
    if (resetTokenStore != null) {
      try {
        resetTokenStore.retireOpenTokens(account);
      } catch (RuntimeException failure) {
        logger().warn("credential/change-reset-links-not-retired: open reset links of "
            + "user '{}' could not be retired after the password change: {}",
            account, failure.toString());
      }
    }
    try {
      changeListener.credentialChanged(account,
          CredentialChangeListener.Cause.PASSWORD_CHANGED, now);
    } catch (RuntimeException failure) {
      logger().warn("credential/change-listener-failed: listener failed after the "
          + "password change of user '{}': {}", account, failure.toString());
    }

    return new PasswordChangeResult.Succeeded(
        SessionHandlingDecision.INVALIDATE_OTHER_SESSIONS);
  }
}
