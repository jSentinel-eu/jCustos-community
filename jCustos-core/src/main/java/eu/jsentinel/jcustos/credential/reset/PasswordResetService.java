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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.PasswordResetCompleted;
import eu.jsentinel.jcustos.audit.PasswordResetRequested;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidationResult;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import eu.jsentinel.jcustos.credential.token.SelectorVerifierToken;
import eu.jsentinel.jcustos.credential.token.TokenDigestRecord;
import eu.jsentinel.jcustos.credential.token.TokenDigestService;
import eu.jsentinel.jcustos.credential.token.TokenVerificationResult;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Password reset core service.
 *
 * <h2>Issue</h2>
 * <p>{@link #issue(String, Duration)} mints a {@link SelectorVerifierToken}
 * through {@link TokenDigestService}, retires every still-open token of
 * the same credential (JS-SEC-074, CWE-640: only the newest link works),
 * persists the digest with the supplied TTL, emits
 * {@link PasswordResetRequested} and — for credentials in a state that
 * allows it — transitions the credential to
 * {@link CredentialStatus#RESET_PENDING}. The verifier is returned to
 * the caller exactly once; the store retains only the digest
 * (CWE-522 / CWE-209 / CWE-640).</p>
 *
 * <h2>Consume</h2>
 * <p>{@link #consume(String, SecretValue)} parses the wire token,
 * looks up the digest record by selector, checks expiry and status,
 * verifies the verifier digest in constant time
 * ({@link TokenDigestService#verifyVerifier}), validates the new
 * password against the input policy, hashes it, performs a
 * compare-and-swap on the credential's encoded hash and finally CAS-marks
 * the reset token CONSUMED — all single-use (CWE-362 / CWE-640). Open
 * siblings are retired and {@link PasswordResetCompleted} is emitted
 * (JS-SEC-074).</p>
 *
 * <p>Every failure variant collapses to the same generic public
 * response at the adapter boundary; the differentiated reason stays
 * inside the audit trail (CWE-209).</p>
 */
public final class PasswordResetService {

  private final CredentialStore credentialStore;
  private final ResetTokenStore resetStore;
  private final TokenDigestService tokens;
  private final PasswordHashingService hashingService;
  private final PasswordInputValidator inputValidator;
  private final PasswordInputPolicy inputPolicy;
  private final CredentialLifecycleService lifecycleService;
  private final Clock clock;
  private final JCustosAuditService auditService;

  public PasswordResetService(
      CredentialStore credentialStore,
      ResetTokenStore resetStore,
      TokenDigestService tokens,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock) {
    this(credentialStore, resetStore, tokens, hashingService, inputValidator,
        inputPolicy, lifecycleService, clock, null);
  }

  /**
   * Full constructor with an explicit audit sink.
   *
   * @param auditService sink for {@link PasswordResetRequested} /
   *                     {@link PasswordResetCompleted}, or {@code null} to resolve
   *                     {@link JCustosServiceResolver#securityAuditService()} per event
   * @since 00.84.00
   */
  public PasswordResetService(
      CredentialStore credentialStore,
      ResetTokenStore resetStore,
      TokenDigestService tokens,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock,
      JCustosAuditService auditService) {
    this.auditService = auditService;
    this.credentialStore = Objects.requireNonNull(credentialStore, "credentialStore");
    this.resetStore = Objects.requireNonNull(resetStore, "resetStore");
    this.tokens = Objects.requireNonNull(tokens, "tokens");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    this.inputValidator = Objects.requireNonNull(inputValidator, "inputValidator");
    this.inputPolicy = Objects.requireNonNull(inputPolicy, "inputPolicy");
    this.lifecycleService = Objects.requireNonNull(lifecycleService, "lifecycleService");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Issues a fresh reset token. Returns either a {@code Created} with
   * the wire token, or an opaque failure — callers must surface the
   * same generic message in both cases (CWE-203).
   */
  public ResetTokenCreationResult issue(String username, Duration ttl) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be positive");
    }

    Optional<CredentialRecord> credential = credentialStore.findByUsername(username);
    if (credential.isEmpty()) {
      return ResetTokenCreationResult.UnknownUser.INSTANCE;
    }
    CredentialStatus status = credential.get().status();
    // JS-SEC-076 (CWE-284): a reset IS the way out of COMPROMISED — it rotates
    // the secret. Only DISABLED stays blocked; re-enabling is an administrative
    // decision, not something a password-reset link may perform.
    if (status == CredentialStatus.DISABLED) {
      return ResetTokenCreationResult.Blocked.INSTANCE;
    }

    Instant now = Instant.now(clock);
    Instant expiresAt = now.plus(ttl);

    SelectorVerifierToken token = tokens.generate();
    TokenDigestRecord digest = tokens.digest(token);
    ResetTokenRecord record = new ResetTokenRecord(
        digest, username, now, expiresAt,
        ResetTokenStatus.ISSUED, 1L);
    // JS-SEC-074 (CWE-640): only the newest link may work. Retire every open
    // sibling before the new token exists, so an older intercepted link dies
    // the moment the user asks again.
    retireOpenSiblings(username, null);
    resetStore.save(record);
    publish(new PasswordResetRequested(now, username, token.selector()));

    // Mark the credential RESET_PENDING so concurrent password logins
    // surface ResetInProgress in the lifecycle layer. Failure to
    // transition is non-fatal — the consume step will still verify
    // and apply the reset.
    if (status == CredentialStatus.ACTIVE
        || status == CredentialStatus.MUST_CHANGE
        || status == CredentialStatus.REHASH_REQUIRED
        || status == CredentialStatus.DEPRECATED_ALGORITHM
        || status == CredentialStatus.LOCKED
        || status == CredentialStatus.COMPROMISED) {
      if (lifecycleService.isAllowed(status, CredentialStatus.RESET_PENDING)) {
        lifecycleService.transition(
            username, status, CredentialStatus.RESET_PENDING,
            "reset-issued");
      }
    }
    return new ResetTokenCreationResult.Created(token);
  }

  /**
   * Consumes the supplied wire token, atomically replacing the
   * credential's hash with the supplied new password and marking the
   * token CONSUMED.
   *
   * <p>Returns {@code Succeeded} only when every step succeeded; any
   * failure path returns {@code Failed} so the public response stays
   * generic (CWE-203 / CWE-209).</p>
   */
  public PasswordResetConsumeResult consume(
      String wireToken, SecretValue newPassword) {
    Objects.requireNonNull(newPassword, "newPassword");

    Optional<SelectorVerifierToken> parsed = tokens.parse(wireToken);
    if (parsed.isEmpty()) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }
    SelectorVerifierToken token = parsed.get();

    Optional<ResetTokenRecord> stored = resetStore.findBySelector(token.selector());
    if (stored.isEmpty()) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }
    ResetTokenRecord record = stored.get();

    Instant now = Instant.now(clock);
    if (record.isExpired(now)) {
      // Lazy expiry CAS so audit timelines stay accurate; do not
      // surface anything beyond Failed to the caller.
      resetStore.markExpiredIfCurrent(token.selector(), record.status());
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }
    if (record.status() != ResetTokenStatus.ISSUED) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    TokenVerificationResult verifyResult =
        tokens.verifyVerifier(token, record.digest());
    if (!(verifyResult instanceof TokenVerificationResult.Verified)) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    PasswordInputValidationResult inputCheck =
        inputValidator.validate(newPassword, inputPolicy);
    if (inputCheck instanceof PasswordInputValidationResult.Rejected) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    Optional<CredentialRecord> credential =
        credentialStore.findByUsername(record.username());
    if (credential.isEmpty()) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }
    CredentialRecord credentialRecord = credential.get();
    if (credentialRecord.status() == CredentialStatus.DISABLED
        || credentialRecord.status() == CredentialStatus.COMPROMISED) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    PasswordHashResult newHash = hashingService.hash(newPassword);
    CredentialUpdateResult credUpdate = credentialStore.updateHashIfCurrent(
        record.username(),
        credentialRecord.encodedHash(),
        newHash.encodedHash(),
        now);
    if (!(credUpdate instanceof CredentialUpdateResult.Updated)) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    // Atomic single-use marker — once Updated, no second consume can
    // win (CWE-362).
    ResetTokenUpdateResult tokenUpdate = resetStore.markConsumedIfCurrent(
        token.selector(), ResetTokenStatus.ISSUED);
    if (!(tokenUpdate instanceof ResetTokenUpdateResult.Updated)) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }
    // JS-SEC-074 (CWE-640): the reset is done; no other link issued for this
    // credential may reset the password a second time.
    retireOpenSiblings(record.username(), token.selector());
    publish(new PasswordResetCompleted(now, record.username(), token.selector()));

    // Move the credential back to ACTIVE.
    if (credentialRecord.status() == CredentialStatus.RESET_PENDING
        && lifecycleService.isAllowed(
            CredentialStatus.RESET_PENDING, CredentialStatus.ACTIVE)) {
      lifecycleService.transition(record.username(),
          CredentialStatus.RESET_PENDING, CredentialStatus.ACTIVE,
          "reset-consumed");
    }
    return PasswordResetConsumeResult.Succeeded.INSTANCE;
  }

  /**
   * Marks every still-ISSUED token of {@code username} EXPIRED, except the
   * token whose selector is {@code keepSelector}. Best-effort: a CAS that
   * loses against a concurrent consume leaves that record alone.
   *
   * @return number of siblings retired
   */
  private int retireOpenSiblings(String username, String keepSelector) {
    int retired = 0;
    for (ResetTokenRecord sibling : resetStore.findByUsername(username)) {
      if (sibling.status() != ResetTokenStatus.ISSUED
          || sibling.selector().equals(keepSelector)) {
        continue;
      }
      ResetTokenUpdateResult result = resetStore.markExpiredIfCurrent(
          sibling.selector(), ResetTokenStatus.ISSUED);
      if (result instanceof ResetTokenUpdateResult.Updated) {
        retired++;
      }
    }
    return retired;
  }

  private void publish(AuditEvent event) {
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block a reset because the audit sink failed
    }
  }
}
