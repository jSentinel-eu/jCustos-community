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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.audit.PasswordResetCompleted;
import eu.jsentinel.jcustos.audit.PasswordResetRequested;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.abuse.AbuseAttemptContext;
import eu.jsentinel.jcustos.credential.abuse.AbuseAttemptType;
import eu.jsentinel.jcustos.credential.abuse.AbuseDecision;
import eu.jsentinel.jcustos.credential.abuse.AbuseDetectionService;
import eu.jsentinel.jcustos.credential.abuse.AttemptOutcome;
import eu.jsentinel.jcustos.credential.change.CredentialChangeListener;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidationResult;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.lifecycle.InvalidStatusTransitionException;
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
 * persists the digest with the supplied TTL and emits
 * {@link PasswordResetRequested}. The verifier is returned to
 * the caller exactly once; the store retains only the digest
 * (CWE-522 / CWE-209 / CWE-640).</p>
 *
 * <p>A reset request is unauthenticated, so it must not take anything away
 * from the account's owner (JS-SEC-121, CWE-645, CWE-640). Since 00.84.00 the
 * request therefore leaves the status of a usable credential untouched: the
 * reset runs <em>alongside</em> the password login until {@link #consume}
 * replaces the password. Before, the request moved an {@code ACTIVE}
 * credential to {@link CredentialStatus#RESET_PENDING}, which locked the
 * owner out of the password login for as long as anyone kept asking.</p>
 *
 * <p>The one path that still enters {@code RESET_PENDING} is the way out of
 * {@link CredentialStatus#COMPROMISED} (JS-SEC-076): that credential is
 * blocked anyway and stays blocked until the link is consumed. When the last
 * open link of such a credential lapses unused, the credential returns to
 * {@code COMPROMISED} — see {@link #releaseLapsedReset(String)}.</p>
 *
 * <h2>One key per account</h2>
 * <p>The {@link CredentialStore} decides which spellings of a user name are
 * the same account; {@code InMemoryCredentialStore} folds {@code alice} and
 * {@code ALICE} onto one record (JS-SEC-123, CWE-178). Since 00.84.00 the
 * service therefore keys everything it stores for an account - the reset
 * tokens, the status remembered for {@code RESET_PENDING} - and the audit
 * events on {@link CredentialRecord#username()} of the record the store
 * returned, not on the spelling of the request. Before, a link requested as
 * {@code ALICE} did not retire the link requested as {@code alice}, so
 * "only the newest link works" (JS-SEC-074) held per spelling, not per
 * account. The throttle receives the name as it was typed, as its contract
 * asks; {@code InMemoryAbuseDetectionService} canonicalises it itself.</p>
 *
 * <h2>Throttle</h2>
 * <p>{@link #withAbuseDetection(AbuseDetectionService)} gives the service a
 * throttle seam. With it, every request is evaluated as
 * {@link AbuseAttemptType#RESET_REQUEST} <em>before</em> anything is
 * touched; a request the throttle refuses issues no token and — the point
 * of JS-SEC-121 — retires no sibling, so a flood of requests cannot keep
 * invalidating the link the owner just received. Without the seam every
 * request is accepted and the adapter is expected to throttle before it
 * calls the service.</p>
 *
 * <h2>Consume</h2>
 * <p>{@link #consume(String, SecretValue)} parses the wire token,
 * looks up the digest record by selector, checks expiry and status,
 * verifies the verifier digest in constant time
 * ({@link TokenDigestService#verifyVerifier}), validates the new
 * password against the input policy, then <em>claims</em> the token by
 * CAS-marking it CONSUMED and only after a successful claim hashes the
 * password and performs a compare-and-swap on the credential's encoded
 * hash (JS-SEC-128, CWE-367: one token writes at most one password) through
 * {@link CredentialStore#replaceSecretIfCurrent}, which records the change and
 * clears a compromise marker in the same step (JS-SEC-161). Open
 * siblings are retired and {@link PasswordResetCompleted} is emitted
 * (JS-SEC-074). A credential that was {@code RESET_PENDING} or
 * {@link CredentialStatus#MUST_CHANGE} returns to {@code ACTIVE}; since
 * {@code PasswordChangeService} refuses to replace a secret declared
 * compromised, the reset is the way out of {@code COMPROMISED -> MUST_CHANGE}
 * (JS-SEC-161).</p>
 *
 * <p>Every failure variant collapses to the same generic public
 * response at the adapter boundary; the differentiated reason stays
 * inside the audit trail (CWE-209).</p>
 */
public final class PasswordResetService implements HasLogger {

  /** Lifecycle reason key of the transition back out of {@code RESET_PENDING} (JS-SEC-121). */
  static final String REASON_RESET_LAPSED = "reset-lapsed";

  private final CredentialStore credentialStore;
  private final ResetTokenStore resetStore;
  private final TokenDigestService tokens;
  private final PasswordHashingService hashingService;
  private final PasswordInputValidator inputValidator;
  private final PasswordInputPolicy inputPolicy;
  private final CredentialLifecycleService lifecycleService;
  private final Clock clock;
  private final JCustosAuditService auditService;
  /** Optional throttle seam (JS-SEC-121); {@code null} when the adapter throttles itself. */
  private final AbuseDetectionService abuseDetection;
  /** Optional hook after a consumed reset (JS-SEC-128); never {@code null}. */
  private final CredentialChangeListener changeListener;

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
    this(credentialStore, resetStore, tokens, hashingService, inputValidator,
        inputPolicy, lifecycleService, clock, auditService,
        null, CredentialChangeListener.noop());
  }

  private PasswordResetService(
      CredentialStore credentialStore,
      ResetTokenStore resetStore,
      TokenDigestService tokens,
      PasswordHashingService hashingService,
      PasswordInputValidator inputValidator,
      PasswordInputPolicy inputPolicy,
      CredentialLifecycleService lifecycleService,
      Clock clock,
      JCustosAuditService auditService,
      AbuseDetectionService abuseDetection,
      CredentialChangeListener changeListener) {
    this.auditService = auditService;
    this.credentialStore = Objects.requireNonNull(credentialStore, "credentialStore");
    this.resetStore = Objects.requireNonNull(resetStore, "resetStore");
    this.tokens = Objects.requireNonNull(tokens, "tokens");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    this.inputValidator = Objects.requireNonNull(inputValidator, "inputValidator");
    this.inputPolicy = Objects.requireNonNull(inputPolicy, "inputPolicy");
    this.lifecycleService = Objects.requireNonNull(lifecycleService, "lifecycleService");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.abuseDetection = abuseDetection;
    this.changeListener = Objects.requireNonNull(changeListener, "changeListener");
  }

  /**
   * Returns a copy of this service that asks {@code abuseDetection} before it
   * accepts a reset request (JS-SEC-121, CWE-799).
   *
   * <p>The request is evaluated as {@link AbuseAttemptType#RESET_REQUEST}
   * with the username, the client address handed to
   * {@link #issue(String, Duration, String)} and {@link TenantId#DEFAULT}.
   * {@link AbuseDecision.Block} and
   * {@link AbuseDecision.RequireAdditionalCheck} refuse the request with
   * {@link ResetTokenCreationResult.Blocked} — the service cannot perform an
   * additional check itself, so it fails closed; an adapter that offers a
   * step-up evaluates the throttle itself and uses a service without this
   * seam. {@link AbuseDecision.Delay} lets the request pass; the pause is the
   * adapter's to apply. The service records the outcome of every request it
   * let pass, so the adapter must not record {@code RESET_REQUEST} a second
   * time.</p>
   *
   * @param abuseDetection the throttle; non-null
   * @return a new service; this instance is unchanged
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public PasswordResetService withAbuseDetection(AbuseDetectionService abuseDetection) {
    return new PasswordResetService(credentialStore, resetStore, tokens, hashingService,
        inputValidator, inputPolicy, lifecycleService, clock, auditService,
        Objects.requireNonNull(abuseDetection, "abuseDetection"), changeListener);
  }

  /**
   * Returns a copy of this service that notifies {@code listener} after every
   * consumed reset (JS-SEC-128, CWE-613).
   * {@link eu.jsentinel.jcustos.credential.change.RevokingCredentialChangeListener}
   * raises the subject's security version and revokes remember-me and
   * refresh tokens.
   *
   * @param listener the hook; non-null
   * @return a new service; this instance is unchanged
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public PasswordResetService withCredentialChangeListener(CredentialChangeListener listener) {
    return new PasswordResetService(credentialStore, resetStore, tokens, hashingService,
        inputValidator, inputPolicy, lifecycleService, clock, auditService,
        abuseDetection, Objects.requireNonNull(listener, "listener"));
  }

  /**
   * Issues a fresh reset token. Returns either a {@code Created} with
   * the wire token, or an opaque failure — callers must surface the
   * same generic message in both cases (CWE-203).
   *
   * <p>Equivalent to {@link #issue(String, Duration, String)} without a
   * client address.</p>
   */
  public ResetTokenCreationResult issue(String username, Duration ttl) {
    return issue(username, ttl, null);
  }

  /**
   * Issues a fresh reset token for a request that came from
   * {@code clientAddress}.
   *
   * <p>The status of a usable credential is not changed (JS-SEC-121): the
   * owner can keep signing in with the current password while the link is
   * open. Only a {@link CredentialStatus#COMPROMISED} credential moves to
   * {@link CredentialStatus#RESET_PENDING}.</p>
   *
   * <p>When a throttle is configured
   * ({@link #withAbuseDetection(AbuseDetectionService)}) and refuses the
   * request, the result is {@link ResetTokenCreationResult.Blocked} for known
   * and unknown usernames alike; no token is issued and no open link is
   * retired.</p>
   *
   * @param username      the credential's username; non-null
   * @param ttl           lifetime of the link; positive
   * @param clientAddress resolved client address for the per-address
   *                      throttle, or {@code null} when unknown
   * @return the outcome; adapters surface the same public response for all
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public ResetTokenCreationResult issue(String username, Duration ttl, String clientAddress) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be positive");
    }
    Instant now = Instant.now(clock);

    // JS-SEC-121 (CWE-799, CWE-645): ask the throttle before anything is
    // touched. A refused request must neither mint a token nor retire the link
    // the owner already holds — otherwise repeating the request is all it takes
    // to keep every delivered link dead. The answer is the same for known and
    // unknown usernames (CWE-203).
    AbuseAttemptContext attempt = abuseDetection == null ? null
        : new AbuseAttemptContext(AbuseAttemptType.RESET_REQUEST,
            Optional.of(username), Optional.ofNullable(clientAddress),
            TenantId.DEFAULT, now);
    if (attempt != null) {
      AbuseDecision decision = abuseDetection.evaluate(attempt);
      if (decision instanceof AbuseDecision.Block
          || decision instanceof AbuseDecision.RequireAdditionalCheck) {
        return ResetTokenCreationResult.Blocked.INSTANCE;
      }
    }

    Optional<CredentialRecord> credential = credentialStore.findByUsername(username);
    if (credential.isEmpty()) {
      recordOutcome(attempt, AttemptOutcome.FAILURE);
      return ResetTokenCreationResult.UnknownUser.INSTANCE;
    }
    // JS-SEC-123 (CWE-178): from here on the account is named the way its
    // record names it. The store decided that the requested spelling is this
    // account; keying the tokens on the request's spelling instead would give
    // every spelling a link of its own that the next request does not retire.
    final String account = credential.get().username();
    CredentialStatus status = credential.get().status();
    // JS-SEC-076 (CWE-284): a reset IS the way out of COMPROMISED — it rotates
    // the secret. Only DISABLED stays blocked; re-enabling is an administrative
    // decision, not something a password-reset link may perform.
    if (status == CredentialStatus.DISABLED) {
      recordOutcome(attempt, AttemptOutcome.FAILURE);
      return ResetTokenCreationResult.Blocked.INSTANCE;
    }

    Instant expiresAt = now.plus(ttl);

    SelectorVerifierToken token = tokens.generate();
    TokenDigestRecord digest = tokens.digest(token);
    ResetTokenRecord record = new ResetTokenRecord(
        digest, account, now, expiresAt,
        ResetTokenStatus.ISSUED, 1L);
    // JS-SEC-074 (CWE-640): only the newest link may work. Retire every open
    // sibling before the new token exists, so an older intercepted link dies
    // the moment the user asks again. JS-SEC-121: this point is only reached
    // by a request that passed the throttle above.
    retireOpenSiblings(account, null);
    resetStore.save(record);
    publish(new PasswordResetRequested(now, account, token.selector()));

    // JS-SEC-121 (CWE-645, CWE-640): an unauthenticated request does not change
    // the status of a usable credential — ACTIVE, MUST_CHANGE, REHASH_REQUIRED,
    // DEPRECATED_ALGORITHM and LOCKED stay what they are, and the password
    // login keeps working until consume replaces the password. The only
    // transition left is COMPROMISED -> RESET_PENDING (JS-SEC-076): that
    // credential is blocked either way, and RESET_PENDING tells consume that
    // the reset was requested after the compromise was recorded. The status is
    // read again after the token is stored, so that a concurrent
    // releaseLapsedReset which just returned the credential to COMPROMISED
    // cannot strand the new link.
    CredentialStatus current = credentialStore.findByUsername(account)
        .map(CredentialRecord::status).orElse(status);
    if (current == CredentialStatus.COMPROMISED) {
      enterResetPending(account);
    }
    recordOutcome(attempt, AttemptOutcome.SUCCESS);
    return new ResetTokenCreationResult.Created(token);
  }

  /**
   * Returns a credential to the status it had before a reset moved it to
   * {@link CredentialStatus#RESET_PENDING}, once no open reset link is left
   * for it (JS-SEC-121, CWE-645).
   *
   * <p>There is no timer in the core. The check runs when an expired link is
   * presented to {@link #consume}, and adapters call this method where a
   * {@code RESET_PENDING} credential shows up — typically in the login path
   * before the lifecycle decision is evaluated — or from a housekeeping job.
   * It is cheap and idempotent.</p>
   *
   * <p>Only a credential whose earlier status the {@link ResetTokenStore}
   * recorded is touched ({@link ResetTokenStore#statusBeforeReset}); the
   * reset service records it for the path out of {@code COMPROMISED}. A
   * credential that is {@code RESET_PENDING} for another reason — set by an
   * administrator, or by a version before 00.84.00 — is left alone and
   * leaves that status through a consumed reset.</p>
   *
   * @param username the credential's username; non-null
   * @return the credential's status after the check, empty for an unknown username
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public Optional<CredentialStatus> releaseLapsedReset(String username) {
    Objects.requireNonNull(username, "username");
    Optional<CredentialRecord> credential = credentialStore.findByUsername(username);
    if (credential.isEmpty()) {
      return Optional.empty();
    }
    // JS-SEC-123 (CWE-178): the tokens are keyed on the record's own name.
    String account = credential.get().username();
    releaseIfLapsed(account, Instant.now(clock));
    return credentialStore.findByUsername(account).map(CredentialRecord::status);
  }

  /**
   * Consumes the supplied wire token, atomically replacing the
   * credential's hash with the supplied new password and marking the
   * token CONSUMED.
   *
   * <p>Returns {@code Succeeded} only when every step succeeded; any
   * failure path returns {@code Failed} so the public response stays
   * generic (CWE-203 / CWE-209).</p>
   *
   * <p>The token is claimed before the password is hashed and written
   * (JS-SEC-128, CWE-367). A token whose claim succeeded stays consumed even
   * when the write that follows fails; the user then asks for a new link.</p>
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
      // JS-SEC-121: the link lapsed unused. If it was the last open one of a
      // credential on the path out of COMPROMISED, the credential goes back.
      releaseIfLapsed(record.username(), now);
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

    // JS-SEC-128 (CWE-367, CWE-640): claim the token FIRST. The CAS on the
    // token status is the single-use guarantee; hashing and writing the
    // password happen only for the caller whose claim succeeded. In the order
    // used before 00.84.00 — hash write first, claim second — a second consume
    // that ran in between read the already replaced hash as its witness, wrote
    // its own password and took the claim, so one token wrote two passwords
    // and the later caller's password stayed.
    ResetTokenUpdateResult tokenUpdate = resetStore.markConsumedIfCurrent(
        token.selector(), ResetTokenStatus.ISSUED);
    if (!(tokenUpdate instanceof ResetTokenUpdateResult.Updated)) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    // From here on the token is spent. If hashing throws or the compare-and-swap
    // loses against a concurrent credential change, the reset fails and the
    // token stays consumed — a link must never become usable again.
    PasswordHashResult newHash = hashingService.hash(newPassword);
    // JS-SEC-161 (CWE-620): a new secret - the store records the change and
    // clears the compromise marker in the same step as the hash.
    CredentialUpdateResult credUpdate = credentialStore.replaceSecretIfCurrent(
        record.username(),
        credentialRecord.encodedHash(),
        newHash.encodedHash(),
        now);
    if (!(credUpdate instanceof CredentialUpdateResult.Updated)) {
      return PasswordResetConsumeResult.Failed.INSTANCE;
    }

    // JS-SEC-074 (CWE-640): the reset is done; no other link issued for this
    // credential may reset the password a second time.
    retireOpenSiblings(record.username(), token.selector());
    publish(new PasswordResetCompleted(now, record.username(), token.selector()));

    // Move the credential back to ACTIVE. JS-SEC-161 (CWE-620): MUST_CHANGE is
    // cleared too - the reset wrote a secret only the owner of the recovery
    // channel chose, which is what MUST_CHANGE asks for, and for a credential
    // that went COMPROMISED -> MUST_CHANGE the reset is the only way back,
    // because PasswordChangeService refuses a change while the compromise is
    // recorded.
    CredentialStatus statusBefore = credentialRecord.status();
    if ((statusBefore == CredentialStatus.RESET_PENDING
        || statusBefore == CredentialStatus.MUST_CHANGE)
        && lifecycleService.isAllowed(statusBefore, CredentialStatus.ACTIVE)) {
      try {
        lifecycleService.transition(record.username(),
            statusBefore, CredentialStatus.ACTIVE,
            "reset-consumed");
      } catch (InvalidStatusTransitionException refused) {
        // JS-SEC-161: only a store that does not record the new secret gets here
        // (replaceSecretIfCurrent left the compromise marker in place). The
        // password is replaced; the credential keeps its status.
        logger().warn("credential/rotation-not-recorded: the password of user '{}' was"
            + " reset, but the credential store did not record the new secret, so the"
            + " credential stays {}: {}", LogFieldScrubber.scrub(record.username()),
            statusBefore, refused.getMessage());
      }
    }
    // JS-SEC-121: the reset completed; there is no earlier status to return to.
    resetStore.forgetStatusBeforeReset(record.username());

    // JS-SEC-128 (CWE-613): whatever was obtained with the old password is
    // handed to the listener for revocation. The password is already replaced,
    // so a failing listener is logged and does not turn the reset into a failure.
    try {
      changeListener.credentialChanged(record.username(),
          CredentialChangeListener.Cause.PASSWORD_RESET, now);
    } catch (RuntimeException failure) {
      logger().warn("credential/reset-listener-failed: listener failed after the "
          + "password reset of user '{}': {}", record.username(), failure.toString());
    }
    return PasswordResetConsumeResult.Succeeded.INSTANCE;
  }

  /**
   * COMPROMISED -> RESET_PENDING, remembering where the credential came from
   * (JS-SEC-076, JS-SEC-121).
   */
  private void enterResetPending(String username) {
    if (!lifecycleService.isAllowed(
        CredentialStatus.COMPROMISED, CredentialStatus.RESET_PENDING)) {
      return;
    }
    // Record the origin before the transition: a crash in between leaves a
    // record for a credential that is not RESET_PENDING, which releaseIfLapsed
    // ignores; the other order could leave RESET_PENDING without a way back.
    resetStore.rememberStatusBeforeReset(username, CredentialStatus.COMPROMISED);
    lifecycleService.transition(
        username, CredentialStatus.COMPROMISED, CredentialStatus.RESET_PENDING,
        "reset-issued");
  }

  /**
   * JS-SEC-121 (CWE-645): returns a RESET_PENDING credential to its recorded
   * earlier status when it has no open, unexpired link left.
   */
  private void releaseIfLapsed(String username, Instant now) {
    Optional<CredentialStatus> origin = resetStore.statusBeforeReset(username);
    if (origin.isEmpty() || hasOpenToken(username, now)) {
      return;
    }
    Optional<CredentialRecord> credential = credentialStore.findByUsername(username);
    if (credential.isEmpty()
        || credential.get().status() != CredentialStatus.RESET_PENDING) {
      return;
    }
    CredentialStatus target = origin.get();
    if (!lifecycleService.isAllowed(CredentialStatus.RESET_PENDING, target)) {
      return;
    }
    CredentialUpdateResult released = lifecycleService.transition(
        username, CredentialStatus.RESET_PENDING, target, REASON_RESET_LAPSED);
    if (!(released instanceof CredentialUpdateResult.Updated)) {
      return;
    }
    // A request that stored a new link while the credential was still
    // RESET_PENDING saw nothing to do. Look again now that the status is
    // written: issue reads the status after it stored its token, this method
    // reads the tokens after it wrote the status — one of the two sees the other.
    if (target == CredentialStatus.COMPROMISED && hasOpenToken(username, now)) {
      enterResetPending(username);
      return;
    }
    resetStore.forgetStatusBeforeReset(username);
  }

  /**
   * @return whether {@code username} has a link that is still ISSUED and not
   *     past its expiry at {@code now}; links past their expiry are marked
   *     EXPIRED on the way
   */
  private boolean hasOpenToken(String username, Instant now) {
    boolean open = false;
    for (ResetTokenRecord candidate : resetStore.findByUsername(username)) {
      if (candidate.status() != ResetTokenStatus.ISSUED) {
        continue;
      }
      if (candidate.isExpired(now)) {
        resetStore.markExpiredIfCurrent(candidate.selector(), ResetTokenStatus.ISSUED);
      } else {
        open = true;
      }
    }
    return open;
  }

  private void recordOutcome(AbuseAttemptContext attempt, AttemptOutcome outcome) {
    if (attempt == null) {
      return;
    }
    try {
      abuseDetection.recordOutcome(attempt, outcome);
    } catch (RuntimeException failure) {
      // The request itself is decided; a counter that could not be updated
      // must not turn an issued link into an error.
      logger().warn("credential/reset-throttle-record-failed: {}", failure.toString());
    }
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
