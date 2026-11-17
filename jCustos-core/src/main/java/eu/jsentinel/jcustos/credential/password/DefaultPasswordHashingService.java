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
package eu.jsentinel.jcustos.credential.password;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationContext;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatException;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashRecord;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashValidationException;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;

import java.util.Objects;
import java.util.Optional;

/**
 * Reference {@link PasswordHashingService}.
 *
 * <p>Each {@code verify(...)} call walks the pipeline in this strict
 * order:</p>
 *
 * <ol>
 *   <li><strong>acquire limiter permit</strong> &mdash; one
 *       {@link KdfExecutionLimiter} permit covers the whole call,
 *       including any dummy KDF taken on failure;</li>
 *   <li><strong>parse</strong> &mdash; decode the envelope through
 *       {@link PasswordHashCodec};</li>
 *   <li><strong>validate</strong> &mdash; gate the envelope through
 *       {@link PasswordHashValidator} (rejects out-of-bound parameters
 *       cheaply, CWE-400);</li>
 *   <li><strong>resolveProvider</strong> &mdash; look up the provider
 *       that produced the envelope (CWE-693);</li>
 *   <li><strong>resolvePepper</strong> &mdash; ask the
 *       {@link PepperService} for the stored pepper key; a key id the
 *       service cannot resolve (with {@code NoOpPepperService}: every
 *       key id) fails verification through the dummy path rather than
 *       being silently downgraded;</li>
 *   <li><strong>verify</strong> &mdash; delegate the constant-time
 *       comparison to the provider;</li>
 *   <li><strong>rehashDecision</strong> &mdash; on success, compute
 *       whether the envelope should be transparently upgraded.</li>
 * </ol>
 *
 * <p>Every failure path executes a comparable
 * {@link DummyVerificationService} call before returning so that
 * &quot;user does not exist&quot;, &quot;envelope is malformed&quot;
 * and &quot;provider is missing&quot; collapse onto the same
 * observable timing profile (CWE-203, CWE-208). Every public failure
 * of an evaluated credential collapses onto
 * {@link PublicFailureType#INVALID_CREDENTIALS}; the differentiated
 * {@link InternalAuditEventType} is preserved for audit sinks.</p>
 *
 * <p><strong>Load shedding is not a wrong password</strong> (JS-SEC-126,
 * CWE-703, CWE-645): when the {@link KdfExecutionLimiter} grants no
 * permit, nothing was evaluated, and the result is
 * {@link PublicFailureType#TEMPORARILY_UNAVAILABLE} with
 * {@link InternalAuditEventType#VERIFICATION_REJECTED_KDF_LIMIT}. Until
 * 00.83.00 it was {@code INVALID_CREDENTIALS}, so a flood of anonymous
 * requests that kept the permits busy made correct logins count as
 * failures and locked the accounts behind them. Callers must not record
 * such a result as a failed attempt; see
 * {@link CredentialVerificationResult#temporarilyUnavailable()}.</p>
 *
 * <p><strong>Cost floor (JS-SEC-009, closed in 00.82.00):</strong> the dummy
 * KDF runs the <em>preferred</em> algorithm, so a stored hash on a different
 * algorithm verifies at a different cost. During a lazy multi-KDF migration
 * (legacy PBKDF2 alongside a preferred Argon2id) that difference is measurable
 * from outside and separates &quot;existing but unmigrated&quot; from &quot;no
 * such user&quot; — the very distinction the dummy path exists to hide. A
 * verification against a non-preferred envelope therefore runs an additional
 * preferred-cost dummy KDF, putting every outcome on the same floor. The price
 * is one extra KDF per unmigrated account, which disappears as the migration
 * completes.</p>
 */
public final class DefaultPasswordHashingService implements PasswordHashingService {

  private final PasswordHashCodec codec;
  private final PasswordHashValidator validator;
  private final PasswordHashProviderRegistry providerRegistry;
  private final PepperService pepperService;
  private final PasswordHashPolicy policy;
  private final RehashDecisionEngine rehashEngine;
  private final KdfExecutionLimiter limiter;
  private final DummyVerificationService dummyService;

  public DefaultPasswordHashingService(
      PasswordHashCodec codec,
      PasswordHashValidator validator,
      PasswordHashProviderRegistry providerRegistry,
      PepperService pepperService,
      PasswordHashPolicy policy,
      RehashDecisionEngine rehashEngine,
      KdfExecutionLimiter limiter,
      DummyVerificationService dummyService) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.validator = Objects.requireNonNull(validator, "validator");
    this.providerRegistry = Objects.requireNonNull(
        providerRegistry, "providerRegistry");
    this.pepperService = Objects.requireNonNull(pepperService, "pepperService");
    this.policy = Objects.requireNonNull(policy, "policy");
    this.rehashEngine = Objects.requireNonNull(rehashEngine, "rehashEngine");
    this.limiter = Objects.requireNonNull(limiter, "limiter");
    this.dummyService = Objects.requireNonNull(dummyService, "dummyService");

    PasswordHashProvider preferred = providerRegistry.resolve(
        policy.preferredProviderId(), policy.preferredAlgorithm())
        .orElseThrow(() -> new IllegalStateException(
            "policy's preferred provider is not registered"));
    if (!preferred.algorithm().equals(policy.preferredAlgorithm())
        || !preferred.providerId().equals(policy.preferredProviderId())) {
      throw new IllegalStateException(
          "preferred provider does not advertise the preferred algorithm");
    }
  }

  @Override
  public PasswordHashResult hash(char[] password) {
    Objects.requireNonNull(password, "password");
    PasswordHashProvider provider = providerRegistry
        .resolve(policy.preferredProviderId(), policy.preferredAlgorithm())
        .orElseThrow(() -> new IllegalStateException(
            "preferred provider disappeared after construction"));
    Optional<PepperReference> pepper = resolveActivePepper();
    Optional<KdfExecutionLimiter.Lease> lease = limiter.acquire();
    if (lease.isEmpty()) {
      throw new KdfLimitExceededException();
    }
    try (KdfExecutionLimiter.Lease l = lease.get()) {
      return provider.hash(password, policy, pepper);
    }
  }

  @Override
  public CredentialVerificationResult verify(
      char[] password, String encodedHash) {
    Objects.requireNonNull(password, "password");
    Optional<KdfExecutionLimiter.Lease> lease = limiter.acquire();
    if (lease.isEmpty()) {
      return shed();
    }
    try (KdfExecutionLimiter.Lease l = lease.get()) {
      return verifyUnderLease(password, encodedHash);
    }
  }

  @Override
  public CredentialVerificationResult verifyAgainstNothing(char[] password) {
    Objects.requireNonNull(password, "password");
    Optional<KdfExecutionLimiter.Lease> lease = limiter.acquire();
    if (lease.isEmpty()) {
      return shed();
    }
    try (KdfExecutionLimiter.Lease l = lease.get()) {
      dummyService.runDummyKdf(password, DummyVerificationContext.UNKNOWN_USER);
      return failed(InternalAuditEventType.VERIFICATION_DUMMY_PATH);
    }
  }

  @Override
  public RehashDecision needsRehash(String encodedHash) {
    if (encodedHash == null) {
      return RehashDecision.NotRequired.INSTANCE;
    }
    try {
      PasswordHashRecord record = codec.decode(encodedHash);
      return rehashEngine.decide(
          record.envelope(), policy, pepperService.activeKeyId(),
          providerHint(record.envelope()));
    } catch (PasswordHashFormatException e) {
      return RehashDecision.NotRequired.INSTANCE;
    }
  }

  /**
   * JS-SEC-133 (CWE-327, CWE-521): the rehash reason the envelope's own provider reports,
   * whatever the policy's defaults say - so a legacy bcrypt hash is rehashed under a policy
   * whose bcrypt defaults were assembled without {@code term=1}. A provider that is not
   * registered reports nothing; a hint that fails is logged and treated as none, because
   * {@code needsRehash} runs after a successful login and must not break it.
   */
  private Optional<RehashReason> providerHint(PasswordHashEnvelope envelope) {
    try {
      return providerRegistry.resolve(envelope.providerId(), envelope.algorithm())
          .flatMap(provider -> provider.rehashHint(envelope));
    } catch (RuntimeException hintFailure) {
      HasLogger.staticLogger().warn(
          "credential/rehash-hint-failed: provider {} could not assess a stored hash: {}",
          LogFieldScrubber.scrub(envelope.providerId()), hintFailure.getClass().getName());
      return Optional.empty();
    }
  }

  private CredentialVerificationResult verifyUnderLease(
      char[] password, String encodedHash) {
    if (encodedHash == null) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.ENVELOPE_DECODE_ERROR);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR);
    }

    PasswordHashRecord record;
    try {
      record = codec.decode(encodedHash);
    } catch (PasswordHashFormatException e) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.ENVELOPE_DECODE_ERROR);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR);
    }

    PasswordHashEnvelope envelope = record.envelope();

    try {
      validator.validate(envelope, policy);
    } catch (PasswordHashValidationException e) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.ENVELOPE_VALIDATION_ERROR);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS);
    }

    Optional<PasswordHashProvider> resolvedProvider = providerRegistry
        .resolve(envelope.providerId(), envelope.algorithm());
    if (resolvedProvider.isEmpty()) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.PROVIDER_MISSING);
      return failed(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PROVIDER);
    }

    Optional<PepperReference> pepperReference;
    if (envelope.pepperKeyId().isPresent()) {
      String keyId = envelope.pepperKeyId().get();
      Optional<byte[]> resolved = pepperService.resolve(keyId);
      if (resolved.isEmpty()) {
        dummyService.runDummyKdf(password,
            DummyVerificationContext.PEPPER_KEY_UNKNOWN);
        return failed(
            InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY);
      }
      try {
        pepperReference = Optional.of(new PepperReference(keyId, resolved.get()));
      } catch (IllegalArgumentException e) {
        dummyService.runDummyKdf(password,
            DummyVerificationContext.PEPPER_KEY_UNKNOWN);
        return failed(
            InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY);
      } finally {
        java.util.Arrays.fill(resolved.get(), (byte) 0);
      }
    } else {
      pepperReference = Optional.empty();
    }

    ProviderVerificationResult providerResult = resolvedProvider.get()
        .verify(password, envelope, pepperReference);

    // Cost floor (CWE-208). A stored hash on a non-preferred algorithm costs a
    // different amount to verify than the dummy KDF, which always runs the
    // preferred one. During a lazy migration that difference is measurable from
    // outside and separates "existing but unmigrated" from "no such user" —
    // exactly the distinction the dummy path exists to hide. Topping the run up
    // with a preferred-cost KDF removes it, at the price of one extra KDF for
    // accounts that have not migrated yet.
    if (!isPreferred(envelope)) {
      dummyService.runDummyKdf(password,
          DummyVerificationContext.NON_PREFERRED_ALGORITHM_COST_FLOOR);
    }

    return switch (providerResult) {
      case ProviderVerificationResult.Matched ignored ->
          new CredentialVerificationResult.Verified(
              record.encoded(),
              envelope.credentialType(),
              envelope.algorithm(),
              envelope.providerId(),
              envelope.formatVersion().wireValue(),
              envelope.policyVersion(),
              envelope.pepperKeyId());
      case ProviderVerificationResult.NotMatched ignored ->
          failed(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH);
      case ProviderVerificationResult.ProviderError err ->
          failed(err.internalAuditEventType());
    };
  }

  /**
   * Whether this envelope was produced by the preferred provider and algorithm —
   * that is, whether verifying it costs what the dummy path costs.
   */
  private boolean isPreferred(PasswordHashEnvelope envelope) {
    return envelope.providerId().equals(policy.preferredProviderId())
        && envelope.algorithm().equals(policy.preferredAlgorithm());
  }

  private static CredentialVerificationResult.Failed failed(
      InternalAuditEventType internal) {
    return new CredentialVerificationResult.Failed(
        PublicFailureType.INVALID_CREDENTIALS, internal);
  }

  /**
   * JS-SEC-126 (CWE-703, CWE-645): no permit, so no verdict. The outcome says "try again", not
   * "wrong password", and it is the same whatever the supplied credential was.
   */
  private static CredentialVerificationResult.Failed shed() {
    return new CredentialVerificationResult.Failed(
        PublicFailureType.TEMPORARILY_UNAVAILABLE,
        InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT);
  }

  private Optional<PepperReference> resolveActivePepper() {
    Optional<String> activeKey = pepperService.activeKeyId();
    if (activeKey.isEmpty()) {
      return Optional.empty();
    }
    Optional<byte[]> resolved = pepperService.resolve(activeKey.get());
    if (resolved.isEmpty()) {
      throw new IllegalStateException(
          "active pepper key id does not resolve in the pepper service");
    }
    byte[] keyBytes = resolved.get();
    try {
      return Optional.of(new PepperReference(activeKey.get(), keyBytes));
    } finally {
      java.util.Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /**
   * Thrown by {@link #hash(char[])} when the limiter is saturated.
   * Verification paths do not throw; they return a
   * {@link PublicFailureType#TEMPORARILY_UNAVAILABLE} result instead.
   */
  public static final class KdfLimitExceededException extends RuntimeException {
    public KdfLimitExceededException() {
      super("KDF execution limiter rejected the request");
    }
  }
}
