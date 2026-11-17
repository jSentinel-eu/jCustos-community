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

import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JS-SEC-064 (CWE-208, CWE-203): {@link ConstantCostCredentialCheck} runs a KDF whether or not
 * the account exists. The pipeline is the real {@link DefaultPasswordHashingService} with PBKDF2;
 * a hand-written wrapper around the real provider counts the KDF runs.
 */
@DisplayName("JS-SEC-064 - ConstantCostCredentialCheck costs one KDF run with or without an account")
class ConstantCostCredentialCheckTest {

  private static final char[] PASSWORD = "Correct-Horse-Battery-1".toCharArray();

  /** Delegates to the real PBKDF2 provider and counts every verification. */
  private static final class CountingProvider implements PasswordHashProvider {
    private final PasswordHashProvider delegate = new Pbkdf2PasswordHashProvider();
    private final AtomicInteger verifications = new AtomicInteger();

    @Override public String providerId() {
      return delegate.providerId();
    }

    @Override public String algorithm() {
      return delegate.algorithm();
    }

    @Override public PasswordHashResult hash(char[] password, PasswordHashPolicy policy,
                                             Optional<PepperReference> pepper) {
      return delegate.hash(password, policy, pepper);
    }

    @Override public ProviderVerificationResult verify(char[] password, PasswordHashEnvelope envelope,
                                                       Optional<PepperReference> pepper) {
      verifications.incrementAndGet();
      return delegate.verify(password, envelope, pepper);
    }
  }

  /** Never grants a lease - every verification is shed. */
  private static final class ExhaustedLimiter implements KdfExecutionLimiter {
    @Override public Optional<Lease> acquire() {
      return Optional.empty();
    }
  }

  private static PasswordHashPolicy fastPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  private static PasswordHashingService pipeline(CountingProvider provider, KdfExecutionLimiter limiter) {
    PasswordHashPolicy policy = fastPolicy();
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(List.of(provider));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(new PasswordHashParameterValidatorRegistry(
            List.of(new Pbkdf2ParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        policy,
        new RehashDecisionEngine(),
        limiter,
        new DefaultDummyVerificationService(registry, policy, PasswordHashCodec.DEFAULT));
  }

  @Test
  @DisplayName("no account: one KDF run on the dummy path, answered INVALID_CREDENTIALS")
  void unknownAccountRunsTheDummyKdf() {
    CountingProvider provider = new CountingProvider();
    PasswordHashingService hashing = pipeline(provider, NoLimitKdfExecutionLimiter.INSTANCE);

    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        ConstantCostCredentialCheck.verify(Optional.empty(), PASSWORD, hashing));

    assertEquals(PublicFailureType.INVALID_CREDENTIALS, failed.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_DUMMY_PATH, failed.internalAuditEventType());
    assertEquals(1, provider.verifications.get(), "the unknown account costs one KDF run");
  }

  @Test
  @DisplayName("a known account costs the same one KDF run - right or wrong password")
  void knownAccountRunsOneKdf() {
    CountingProvider provider = new CountingProvider();
    PasswordHashingService hashing = pipeline(provider, NoLimitKdfExecutionLimiter.INSTANCE);
    String stored = hashing.hash(PASSWORD).encodedHash();

    assertInstanceOf(CredentialVerificationResult.Verified.class,
        ConstantCostCredentialCheck.verify(Optional.of(stored), PASSWORD, hashing));
    assertEquals(1, provider.verifications.get());

    CredentialVerificationResult.Failed wrong = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        ConstantCostCredentialCheck.verify(Optional.of(stored), "wrong".toCharArray(), hashing));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, wrong.publicFailureType());
    assertEquals(2, provider.verifications.get());
  }

  @Test
  @DisplayName("a blank stored hash costs what an unknown account costs")
  void blankHashTakesTheDummyPath() {
    CountingProvider provider = new CountingProvider();
    PasswordHashingService hashing = pipeline(provider, NoLimitKdfExecutionLimiter.INSTANCE);

    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        ConstantCostCredentialCheck.verify(Optional.of("  "), PASSWORD, hashing));
    assertEquals(InternalAuditEventType.VERIFICATION_DUMMY_PATH, failed.internalAuditEventType());
    assertEquals(1, provider.verifications.get());
  }

  @Test
  @DisplayName("under load both paths answer TEMPORARILY_UNAVAILABLE - the outcome does not reveal the account")
  void shedVerificationLooksTheSame() {
    CountingProvider provider = new CountingProvider();
    PasswordHashingService working = pipeline(provider, NoLimitKdfExecutionLimiter.INSTANCE);
    String stored = working.hash(PASSWORD).encodedHash();
    PasswordHashingService saturated = pipeline(provider, new ExhaustedLimiter());

    CredentialVerificationResult unknown =
        ConstantCostCredentialCheck.verify(Optional.empty(), PASSWORD, saturated);
    CredentialVerificationResult known =
        ConstantCostCredentialCheck.verify(Optional.of(stored), PASSWORD, saturated);
    assertEquals(known, unknown);
    assertEquals(true, unknown.temporarilyUnavailable());
  }

  @Test
  @DisplayName("fail closed: a pipeline that answers the dummy path with Verified does not log anyone in")
  void dummyVerifiedIsRefused() {
    CountingProvider provider = new CountingProvider();
    PasswordHashingService real = pipeline(provider, NoLimitKdfExecutionLimiter.INSTANCE);
    CredentialVerificationResult.Verified verified = assertInstanceOf(
        CredentialVerificationResult.Verified.class,
        real.verify(PASSWORD, real.hash(PASSWORD).encodedHash()));
    PasswordHashingService broken = new PasswordHashingService() {
      @Override public PasswordHashResult hash(char[] password) {
        return real.hash(password);
      }

      @Override public CredentialVerificationResult verify(char[] password, String encodedHash) {
        return real.verify(password, encodedHash);
      }

      @Override public RehashDecision needsRehash(String encodedHash) {
        return real.needsRehash(encodedHash);
      }

      @Override public CredentialVerificationResult verifyAgainstNothing(char[] password) {
        return verified;
      }
    };

    CredentialVerificationResult.Failed failed = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        ConstantCostCredentialCheck.verify(Optional.empty(), PASSWORD, broken));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, failed.publicFailureType());
  }

  @Test
  @DisplayName("null arguments are refused")
  void nullsAreRefused() {
    PasswordHashingService hashing = pipeline(new CountingProvider(), NoLimitKdfExecutionLimiter.INSTANCE);
    assertThrows(NullPointerException.class,
        () -> ConstantCostCredentialCheck.verify(null, PASSWORD, hashing));
    assertThrows(NullPointerException.class,
        () -> ConstantCostCredentialCheck.verify(Optional.empty(), null, hashing));
    assertThrows(NullPointerException.class,
        () -> ConstantCostCredentialCheck.verify(Optional.empty(), PASSWORD, null));
  }
}
