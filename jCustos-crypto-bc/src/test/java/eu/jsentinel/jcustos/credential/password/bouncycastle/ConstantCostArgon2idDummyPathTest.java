/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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
package eu.jsentinel.jcustos.credential.password.bouncycastle;

import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.ConstantCostCredentialCheck;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.DefaultPasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterValidator;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idPasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * JS-SEC-064 (CWE-208, CWE-203): with the Bouncy Castle provider, the unknown-account path of
 * {@link ConstantCostCredentialCheck} runs a real Argon2id derivation - the same algorithm with
 * the same parameters as the verification of a stored hash. A hand-written wrapper around the
 * real {@link Argon2idPasswordHashProvider} records every verification and its envelope; no
 * mocks.
 */
@DisplayName("JS-SEC-064 - the unknown-account path runs Argon2id like a real verification")
class ConstantCostArgon2idDummyPathTest {

  private static final char[] PASSWORD = "Correct-Horse-Battery-1".toCharArray();

  /** Delegates to the real Argon2id provider and records each verified envelope. */
  private static final class RecordingArgon2idProvider implements PasswordHashProvider {
    private final PasswordHashProvider delegate = new Argon2idPasswordHashProvider();
    private final List<PasswordHashEnvelope> verified = Collections.synchronizedList(new ArrayList<>());

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
      verified.add(envelope);
      return delegate.verify(password, envelope, pepper);
    }
  }

  /** Argon2id with small parameters so that the test stays fast. */
  private static PasswordHashPolicy fastArgon2idPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Argon2idParameterNames.ITERATIONS, "1");
    defaults.put(Argon2idParameterNames.MEMORY_KIB, "8192");
    defaults.put(Argon2idParameterNames.PARALLELISM, "1");
    defaults.put(Argon2idParameterNames.HASH_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Argon2idParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Argon2idParameterNames.ITERATIONS, "5");
    max.put(Argon2idParameterNames.MEMORY_KIB, "65536");
    max.put(Argon2idParameterNames.PARALLELISM, "4");
    max.put(Argon2idParameterNames.HASH_LENGTH, "64");
    max.put(Argon2idParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM, defaults)
        .minimumParameters(Argon2idParameterNames.ALGORITHM, min)
        .maximumParameters(Argon2idParameterNames.ALGORITHM, max)
        .build();
  }

  @Test
  @DisplayName("unknown account and known account: one Argon2id run each, same algorithm and parameters")
  void dummyPathRunsArgon2id() {
    RecordingArgon2idProvider provider = new RecordingArgon2idProvider();
    PasswordHashPolicy policy = fastArgon2idPolicy();
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(List.of(provider));
    PasswordHashingService hashing = new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(new PasswordHashParameterValidatorRegistry(
            List.of(new Argon2idParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        policy,
        new RehashDecisionEngine(),
        NoLimitKdfExecutionLimiter.INSTANCE,
        new DefaultDummyVerificationService(registry, policy, PasswordHashCodec.DEFAULT));
    String stored = hashing.hash(PASSWORD).encodedHash();
    provider.verified.clear();

    CredentialVerificationResult.Failed unknown = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        ConstantCostCredentialCheck.verify(Optional.empty(), PASSWORD, hashing));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, unknown.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_DUMMY_PATH, unknown.internalAuditEventType());
    assertEquals(1, provider.verified.size(), "the unknown account ran one Argon2id derivation");

    CredentialVerificationResult.Failed wrong = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        ConstantCostCredentialCheck.verify(Optional.of(stored), "wrong".toCharArray(), hashing));
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, wrong.publicFailureType(),
        "the caller sees the same public answer for both");
    assertEquals(2, provider.verified.size());

    PasswordHashEnvelope dummyEnvelope = provider.verified.get(0);
    PasswordHashEnvelope realEnvelope = provider.verified.get(1);
    assertEquals(Argon2idParameterNames.ALGORITHM, dummyEnvelope.algorithm());
    assertEquals(realEnvelope.algorithm(), dummyEnvelope.algorithm());
    assertEquals(costParameters(realEnvelope), costParameters(dummyEnvelope),
        "the dummy derivation costs what the real one costs");

    assertInstanceOf(CredentialVerificationResult.Verified.class,
        ConstantCostCredentialCheck.verify(Optional.of(stored), PASSWORD, hashing));
  }

  /** Iterations, memory, parallelism and length - everything but the salt. */
  private static Map<String, String> costParameters(PasswordHashEnvelope envelope) {
    Map<String, String> cost = new LinkedHashMap<>(envelope.parameters());
    cost.remove(Argon2idParameterNames.SALT);
    assertEquals(4, cost.size(), "t, m, p and l: " + cost);
    return cost;
  }
}
