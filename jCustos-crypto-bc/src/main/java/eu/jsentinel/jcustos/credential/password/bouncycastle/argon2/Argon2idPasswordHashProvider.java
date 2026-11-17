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
package eu.jsentinel.jcustos.credential.password.bouncycastle.argon2;

import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.pepper.PepperApplicator;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.ResourceEstimate;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Argon2id password hash provider backed by BouncyCastle's low-level
 * {@link Argon2BytesGenerator}.
 *
 * <p>The provider sticks to BouncyCastle's <em>lightweight</em> API
 * (no JCA registration) so loading this module does not change the
 * global JCA provider order. Salt is drawn from a caller-supplied
 * {@link SecureRandom} for every {@code hash(...)} call; the constant-
 * time compare uses {@link MessageDigest#isEqual(byte[], byte[])}.</p>
 *
 * <p>When the pipeline resolves a pepper, the derived key is passed
 * through {@link PepperApplicator} (HMAC-SHA-256) and the key id is
 * recorded in the envelope; with {@code NoOpPepperService} the provider
 * receives {@link Optional#empty()} and stores the derived key as it is.</p>
 */
public final class Argon2idPasswordHashProvider implements PasswordHashProvider {

  private final PasswordHashCodec codec;
  private final SecureRandom random;

  public Argon2idPasswordHashProvider() {
    this(PasswordHashCodec.DEFAULT, new SecureRandom());
  }

  public Argon2idPasswordHashProvider(
      PasswordHashCodec codec, SecureRandom random) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public String providerId() {
    return Argon2idParameterNames.PROVIDER_ID;
  }

  @Override
  public String algorithm() {
    return Argon2idParameterNames.ALGORITHM;
  }

  @Override
  public PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<PepperReference> pepper) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(pepper, "pepper");

    Map<String, String> defaults = policy.defaultParameters(algorithm());
    int iterations = intOrDefault(defaults, Argon2idParameterNames.ITERATIONS,
        Argon2idDefaults.DEFAULT_ITERATIONS);
    int memoryKib = intOrDefault(defaults, Argon2idParameterNames.MEMORY_KIB,
        Argon2idDefaults.DEFAULT_MEMORY_KIB);
    int parallelism = intOrDefault(defaults, Argon2idParameterNames.PARALLELISM,
        Argon2idDefaults.DEFAULT_PARALLELISM);
    int hashLength = intOrDefault(defaults, Argon2idParameterNames.HASH_LENGTH,
        Argon2idDefaults.DEFAULT_HASH_LENGTH);

    byte[] salt = new byte[Argon2idDefaults.DEFAULT_SALT_LENGTH];
    random.nextBytes(salt);
    byte[] derived = null;
    byte[] peppered = null;
    try {
      derived = deriveKey(password, salt, iterations, memoryKib,
          parallelism, hashLength);
      peppered = PepperApplicator.apply(derived, pepper);

      Map<String, String> params = new LinkedHashMap<>();
      params.put(Argon2idParameterNames.ITERATIONS, Integer.toString(iterations));
      params.put(Argon2idParameterNames.MEMORY_KIB, Integer.toString(memoryKib));
      params.put(Argon2idParameterNames.PARALLELISM, Integer.toString(parallelism));
      params.put(Argon2idParameterNames.HASH_LENGTH, Integer.toString(hashLength));
      params.put(Argon2idParameterNames.SALT,
          Base64.getEncoder().encodeToString(salt));
      Optional<String> pepperKeyId = pepper.map(PepperReference::keyId);

      PasswordHashEnvelope envelope = new PasswordHashEnvelope(
          policy.preferredFormatVersion(),
          CredentialType.PASSWORD,
          algorithm(),
          providerId(),
          policy.policyVersion(),
          pepperKeyId,
          params,
          Base64.getEncoder().encodeToString(peppered)
      );
      String encoded = codec.encode(envelope);

      return new PasswordHashResult(
          encoded,
          CredentialType.PASSWORD,
          envelope.formatVersion().wireValue(),
          algorithm(),
          providerId(),
          policy.policyVersion(),
          pepperKeyId,
          params
      );
    } finally {
      Arrays.fill(salt, (byte) 0);
      if (derived != null) {
        Arrays.fill(derived, (byte) 0);
      }
      if (peppered != null) {
        Arrays.fill(peppered, (byte) 0);
      }
    }
  }

  @Override
  public ProviderVerificationResult verify(
      char[] password,
      PasswordHashEnvelope envelope,
      Optional<PepperReference> pepper) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(pepper, "pepper");

    Map<String, String> params = envelope.parameters();
    int iterations;
    int memoryKib;
    int parallelism;
    int hashLength;
    byte[] salt;
    byte[] expectedDerived;
    try {
      iterations = Integer.parseInt(
          Objects.requireNonNull(params.get(Argon2idParameterNames.ITERATIONS)));
      memoryKib = Integer.parseInt(
          Objects.requireNonNull(params.get(Argon2idParameterNames.MEMORY_KIB)));
      parallelism = Integer.parseInt(
          Objects.requireNonNull(params.get(Argon2idParameterNames.PARALLELISM)));
      hashLength = Integer.parseInt(
          Objects.requireNonNull(params.get(Argon2idParameterNames.HASH_LENGTH)));
      salt = Base64.getDecoder().decode(
          Objects.requireNonNull(params.get(Argon2idParameterNames.SALT)));
      expectedDerived = Base64.getDecoder().decode(envelope.innerHash());
    } catch (NullPointerException | IllegalArgumentException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "argon2id envelope parameters are not parseable");
    }

    byte[] candidate = null;
    byte[] peppered = null;
    try {
      // R017: defence-in-depth — reject cost parameters above the hard ceilings
      // BEFORE allocating, so a tampered/corrupt envelope (e.g. m=2_000_000 KiB)
      // cannot trigger a multi-GB allocation on the verify path (CWE-400/770).
      // The policy-driven *ParameterValidator only runs on the hash path, not here.
      if (iterations > Argon2idDefaults.MAX_ITERATIONS
          || memoryKib > Argon2idDefaults.MAX_MEMORY_KIB
          || parallelism > Argon2idDefaults.MAX_PARALLELISM
          || hashLength > Argon2idDefaults.MAX_HASH_LENGTH) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
            "argon2id envelope cost parameters exceed safe limits");
      }
      candidate = deriveKey(password, salt, iterations, memoryKib,
          parallelism, hashLength);
      peppered = PepperApplicator.apply(candidate, pepper);
      return MessageDigest.isEqual(peppered, expectedDerived)
          ? ProviderVerificationResult.Matched.INSTANCE
          : ProviderVerificationResult.NotMatched.INSTANCE;
    } catch (PepperApplicator.PepperApplicationException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
          e.getMessage());
    } catch (RuntimeException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
          "argon2id generator rejected the parameters");
    } finally {
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(expectedDerived, (byte) 0);
      if (candidate != null) {
        Arrays.fill(candidate, (byte) 0);
      }
      if (peppered != null) {
        Arrays.fill(peppered, (byte) 0);
      }
    }
  }

  @Override
  public ResourceEstimate resourceEstimate(Map<String, String> parameters) {
    Objects.requireNonNull(parameters, "parameters");
    int iterations = intOrDefault(parameters,
        Argon2idParameterNames.ITERATIONS, Argon2idDefaults.DEFAULT_ITERATIONS);
    int memoryKib = intOrDefault(parameters,
        Argon2idParameterNames.MEMORY_KIB, Argon2idDefaults.DEFAULT_MEMORY_KIB);
    int parallelism = intOrDefault(parameters,
        Argon2idParameterNames.PARALLELISM, Argon2idDefaults.DEFAULT_PARALLELISM);
    long memoryBytes = (long) memoryKib * 1024L;
    // Heuristic CPU estimate: 1 µs per KiB per iteration, divided by
    // available lanes. The estimate is intentionally coarse — its only
    // job is to feed budget logic in later phases.
    long cpuMicros =
        Math.max(1L, ((long) iterations * (long) memoryKib) / Math.max(1, parallelism));
    return new ResourceEstimate(cpuMicros, memoryBytes);
  }

  private static byte[] deriveKey(
      char[] password, byte[] salt,
      int iterations, int memoryKib, int parallelism, int hashLength) {
    Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withSalt(salt)
        .withIterations(iterations)
        .withMemoryAsKB(memoryKib)
        .withParallelism(parallelism)
        .build();
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(parameters);
    byte[] out = new byte[hashLength];
    generator.generateBytes(password, out);
    return out;
  }

  private static int intOrDefault(
      Map<String, String> map, String key, int fallback) {
    String raw = map.get(key);
    if (raw == null) {
      return fallback;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
