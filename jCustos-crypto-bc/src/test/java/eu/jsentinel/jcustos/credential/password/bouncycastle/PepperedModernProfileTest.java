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
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.DefaultPasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterValidator;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idPasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationContext;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pepper.FilePepperService;
import eu.jsentinel.jcustos.credential.password.pepper.InMemoryPepperService;
import eu.jsentinel.jcustos.credential.password.pepper.KeyStorePepperService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * The modern profile with a pepper (00.84.00): {@link BouncyCastleHashingServices#modern(
 * PasswordHashPolicy, eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter,
 * PepperService)} and {@link BouncyCastleHashingServices#modern(PepperService)} pepper Argon2id
 * with keys from a PKCS12 store or from key files. Keys are generated per test into a temporary
 * directory; no key material is committed. No mocks: the real Argon2id provider, recorded by a
 * hand-written wrapper where the test has to see which derivations ran.
 */
@DisplayName("Peppered modern profile - Argon2id with KeyStore and file pepper sources")
class PepperedModernProfileTest {

  private static final char[] PASSWORD = "Correct-Horse-Battery-7".toCharArray();
  private static final char[] STORE_PASSWORD = "synthetic-store-password-2".toCharArray();
  private static final SecureRandom RANDOM = new SecureRandom();

  @TempDir
  Path dir;

  private static byte[] key() {
    byte[] key = new byte[PepperReference.MIN_KEY_BYTES];
    RANDOM.nextBytes(key);
    return key;
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

  private static PasswordHashingService peppered(PepperService pepper) {
    return BouncyCastleHashingServices.modern(
        fastArgon2idPolicy(), NoLimitKdfExecutionLimiter.INSTANCE, pepper);
  }

  private static void ownerOnly(Path file) throws IOException {
    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }
  }

  /** A PKCS12 file as keytool writes it, restricted to its owner. */
  private Path pkcs12(String name, Map<String, byte[]> keysByAlias)
      throws GeneralSecurityException, IOException {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    for (Map.Entry<String, byte[]> entry : keysByAlias.entrySet()) {
      store.setEntry(entry.getKey(),
          new KeyStore.SecretKeyEntry(new SecretKeySpec(entry.getValue(), "HmacSHA256")),
          new KeyStore.PasswordProtection(STORE_PASSWORD));
    }
    Path file = dir.resolve(name);
    try (OutputStream out = Files.newOutputStream(file)) {
      store.store(out, STORE_PASSWORD);
    }
    ownerOnly(file);
    return file;
  }

  private Path keyFile(Path directory, String keyId, byte[] key) throws IOException {
    Path file = directory.resolve(keyId);
    Files.writeString(file, Base64.getEncoder().encodeToString(key) + "\n",
        StandardCharsets.US_ASCII);
    ownerOnly(file);
    return file;
  }

  private static String pepperKeyIdOf(String encodedHash) {
    return PasswordHashCodec.DEFAULT.decode(encodedHash).envelope().pepperKeyId().orElseThrow();
  }

  @Test
  @DisplayName("PKCS12 pepper: Argon2id round trip, and the pepper really takes part")
  void roundTripWithKeyStorePepper() throws Exception {
    byte[] key = key();
    KeyStorePepperService pepper = KeyStorePepperService
        .fromPkcs12(pkcs12("pepper.p12", Map.of("pepper-2026", key)), STORE_PASSWORD)
        .activeAlias("pepper-2026")
        .load();
    PasswordHashingService hashing = peppered(pepper);

    PasswordHashResult hashed = hashing.hash(PASSWORD);
    assertEquals(Argon2idParameterNames.ALGORITHM, hashed.algorithm());
    assertEquals("pepper-2026", pepperKeyIdOf(hashed.encodedHash()),
        "the envelope names the pepper key, never the key itself");
    CredentialVerificationResult.Verified verified = assertInstanceOf(
        CredentialVerificationResult.Verified.class, hashing.verify(PASSWORD, hashed.encodedHash()));
    assertEquals(Optional.of("pepper-2026"), verified.pepperKeyId());
    assertSame(RehashDecision.NotRequired.INSTANCE, hashing.needsRehash(hashed.encodedHash()));
    CredentialVerificationResult.Failed wrong = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        hashing.verify("Correct-Horse-Battery-8".toCharArray(), hashed.encodedHash()));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH, wrong.internalAuditEventType());

    // Without the pepper the stored hash is useless, and another key under the same id
    // does not match: the HMAC after Argon2id really used the loaded key.
    CredentialVerificationResult.Failed unpeppered = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        BouncyCastleHashingServices.modern(fastArgon2idPolicy(), NoLimitKdfExecutionLimiter.INSTANCE)
            .verify(PASSWORD, hashed.encodedHash()));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY,
        unpeppered.internalAuditEventType());
    CredentialVerificationResult.Failed otherKey = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        peppered(InMemoryPepperService.withActiveKey("pepper-2026", key()))
            .verify(PASSWORD, hashed.encodedHash()));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH,
        otherKey.internalAuditEventType());
    CredentialVerificationResult.Verified sameKeyInMemory = assertInstanceOf(
        CredentialVerificationResult.Verified.class,
        peppered(InMemoryPepperService.withActiveKey("pepper-2026", key))
            .verify(PASSWORD, hashed.encodedHash()));
    assertEquals(Optional.of("pepper-2026"), sameKeyInMemory.pepperKeyId());
  }

  @Test
  @DisplayName("file pepper: Argon2id round trip through modern(pepper) with the reference policy")
  void roundTripWithFilePepperAndReferencePolicy() throws Exception {
    byte[] key = key();
    keyFile(dir, "pepper-2026", key);
    FilePepperService pepper = FilePepperService.fromDirectory(dir)
        .activeKeyId("pepper-2026")
        .load();

    PasswordHashingService hashing = BouncyCastleHashingServices.modern(pepper);
    PasswordHashResult hashed = hashing.hash(PASSWORD);

    assertEquals(Argon2idParameterNames.ALGORITHM, hashed.algorithm());
    assertEquals("pepper-2026", pepperKeyIdOf(hashed.encodedHash()));
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        hashing.verify(PASSWORD, hashed.encodedHash()));
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        BouncyCastleHashingServices.modern(BouncyCastleHashingServices.modernPolicy(),
                NoLimitKdfExecutionLimiter.INSTANCE, InMemoryPepperService.withActiveKey(
                    "pepper-2026", key))
            .verify(PASSWORD, hashed.encodedHash()),
        "the file's key is the key the hash was peppered with");
  }

  @Test
  @DisplayName("rotation: the retired key still verifies, needsRehash reports PEPPER_KEY_ROTATED")
  void rotation() throws Exception {
    byte[] key2025 = key();
    byte[] key2026 = key();
    PasswordHashingService before = peppered(KeyStorePepperService
        .fromPkcs12(pkcs12("2025.p12", Map.of("pepper-2025", key2025)), STORE_PASSWORD)
        .activeAlias("pepper-2025")
        .load());
    String historical = before.hash(PASSWORD).encodedHash();
    assertEquals("pepper-2025", pepperKeyIdOf(historical));

    Map<String, byte[]> both = new LinkedHashMap<>();
    both.put("pepper-2026", key2026);
    both.put("pepper-2025", key2025);
    PasswordHashingService rotating = peppered(KeyStorePepperService
        .fromPkcs12(pkcs12("rotating.p12", both), STORE_PASSWORD)
        .activeAlias("pepper-2026")
        .retiredAlias("pepper-2025")
        .load());

    CredentialVerificationResult.Verified verified = assertInstanceOf(
        CredentialVerificationResult.Verified.class, rotating.verify(PASSWORD, historical));
    assertEquals(Optional.of("pepper-2025"), verified.pepperKeyId());
    RehashDecision.Required required = assertInstanceOf(
        RehashDecision.Required.class, rotating.needsRehash(historical));
    assertEquals(RehashReason.PEPPER_KEY_ROTATED, required.reason());

    String rehashed = rotating.hash(PASSWORD).encodedHash();
    assertEquals("pepper-2026", pepperKeyIdOf(rehashed), "a rehash is peppered with the active key");
    assertSame(RehashDecision.NotRequired.INSTANCE, rotating.needsRehash(rehashed));

    // The same rotation from key files: the retired file verifies the old hash.
    Path secrets = Files.createDirectory(dir.resolve("secrets"));
    keyFile(secrets, "pepper-2026", key2026);
    keyFile(secrets, "pepper-2025", key2025);
    PasswordHashingService fromFiles = peppered(FilePepperService.fromDirectory(secrets)
        .activeKeyId("pepper-2026")
        .retiredKeyId("pepper-2025")
        .load());
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        fromFiles.verify(PASSWORD, historical));
    assertEquals(RehashReason.PEPPER_KEY_ROTATED,
        assertInstanceOf(RehashDecision.Required.class, fromFiles.needsRehash(historical)).reason());
  }

  /** Delegates to the real Argon2id provider and records each verified envelope. */
  private static final class RecordingArgon2idProvider implements PasswordHashProvider {
    private final PasswordHashProvider delegate = new Argon2idPasswordHashProvider();
    private final List<PasswordHashEnvelope> verified =
        Collections.synchronizedList(new ArrayList<>());

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

    @Override public ProviderVerificationResult verify(char[] password,
                                                       PasswordHashEnvelope envelope,
                                                       Optional<PepperReference> pepper) {
      verified.add(envelope);
      return delegate.verify(password, envelope, pepper);
    }
  }

  /** Delegates to the real dummy service and records the context of each dummy run. */
  private static final class RecordingDummyService implements DummyVerificationService {
    private final DummyVerificationService delegate;
    private final List<DummyVerificationContext> contexts =
        Collections.synchronizedList(new ArrayList<>());

    RecordingDummyService(DummyVerificationService delegate) {
      this.delegate = delegate;
    }

    @Override public void runDummyKdf(char[] password, DummyVerificationContext context) {
      contexts.add(context);
      delegate.runDummyKdf(password, context);
    }
  }

  @Test
  @DisplayName("a key id the source does not know takes the dummy path: one Argon2id run, same answer")
  void unknownKeyIdRunsTheDummyPath() throws Exception {
    // a hash peppered with a key that the verifying source no longer holds
    String retired = peppered(InMemoryPepperService.withActiveKey("pepper-2024", key()))
        .hash(PASSWORD).encodedHash();
    keyFile(dir, "pepper-2026", key());
    FilePepperService pepper = FilePepperService.fromDirectory(dir)
        .activeKeyId("pepper-2026")
        .load();

    // the pipeline BouncyCastleHashingServices.modern(policy, limiter, pepper) builds, with
    // recording wrappers around the real provider and the real dummy service
    RecordingArgon2idProvider provider = new RecordingArgon2idProvider();
    PasswordHashPolicy policy = fastArgon2idPolicy();
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(List.of(provider));
    RecordingDummyService dummy = new RecordingDummyService(
        new DefaultDummyVerificationService(registry, policy, PasswordHashCodec.DEFAULT));
    PasswordHashingService hashing = new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(new PasswordHashParameterValidatorRegistry(
            List.of(new Argon2idParameterValidator()))),
        registry,
        pepper,
        policy,
        new RehashDecisionEngine(),
        NoLimitKdfExecutionLimiter.INSTANCE,
        dummy);
    String current = hashing.hash(PASSWORD).encodedHash();

    CredentialVerificationResult.Failed unknown = assertInstanceOf(
        CredentialVerificationResult.Failed.class, hashing.verify(PASSWORD, retired));

    assertEquals(PublicFailureType.INVALID_CREDENTIALS, unknown.publicFailureType(),
        "the caller sees the answer of a wrong password");
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY,
        unknown.internalAuditEventType());
    assertEquals(List.of(DummyVerificationContext.PEPPER_KEY_UNKNOWN), dummy.contexts,
        "no early return: the unknown key id runs the dummy KDF");
    assertEquals(1, provider.verified.size(), "exactly one Argon2id derivation ran");
    PasswordHashEnvelope dummyEnvelope = provider.verified.get(0);
    assertNotEquals(PasswordHashCodec.DEFAULT.decode(retired).envelope().innerHash(),
        dummyEnvelope.innerHash(),
        "the run derived against the dummy envelope, not against the stored hash");

    provider.verified.clear();
    assertInstanceOf(CredentialVerificationResult.Verified.class, hashing.verify(PASSWORD, current));
    assertEquals(1, provider.verified.size());
    assertEquals(costParameters(provider.verified.get(0)), costParameters(dummyEnvelope),
        "the dummy derivation costs what a real verification costs");
    assertEquals(List.of(DummyVerificationContext.PEPPER_KEY_UNKNOWN), dummy.contexts,
        "a known key id does not run the dummy path");
  }

  /** Iterations, memory, parallelism and length - everything but the salt. */
  private static Map<String, String> costParameters(PasswordHashEnvelope envelope) {
    Map<String, String> cost = new LinkedHashMap<>(envelope.parameters());
    cost.remove(Argon2idParameterNames.SALT);
    assertEquals(4, cost.size(), "t, m, p and l: " + cost);
    return cost;
  }
}
