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
package eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt;

import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BcryptPasswordHashProviderTest {

  /** Fast test policy: cost=4 (~milliseconds per call). */
  private static PasswordHashPolicy fastTestPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(BcryptParameterNames.COST, "4");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(BcryptParameterNames.COST, "4");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(BcryptParameterNames.COST, "6");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(BcryptParameterNames.ALGORITHM)
        .preferredProviderId(BcryptParameterNames.PROVIDER_ID)
        .defaultParameters(BcryptParameterNames.ALGORITHM, defaults)
        .minimumParameters(BcryptParameterNames.ALGORITHM, min)
        .maximumParameters(BcryptParameterNames.ALGORITHM, max)
        .build();
  }

  /** SecureRandom that always emits the same bytes. */
  private static final class FixedSecureRandom extends SecureRandom {
    private final byte[] fixed;

    FixedSecureRandom(byte[] fixed) {
      this.fixed = fixed.clone();
    }

    @Override
    public void nextBytes(byte[] bytes) {
      if (bytes.length != fixed.length) {
        throw new IllegalStateException(
            "expected " + fixed.length + " salt bytes, got " + bytes.length);
      }
      System.arraycopy(fixed, 0, bytes, 0, fixed.length);
    }
  }

  private final BcryptPasswordHashProvider provider = new BcryptPasswordHashProvider();

  @Test
  @DisplayName("hash + verify roundtrip matches on the same password")
  void roundtripMatches() {
    PasswordHashResult r = provider.hash(
        "hunter2".toCharArray(), fastTestPolicy(), Optional.empty());
    assertEquals(CredentialType.PASSWORD, r.credentialType());
    assertEquals(BcryptParameterNames.ALGORITHM, r.algorithm());
    assertEquals(BcryptParameterNames.PROVIDER_ID, r.providerId());

    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("hunter2".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Wrong password yields NotMatched without throwing")
  void wrongPasswordReturnsNotMatched() {
    PasswordHashResult r = provider.hash(
        "hunter2".toCharArray(), fastTestPolicy(), Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("hunter3".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Two hashes of the same password use different salts")
  void freshSaltPerHash() {
    PasswordHashPolicy policy = fastTestPolicy();
    PasswordHashResult a = provider.hash("hunter2".toCharArray(), policy, Optional.empty());
    PasswordHashResult b = provider.hash("hunter2".toCharArray(), policy, Optional.empty());
    assertNotEquals(a.encodedHash(), b.encodedHash());
  }

  @Test
  @DisplayName("Hash output uses the $pwh$ envelope format with bcrypt alg/prov")
  void outputUsesNewEnvelopeFormat() {
    PasswordHashResult r = provider.hash(
        "x".toCharArray(), fastTestPolicy(), Optional.empty());
    assertTrue(r.encodedHash().startsWith("$pwh$v=1$"));
    assertTrue(r.encodedHash().contains("$alg=bcrypt$"));
    assertTrue(r.encodedHash().contains("$prov=bcrypt-bc$"));
    assertTrue(r.encodedHash().contains("$p=c=4,"));
  }

  @Test
  @DisplayName("Deterministic salt produces a deterministic envelope")
  void deterministicEnvelope() {
    byte[] salt = new byte[BcryptParameterNames.SALT_BYTES];
    Arrays.fill(salt, (byte) 0x33);
    BcryptPasswordHashProvider deterministic = new BcryptPasswordHashProvider(
        PasswordHashCodec.DEFAULT, new FixedSecureRandom(salt));
    PasswordHashResult a = deterministic.hash("k".toCharArray(),
        fastTestPolicy(), Optional.empty());
    PasswordHashResult b = deterministic.hash("k".toCharArray(),
        fastTestPolicy(), Optional.empty());
    assertEquals(a.encodedHash(), b.encodedHash());
  }

  @Test
  @DisplayName("Boundary: password of exactly 71 UTF-8 bytes is accepted (71 + NUL terminator = 72)")
  void exactlySeventyOneBytesAccepted() {
    char[] pw = new char[BcryptParameterNames.MAX_TERMINATED_PASSWORD_BYTES];
    Arrays.fill(pw, 'a');
    PasswordHashResult r = provider.hash(pw.clone(), fastTestPolicy(), Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify(pw.clone(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Boundary: 72-byte password is rejected on hash - the terminator needs the last key byte (JS-SEC-133)")
  void seventyTwoBytesRejectedOnHash() {
    char[] pw = new char[72];
    Arrays.fill(pw, 'a');
    assertThrows(BcryptPasswordHashProvider.BcryptInputTooLongException.class,
        () -> provider.hash(pw, fastTestPolicy(), Optional.empty()));
  }

  @Test
  @DisplayName("Boundary: 73-byte password is rejected on hash, no silent truncation")
  void seventyThreeBytesRejectedOnHash() {
    char[] pw = new char[73];
    Arrays.fill(pw, 'a');
    assertThrows(BcryptPasswordHashProvider.BcryptInputTooLongException.class,
        () -> provider.hash(pw, fastTestPolicy(), Optional.empty()));
  }

  @Test
  @DisplayName("Boundary: 73-byte password on verify produces ProviderError, not NotMatched")
  void seventyThreeBytesRejectedOnVerify() {
    // First hash a short password so we have an envelope to verify against.
    PasswordHashResult r = provider.hash(
        "short".toCharArray(), fastTestPolicy(), Optional.empty());
    PasswordHashEnvelope env = PasswordHashCodec.DEFAULT
        .decode(r.encodedHash()).envelope();

    char[] tooLong = new char[73];
    Arrays.fill(tooLong, 'Q');
    ProviderVerificationResult result = provider.verify(
        tooLong, env, Optional.empty());
    ProviderVerificationResult.ProviderError err = assertInstanceOf(
        ProviderVerificationResult.ProviderError.class, result);
    assertFalse(err.message().contains("QQQ"),
        "provider error must not embed candidate password fragments");
  }

  @Test
  @DisplayName("Multi-byte characters count toward the UTF-8 byte limit")
  void multiByteCountsTowardLimit() {
    // ä is 2 bytes in UTF-8; 36 * 'ä' = 72 bytes > 71 (the terminator needs one).
    char[] pw = new char[36];
    Arrays.fill(pw, 'ä');
    assertThrows(BcryptPasswordHashProvider.BcryptInputTooLongException.class,
        () -> provider.hash(pw, fastTestPolicy(), Optional.empty()));
  }

  @Test
  @DisplayName("verify returns ProviderError on malformed parameters")
  void malformedParameters() {
    Map<String, String> bad = new LinkedHashMap<>();
    bad.put(BcryptParameterNames.COST, "nan");
    bad.put(BcryptParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        BcryptParameterNames.ALGORITHM, BcryptParameterNames.PROVIDER_ID,
        1, Optional.empty(), bad, "ZGVyaXZlZA==");
    assertInstanceOf(ProviderVerificationResult.ProviderError.class,
        provider.verify("x".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("verify returns ProviderError when stored salt has wrong length")
  void wrongSaltLength() {
    Map<String, String> bad = new LinkedHashMap<>();
    bad.put(BcryptParameterNames.COST, "4");
    bad.put(BcryptParameterNames.SALT, "AAAA"); // too short
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        BcryptParameterNames.ALGORITHM, BcryptParameterNames.PROVIDER_ID,
        1, Optional.empty(), bad, "ZGVyaXZlZA==");
    assertInstanceOf(ProviderVerificationResult.ProviderError.class,
        provider.verify("x".toCharArray(), env, Optional.empty()));
  }

  @Test
  @DisplayName("Provider identifies itself with the canonical id and algorithm")
  void identifiers() {
    assertEquals(BcryptParameterNames.PROVIDER_ID, provider.providerId());
    assertEquals(BcryptParameterNames.ALGORITHM, provider.algorithm());
    assertTrue(provider.supports(provider.providerId(), provider.algorithm()));
  }

  @Test
  @DisplayName("verify rejects an over-ceiling cost parameter before computing (R02)")
  void verifyRejectsOverCeilingCostBeforeComputing() {
    Map<String, String> tampered = new LinkedHashMap<>();
    // cost = 31 is far above MAX_COST (16). bcrypt runs 2^cost rounds, so without
    // the guard this would monopolise a worker thread. It must be rejected BEFORE
    // computing — the test returning promptly is the proof. The salt is a valid
    // 16-byte value so the guard, not the salt-length check, is what fires.
    tampered.put(BcryptParameterNames.COST, "31");
    tampered.put(BcryptParameterNames.SALT, "AAAAAAAAAAAAAAAAAAAAAA==");
    PasswordHashEnvelope env = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        BcryptParameterNames.ALGORITHM, BcryptParameterNames.PROVIDER_ID,
        1, Optional.empty(), tampered, "ZGVyaXZlZA==");
    ProviderVerificationResult result = provider.verify(
        "x".toCharArray(), env, Optional.empty());
    ProviderVerificationResult.ProviderError error = assertInstanceOf(
        ProviderVerificationResult.ProviderError.class, result);
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
        error.internalAuditEventType());
    assertTrue(error.message().contains("exceed safe limits"));
    // Note: the lower bound is intentionally NOT enforced — roundtripMatches()
    // already verifies a cost-4 hash (below the MIN_COST=10 policy floor) as
    // Matched, proving a legitimately weaker legacy hash still verifies.
  }
}
