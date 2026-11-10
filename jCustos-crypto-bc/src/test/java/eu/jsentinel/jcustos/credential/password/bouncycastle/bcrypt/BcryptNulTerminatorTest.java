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

import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.password.bouncycastle.BouncyCastleHashingServices;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for JS-SEC-133 (CWE-327, CWE-521): the bcrypt provider
 * handed the raw UTF-8 bytes to the generator, without the terminating NUL
 * byte of standard bcrypt, so a periodic password was equivalent to its
 * shortest period.
 *
 * <p>The legacy envelopes below were written by the provider as it stood
 * before the fix (jCustos-crypto-bc 00.84.00-SNAPSHOT of 2026-10-26) and
 * are kept verbatim: they are the proof that existing hashes keep
 * verifying.</p>
 */
@DisplayName("JS-SEC-133 — bcrypt NUL terminator, legacy envelopes and reference vectors")
class BcryptNulTerminatorTest {

  /** Pre-fix hash of {@code hunter2} at cost 4. */
  private static final String LEGACY_HUNTER2_COST_4 =
      "$pwh$v=1$ct=PASSWORD$alg=bcrypt$prov=bcrypt-bc$pol=1"
          + "$p=c=4,s=izRiMIkMeD2W3ZDu6hxBtA==$h=2EVSPbW0t6q1TBcaReixzFyH1YYUxPws";

  /** Pre-fix hash of {@code abcabcabcabc} at cost 4. */
  private static final String LEGACY_PERIODIC_COST_4 =
      "$pwh$v=1$ct=PASSWORD$alg=bcrypt$prov=bcrypt-bc$pol=1"
          + "$p=c=4,s=qIEoEcgZHEkAWlbGQkwUcA==$h=/VFoXlXVjZFeC/d1C/ZAxVe0vO78Vt4A";

  /** Pre-fix hash of {@code hunter2} at the reference cost 12. */
  private static final String LEGACY_HUNTER2_COST_12 =
      "$pwh$v=1$ct=PASSWORD$alg=bcrypt$prov=bcrypt-bc$pol=1"
          + "$p=c=12,s=rM7+9RBU23R8VStvsYSrLA==$h=y3H4+WHocY73+yWOrQugFdcDod2xX08l";

  /** Pre-fix hash of 72 times {@code a} at cost 4 - the old upper bound. */
  private static final String LEGACY_72_BYTES_COST_4 =
      "$pwh$v=1$ct=PASSWORD$alg=bcrypt$prov=bcrypt-bc$pol=1"
          + "$p=c=4,s=2g2YAcs8kU/gwqtiTtVTsQ==$h=NSalzQDgZC47DnISlUNOqTeYlqOWkiHJ";

  private static final String BCRYPT_BASE64 =
      "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  private final BcryptPasswordHashProvider provider = new BcryptPasswordHashProvider();

  // ── the finding ────────────────────────────────────────────────────

  @Test
  @DisplayName("A periodic password no longer verifies with its shortest period")
  void periodicPasswordIsNotEquivalentToItsPeriod() {
    String[][] cases = {
        {"abcabcabcabc", "abc"},
        {"abcabcabcabc", "abcabc"},
        {"Sommer2026!Sommer2026!", "Sommer2026!"},
        {"1212121212121212", "12"},
        {"aaaaaaaaaaaaaaaa", "a"},
    };
    for (String[] c : cases) {
      PasswordHashEnvelope stored = hashToEnvelope(provider, c[0], fastPolicy());
      assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
          provider.verify(c[1].toCharArray(), stored, Optional.empty()),
          "'" + c[1] + "' must not verify against the hash of '" + c[0] + "'");
      assertSame(ProviderVerificationResult.Matched.INSTANCE,
          provider.verify(c[0].toCharArray(), stored, Optional.empty()),
          "the password itself must still verify");
    }
  }

  @Test
  @DisplayName("Through the hashing service: hash(abcabcabcabc), verify(abc) fails")
  void periodicPasswordFailsThroughTheService() {
    PasswordHashingService service = BouncyCastleHashingServices.modern(fastPolicy());
    PasswordHashResult stored = service.hash("abcabcabcabc".toCharArray());
    assertInstanceOf(CredentialVerificationResult.Failed.class,
        service.verify("abc".toCharArray(), stored.encodedHash()));
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("abcabcabcabc".toCharArray(), stored.encodedHash()));
  }

  @Test
  @DisplayName("A new hash records the framing as term=1 in the envelope")
  void newHashRecordsTheTerminator() {
    PasswordHashResult result = provider.hash(
        "hunter2".toCharArray(), fastPolicy(), Optional.empty());
    assertEquals(BcryptParameterNames.TERMINATOR_NUL,
        result.parameters().get(BcryptParameterNames.TERMINATOR));
    assertTrue(result.encodedHash().contains(",term=1$h="),
        "stored form must carry the marker; got: " + result.encodedHash());
    PasswordHashEnvelope decoded = PasswordHashCodec.DEFAULT
        .decode(result.encodedHash()).envelope();
    assertEquals("1", decoded.parameters().get("term"));
  }

  @Test
  @DisplayName("The terminator is written even when the policy defaults do not mention it")
  void terminatorDoesNotDependOnThePolicy() {
    Map<String, String> costOnly = new LinkedHashMap<>();
    costOnly.put(BcryptParameterNames.COST, "4");
    PasswordHashEnvelope stored = hashToEnvelope(provider, "abcabcabcabc", policy(costOnly));
    assertEquals("1", stored.parameters().get(BcryptParameterNames.TERMINATOR));
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("abc".toCharArray(), stored, Optional.empty()));
  }

  // ── legacy envelopes ───────────────────────────────────────────────

  @Test
  @DisplayName("A hash written before the fix still verifies, in legacy framing")
  void legacyHashStillVerifies() {
    PasswordHashEnvelope legacy = PasswordHashCodec.DEFAULT
        .decode(LEGACY_HUNTER2_COST_4).envelope();
    assertFalse(legacy.parameters().containsKey(BcryptParameterNames.TERMINATOR));
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("hunter2".toCharArray(), legacy, Optional.empty()));
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("hunter3".toCharArray(), legacy, Optional.empty()));
  }

  @Test
  @DisplayName("A legacy hash of a 72-byte password still verifies - the old upper bound stays valid for it")
  void legacyHashOfSeventyTwoBytesStillVerifies() {
    PasswordHashEnvelope legacy = PasswordHashCodec.DEFAULT
        .decode(LEGACY_72_BYTES_COST_4).envelope();
    char[] seventyTwo = new char[72];
    Arrays.fill(seventyTwo, 'a');
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify(seventyTwo, legacy, Optional.empty()));
  }

  @Test
  @DisplayName("Legacy framing is not applied to a new hash, nor the new framing to a legacy one")
  void framingIsDecidedByTheStoredHash() {
    // The legacy hash of the periodic password is the weak one: it documents what
    // legacy framing means, and why such a hash has to be rehashed.
    PasswordHashEnvelope legacy = PasswordHashCodec.DEFAULT
        .decode(LEGACY_PERIODIC_COST_4).envelope();
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("abcabcabcabc".toCharArray(), legacy, Optional.empty()));
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("abc".toCharArray(), legacy, Optional.empty()),
        "legacy framing: the period verifies - the reason for the rehash");

    // Marking the same legacy bytes as terminated must not verify: the framing
    // is part of what is checked.
    Map<String, String> relabelled = new LinkedHashMap<>(legacy.parameters());
    relabelled.put(BcryptParameterNames.TERMINATOR, BcryptParameterNames.TERMINATOR_NUL);
    PasswordHashEnvelope asTerminated = withParameters(legacy, relabelled);
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("abcabcabcabc".toCharArray(), asTerminated, Optional.empty()));

    // And stripping the marker from a new hash must not verify either.
    PasswordHashEnvelope fresh = hashToEnvelope(provider, "abcabcabcabc", fastPolicy());
    Map<String, String> stripped = new LinkedHashMap<>(fresh.parameters());
    stripped.remove(BcryptParameterNames.TERMINATOR);
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify("abcabcabcabc".toCharArray(),
            withParameters(fresh, stripped), Optional.empty()));
  }

  @Test
  @DisplayName("Under the reference policy a legacy hash verifies and reports PARAMETERS_OUTDATED; a new hash does not")
  void legacyHashSignalsRehashUnderTheReferencePolicy() {
    PasswordHashingService service =
        BouncyCastleHashingServices.modern(BcryptDefaults.referencePolicy());

    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("hunter2".toCharArray(), LEGACY_HUNTER2_COST_12));
    // Cost 12 is the reference default, so the missing terminator is the only
    // difference to the policy defaults.
    assertEquals(
        new RehashDecision.Required(RehashReason.PARAMETERS_OUTDATED, 1),
        service.needsRehash(LEGACY_HUNTER2_COST_12));

    PasswordHashResult rehashed = service.hash("hunter2".toCharArray());
    assertSame(RehashDecision.NotRequired.INSTANCE,
        service.needsRehash(rehashed.encodedHash()),
        "the rehashed envelope carries term=1 and is current");
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("hunter2".toCharArray(), rehashed.encodedHash()));
  }

  @Test
  @DisplayName("BcryptDefaults.defaultParameters() carries the terminator that drives the rehash signal")
  void defaultParametersCarryTheTerminator() {
    assertEquals(BcryptParameterNames.TERMINATOR_NUL,
        BcryptDefaults.defaultParameters().get(BcryptParameterNames.TERMINATOR));

    Map<String, String> defaults = BcryptDefaults.defaultParameters();
    defaults.put(BcryptParameterNames.COST, "4");
    PasswordHashingService service = BouncyCastleHashingServices.modern(policy(defaults));
    assertEquals(
        new RehashDecision.Required(RehashReason.PARAMETERS_OUTDATED, 1),
        service.needsRehash(LEGACY_HUNTER2_COST_4));
    assertSame(RehashDecision.NotRequired.INSTANCE,
        service.needsRehash(service.hash("hunter2".toCharArray()).encodedHash()));
  }

  // ── compatibility with standard bcrypt ─────────────────────────────

  @Test
  @DisplayName("New hashes equal OpenBSD bcrypt byte for byte (Bouncy Castle OpenBSDBCrypt as reference)")
  void newFormMatchesOpenBsdBcrypt() {
    char[] seventyOne = new char[BcryptParameterNames.MAX_TERMINATED_PASSWORD_BYTES];
    Arrays.fill(seventyOne, 'x');
    String[] passwords = {
        "abc",
        "abcabcabcabc",
        "a",
        "correct horse battery staple",
        "pässwörd-ünïcode-€-🔒",
        new String(seventyOne),
    };
    int salted = 0;
    for (String password : passwords) {
      byte[] salt = new byte[BcryptParameterNames.SALT_BYTES];
      Arrays.fill(salt, (byte) (0x21 + salted++));
      for (int cost : new int[] {4, 5}) {
        byte[] ours = deriveWithFixedSalt(password, salt, cost);
        String reference = OpenBSDBCrypt.generate("2b", password.toCharArray(), salt, cost);
        assertArrayEquals(openBsdHashBytes(reference), standardBytes(ours),
            "derived bytes differ from OpenBSD bcrypt for '" + password + "' at cost " + cost);
      }
    }
  }

  @Test
  @DisplayName("New hashes reproduce the published bcrypt test vectors")
  void newFormMatchesPublishedVectors() {
    // Vectors from the OpenBSD / John the Ripper bcrypt test suite.
    String[][] vectors = {
        {"U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
        {"U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"},
        {"U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"},
    };
    for (String[] vector : vectors) {
      String password = vector[0];
      String mcf = vector[1];
      assertTrue(OpenBSDBCrypt.checkPassword(mcf, password.toCharArray()),
          "the reference implementation must accept the published vector " + mcf);
      byte[] salt = Arrays.copyOf(decodeBcryptBase64(mcf.substring(7, 29)),
          BcryptParameterNames.SALT_BYTES);
      byte[] ours = deriveWithFixedSalt(password, salt, 5);
      assertArrayEquals(openBsdHashBytes(mcf), standardBytes(ours),
          "derived bytes differ from the published vector for '" + password + "'");
    }
  }

  // ── inputs the terminated framing cannot represent ─────────────────

  @Test
  @DisplayName("hash rejects a password that contains U+0000")
  void nulInsidePasswordRejectedOnHash() {
    for (String password : new String[] {"a\u0000a", "\u0000", "abc\u0000", "\u0000abc"}) {
      BcryptPasswordHashProvider.BcryptNulCharacterException e = assertThrows(
          BcryptPasswordHashProvider.BcryptNulCharacterException.class,
          () -> provider.hash(password.toCharArray(), fastPolicy(), Optional.empty()));
      assertFalse(e.getMessage().contains("abc"),
          "the message must not repeat the password");
    }
  }

  @Test
  @DisplayName("verify does not let 'a\\0a' pass for the hash of 'a'")
  void nulInsideCandidateDoesNotCollide() {
    PasswordHashEnvelope stored = hashToEnvelope(provider, "a", fastPolicy());
    for (String candidate : new String[] {"a\u0000a", "a\u0000", "a\u0000a\u0000a"}) {
      ProviderVerificationResult result = provider.verify(
          candidate.toCharArray(), stored, Optional.empty());
      ProviderVerificationResult.ProviderError error = assertInstanceOf(
          ProviderVerificationResult.ProviderError.class, result,
          "a candidate with U+0000 must never match");
      assertEquals(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          error.internalAuditEventType());
    }
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        provider.verify("a".toCharArray(), stored, Optional.empty()));
  }

  @Test
  @DisplayName("Through the hashing service a candidate with U+0000 fails")
  void nulInsideCandidateFailsThroughTheService() {
    PasswordHashingService service = BouncyCastleHashingServices.modern(fastPolicy());
    PasswordHashResult stored = service.hash("a".toCharArray());
    assertInstanceOf(CredentialVerificationResult.Failed.class,
        service.verify("a\u0000a".toCharArray(), stored.encodedHash()));
  }

  @Test
  @DisplayName("hash rejects the empty password with a controlled error")
  void emptyPasswordRejectedOnHash() {
    assertThrows(BcryptPasswordHashProvider.BcryptEmptyPasswordException.class,
        () -> provider.hash(new char[0], fastPolicy(), Optional.empty()));
    PasswordHashingService service = BouncyCastleHashingServices.modern(fastPolicy());
    assertThrows(BcryptPasswordHashProvider.BcryptEmptyPasswordException.class,
        () -> service.hash(new char[0]));
  }

  @Test
  @DisplayName("verify with an empty candidate is a plain mismatch")
  void emptyCandidateIsAMismatch() {
    PasswordHashEnvelope stored = hashToEnvelope(provider, "hunter2", fastPolicy());
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify(new char[0], stored, Optional.empty()));
  }

  // ── limits and malformed markers ───────────────────────────────────

  @Test
  @DisplayName("verify against a new hash rejects a 72-byte candidate, a legacy hash still accepts one")
  void seventyTwoByteCandidateDependsOnTheFraming() {
    char[] seventyTwo = new char[72];
    Arrays.fill(seventyTwo, 'a');
    PasswordHashEnvelope fresh = hashToEnvelope(provider, "short", fastPolicy());
    assertInstanceOf(ProviderVerificationResult.ProviderError.class,
        provider.verify(seventyTwo, fresh, Optional.empty()));

    PasswordHashEnvelope legacy = PasswordHashCodec.DEFAULT
        .decode(LEGACY_HUNTER2_COST_4).envelope();
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        provider.verify(seventyTwo, legacy, Optional.empty()));
  }

  @Test
  @DisplayName("verify refuses an envelope whose terminator marker is not 1")
  void unsupportedTerminatorValueRefusedOnVerify() {
    PasswordHashEnvelope fresh = hashToEnvelope(provider, "hunter2", fastPolicy());
    for (String unsupported : new String[] {"0", "2", "yes"}) {
      Map<String, String> tampered = new LinkedHashMap<>(fresh.parameters());
      tampered.put(BcryptParameterNames.TERMINATOR, unsupported);
      ProviderVerificationResult.ProviderError error = assertInstanceOf(
          ProviderVerificationResult.ProviderError.class,
          provider.verify("hunter2".toCharArray(),
              withParameters(fresh, tampered), Optional.empty()));
      assertEquals(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          error.internalAuditEventType());
    }
  }

  // ── helpers ────────────────────────────────────────────────────────

  private static PasswordHashPolicy fastPolicy() {
    Map<String, String> defaults = BcryptDefaults.defaultParameters();
    defaults.put(BcryptParameterNames.COST, "4");
    return policy(defaults);
  }

  private static PasswordHashPolicy policy(Map<String, String> defaults) {
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

  private static PasswordHashEnvelope hashToEnvelope(
      BcryptPasswordHashProvider provider, String password, PasswordHashPolicy policy) {
    PasswordHashResult result = provider.hash(
        password.toCharArray(), policy, Optional.empty());
    return PasswordHashCodec.DEFAULT.decode(result.encodedHash()).envelope();
  }

  private static PasswordHashEnvelope withParameters(
      PasswordHashEnvelope source, Map<String, String> parameters) {
    return new PasswordHashEnvelope(
        source.formatVersion(), source.credentialType(), source.algorithm(),
        source.providerId(), source.policyVersion(), source.pepperKeyId(),
        parameters, source.innerHash());
  }

  /** The 24 bytes the provider derives for {@code password} under a fixed salt. */
  private static byte[] deriveWithFixedSalt(String password, byte[] salt, int cost) {
    BcryptPasswordHashProvider deterministic = new BcryptPasswordHashProvider(
        PasswordHashCodec.DEFAULT, new FixedSecureRandom(salt));
    Map<String, String> defaults = BcryptDefaults.defaultParameters();
    defaults.put(BcryptParameterNames.COST, Integer.toString(cost));
    PasswordHashEnvelope envelope = hashToEnvelope(deterministic, password, policy(defaults));
    assertArrayEquals(salt, Base64.getDecoder().decode(
        envelope.parameters().get(BcryptParameterNames.SALT)));
    byte[] derived = Base64.getDecoder().decode(envelope.innerHash());
    assertEquals(BcryptParameterNames.DERIVED_BYTES, derived.length);
    return derived;
  }

  /**
   * Standard bcrypt publishes 23 of the 24 derived bytes; the modular crypt
   * format drops the last one.
   */
  private static byte[] standardBytes(byte[] derived) {
    return Arrays.copyOf(derived, BcryptParameterNames.DERIVED_BYTES - 1);
  }

  /** The 23 hash bytes of a {@code $2x$cc$<22 salt chars><31 hash chars>} string. */
  private static byte[] openBsdHashBytes(String mcf) {
    assertEquals(60, mcf.length(), "unexpected bcrypt string: " + mcf);
    byte[] decoded = decodeBcryptBase64(mcf.substring(29));
    assertEquals(BcryptParameterNames.DERIVED_BYTES - 1, decoded.length);
    return decoded;
  }

  /** Decoder for bcrypt's own base64 alphabet ({@code ./A-Za-z0-9}, no padding). */
  private static byte[] decodeBcryptBase64(String text) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int buffer = 0;
    int bits = 0;
    for (char c : text.toCharArray()) {
      int value = BCRYPT_BASE64.indexOf(c);
      assertTrue(value >= 0, "not a bcrypt base64 character: " + c);
      buffer = (buffer << 6) | value;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.write((buffer >> bits) & 0xff);
      }
    }
    return out.toByteArray();
  }

  /** SecureRandom that always emits the same salt. */
  private static final class FixedSecureRandom extends SecureRandom {
    private final byte[] fixed;

    FixedSecureRandom(byte[] fixed) {
      this.fixed = fixed.clone();
    }

    @Override
    public void nextBytes(byte[] bytes) {
      System.arraycopy(fixed, 0, bytes, 0, bytes.length);
    }
  }
}
