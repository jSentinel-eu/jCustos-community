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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.pepper.PepperApplicator;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import org.bouncycastle.crypto.generators.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * bcrypt password hash provider backed by BouncyCastle's low-level
 * {@link BCrypt} generator (Bcprov's lightweight API, no JCA
 * registration).
 *
 * <h2>Password framing (JS-SEC-133)</h2>
 * <p>Blowfish repeats its key cyclically over the key schedule. Standard
 * bcrypt therefore appends a terminating {@code 0x00} byte to the
 * password; without it {@code abc}, {@code abcabc} and
 * {@code abcabcabcabc} derive the same hash, and a periodic password is
 * only as strong as its shortest period (CWE-327, CWE-521). New hashes
 * carry the terminator and record it in the envelope as
 * {@link BcryptParameterNames#TERMINATOR}{@code =1}; with it the derived
 * bytes are those of OpenBSD bcrypt for the same password, salt and
 * cost.</p>
 *
 * <p>An envelope without that parameter is a <em>legacy</em> hash,
 * written before 00.84.00 from the raw UTF-8 bytes. It keeps verifying in
 * legacy framing, so no user is locked out, and is reported for a rehash
 * under every policy: through {@link #rehashHint(PasswordHashEnvelope)},
 * and through the policy defaults when they come from
 * {@link BcryptDefaults#defaultParameters()}; the weakness of a legacy
 * hash ends with that rehash.</p>
 *
 * <p>Two inputs are refused in the new framing: a password containing
 * U+0000, because {@code a} and {@code a\0a} would collide once the
 * terminator is appended, and the empty password.</p>
 *
 * <h2>Input limit</h2>
 * <p>bcrypt's underlying Blowfish key schedule operates on a fixed
 * 72-byte input. With the terminator, a password may occupy at most
 * {@value BcryptParameterNames#MAX_TERMINATED_PASSWORD_BYTES}&nbsp;bytes
 * in its UTF-8 encoding. Longer passwords are <em>not</em> silently
 * truncated by this provider; they are rejected with
 * {@link BcryptInputTooLongException} on {@code hash} and with a
 * {@link ProviderVerificationResult.ProviderError} on {@code verify}. The
 * Konzept §2.2 also forbids silent pre-hashing without a real pepper
 * service, so callers must enforce a policy-level length cap or wait for
 * the Phase-2 pepper-HMAC integration (Prompt 017).</p>
 *
 * <h2>Password shucking</h2>
 * <p>Pre-hashing a password before handing it to bcrypt without a
 * site-wide secret (pepper) lets attackers shuck the outer hash. This
 * provider therefore stays a plain bcrypt implementation in Phase 1b;
 * pre-hashing arrives bundled with the real pepper service in Phase 2.
 * (See §11 of the V9 Konzept.)</p>
 */
public final class BcryptPasswordHashProvider implements PasswordHashProvider {

  private final PasswordHashCodec codec;
  private final SecureRandom random;

  public BcryptPasswordHashProvider() {
    this(PasswordHashCodec.DEFAULT, new SecureRandom());
  }

  public BcryptPasswordHashProvider(
      PasswordHashCodec codec, SecureRandom random) {
    this.codec = Objects.requireNonNull(codec, "codec");
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public String providerId() {
    return BcryptParameterNames.PROVIDER_ID;
  }

  @Override
  public String algorithm() {
    return BcryptParameterNames.ALGORITHM;
  }

  /**
   * JS-SEC-133 (CWE-327, CWE-521): an envelope without
   * {@link BcryptParameterNames#TERMINATOR}{@code =1} is a legacy hash, derived from the raw
   * UTF-8 bytes, under which a periodic password verifies with its shortest period. It needs
   * a rehash whatever the policy's bcrypt defaults are. Until 00.84.00 the signal came from
   * the defaults only, and a policy that assembled them by hand without {@code term=1} never
   * rehashed a legacy hash.
   *
   * @param envelope parsed bcrypt envelope; non-null
   * @return {@link RehashReason#PARAMETERS_OUTDATED} for a legacy envelope, otherwise empty
   * @since 00.84.00
   */
  @Override
  public Optional<RehashReason> rehashHint(PasswordHashEnvelope envelope) {
    Objects.requireNonNull(envelope, "envelope");
    String terminator = envelope.parameters().get(BcryptParameterNames.TERMINATOR);
    return BcryptParameterNames.TERMINATOR_NUL.equals(terminator)
        ? Optional.empty()
        : Optional.of(RehashReason.PARAMETERS_OUTDATED);
  }

  @Override
  public PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<PepperReference> pepper) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(pepper, "pepper");

    // JS-SEC-133 (CWE-327): refuse what the NUL-terminated framing cannot
    // represent before any byte of the password is copied.
    requireRepresentable(password);
    byte[] pwBytes = toTerminatedUtf8(password);
    try {
      requireUnderBcryptLimit(pwBytes);
      Map<String, String> defaults = policy.defaultParameters(algorithm());
      int cost = intOrDefault(defaults, BcryptParameterNames.COST,
          BcryptDefaults.DEFAULT_COST);

      byte[] salt = new byte[BcryptParameterNames.SALT_BYTES];
      random.nextBytes(salt);
      byte[] derived = null;
      byte[] peppered = null;
      try {
        derived = BCrypt.generate(pwBytes, salt, cost);
        peppered = PepperApplicator.apply(derived, pepper);
        Map<String, String> params = new LinkedHashMap<>();
        params.put(BcryptParameterNames.COST, Integer.toString(cost));
        params.put(BcryptParameterNames.SALT,
            Base64.getEncoder().encodeToString(salt));
        // JS-SEC-133 (CWE-327): record the framing, so that verification can tell
        // this hash from a legacy one that was derived without the terminator.
        params.put(BcryptParameterNames.TERMINATOR,
            BcryptParameterNames.TERMINATOR_NUL);
        Optional<String> pepperKeyId = pepper.map(PepperReference::keyId);

        PasswordHashEnvelope envelope = new PasswordHashEnvelope(
            policy.preferredFormatVersion(),
            CredentialType.PASSWORD,
            algorithm(),
            providerId(),
            policy.policyVersion(),
            pepperKeyId,
            params,
            Base64.getEncoder().encodeToString(peppered));
        String encoded = codec.encode(envelope);

        return new PasswordHashResult(
            encoded,
            CredentialType.PASSWORD,
            envelope.formatVersion().wireValue(),
            algorithm(),
            providerId(),
            policy.policyVersion(),
            pepperKeyId,
            params);
      } finally {
        Arrays.fill(salt, (byte) 0);
        if (derived != null) {
          Arrays.fill(derived, (byte) 0);
        }
        if (peppered != null) {
          Arrays.fill(peppered, (byte) 0);
        }
      }
    } finally {
      Arrays.fill(pwBytes, (byte) 0);
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
    // JS-SEC-133 (CWE-327): absent = legacy framing (raw UTF-8 bytes), "1" = the
    // terminating NUL byte of standard bcrypt. Any other value is refused rather
    // than interpreted; the stored hash decides the framing, never the caller.
    String terminator = params.get(BcryptParameterNames.TERMINATOR);
    boolean terminated = terminator != null;
    if (terminated && !BcryptParameterNames.TERMINATOR_NUL.equals(terminator)) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt envelope terminator parameter is not supported");
    }
    int cost;
    byte[] salt;
    byte[] expectedDerived;
    try {
      cost = Integer.parseInt(
          Objects.requireNonNull(params.get(BcryptParameterNames.COST)));
      salt = Base64.getDecoder().decode(
          Objects.requireNonNull(params.get(BcryptParameterNames.SALT)));
      expectedDerived = Base64.getDecoder().decode(envelope.innerHash());
    } catch (NullPointerException | IllegalArgumentException e) {
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt envelope parameters are not parseable");
    }
    if (salt.length != BcryptParameterNames.SALT_BYTES) {
      Arrays.fill(salt, (byte) 0);
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt salt has unexpected length");
    }
    if (cost > BcryptDefaults.MAX_COST) {
      // R02: defence-in-depth — reject a cost above the hard ceiling BEFORE
      // computing. bcrypt runs 2^cost key-schedule rounds, so a tampered envelope
      // with cost=31 would monopolise a worker thread for an extreme duration
      // (CWE-400/770). The policy-driven validator only runs on the hash path,
      // not here. Mirrors the scrypt/argon2 R017 verify guards. The lower bound
      // is intentionally NOT enforced: a legitimately weaker legacy hash must
      // still verify (and then trigger a rehash) — and an out-of-range low/high
      // cost outside bcrypt's 4..31 range is already caught by the generator.
      Arrays.fill(salt, (byte) 0);
      return new ProviderVerificationResult.ProviderError(
          InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
          "bcrypt envelope cost parameters exceed safe limits");
    }

    // JS-SEC-133 (CWE-327): in the terminated framing U+0000 inside the candidate
    // would make it collide with the shorter password in front of it, so it is
    // refused before the KDF runs. A legacy envelope is verified exactly as it was
    // written - no terminator, no additional restriction - so that it keeps
    // verifying until it is rehashed.
    boolean unrepresentable = terminated && containsNul(password);
    byte[] pwBytes = unrepresentable
        ? new byte[0]
        : terminated ? toTerminatedUtf8(password) : toUtf8(password);
    byte[] candidate = null;
    byte[] peppered = null;
    try {
      if (unrepresentable) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
            "candidate password contains U+0000, which bcrypt cannot represent");
      }
      if (pwBytes.length > BcryptParameterNames.MAX_PASSWORD_BYTES) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS,
            "candidate password exceeds the bcrypt input limit");
      }
      try {
        candidate = BCrypt.generate(pwBytes, salt, cost);
      } catch (RuntimeException e) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
            "bcrypt generator rejected the parameters");
      }
      try {
        peppered = PepperApplicator.apply(candidate, pepper);
      } catch (PepperApplicator.PepperApplicationException e) {
        return new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
            e.getMessage());
      }
      return MessageDigest.isEqual(peppered, expectedDerived)
          ? ProviderVerificationResult.Matched.INSTANCE
          : ProviderVerificationResult.NotMatched.INSTANCE;
    } finally {
      Arrays.fill(pwBytes, (byte) 0);
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

  /**
   * Checks the terminated key - password bytes plus the terminator - against
   * bcrypt's 72-byte key, which leaves
   * {@value BcryptParameterNames#MAX_TERMINATED_PASSWORD_BYTES} bytes for the
   * password itself.
   */
  private static void requireUnderBcryptLimit(byte[] terminatedPwBytes) {
    if (terminatedPwBytes.length > BcryptParameterNames.MAX_PASSWORD_BYTES) {
      throw new BcryptInputTooLongException();
    }
  }

  /**
   * JS-SEC-133 (CWE-327): a password the NUL-terminated framing cannot
   * represent is a controlled error on the hash path. The empty password is
   * refused here rather than left to the generator, and U+0000 is refused
   * because the terminator would make {@code a} and {@code a\0a} one key.
   */
  private static void requireRepresentable(char[] password) {
    if (password.length == 0) {
      throw new BcryptEmptyPasswordException();
    }
    if (containsNul(password)) {
      throw new BcryptNulCharacterException();
    }
  }

  /**
   * UTF-8 never encodes any character other than U+0000 with a zero byte, so
   * looking at the characters is equivalent to looking at the encoded bytes.
   */
  private static boolean containsNul(char[] password) {
    boolean found = false;
    // No early exit: the scan time must not depend on where the character sits.
    for (char c : password) {
      found |= c == '\u0000';
    }
    return found;
  }

  private static byte[] toUtf8(char[] password) {
    return encodeUtf8(password, 0);
  }

  /**
   * JS-SEC-133 (CWE-327): the UTF-8 bytes of the password followed by the
   * single {@code 0x00} byte that standard bcrypt appends, cf.
   * {@code BCrypt.passwordToByteArray(char[])} in Bouncy Castle.
   */
  private static byte[] toTerminatedUtf8(char[] password) {
    return encodeUtf8(password, 1);
  }

  /** Encodes into an array with {@code trailingZeroBytes} zero bytes appended. */
  private static byte[] encodeUtf8(char[] password, int trailingZeroBytes) {
    java.nio.CharBuffer charBuffer = java.nio.CharBuffer.wrap(password);
    java.nio.ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
    int encoded = byteBuffer.remaining();
    byte[] out = new byte[encoded + trailingZeroBytes];
    byteBuffer.get(out, 0, encoded);
    if (byteBuffer.hasArray()) {
      Arrays.fill(byteBuffer.array(), (byte) 0);
    }
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

  /**
   * Control-flow signal that the supplied password exceeds bcrypt's
   * input limit: {@value BcryptParameterNames#MAX_TERMINATED_PASSWORD_BYTES}
   * UTF-8 bytes, because the terminating NUL byte occupies the last of
   * the 72 key bytes (JS-SEC-133). Surfaced to callers of
   * {@link #hash(char[], PasswordHashPolicy, java.util.Optional)} so
   * the bootstrap or registration path can reject overlong passwords
   * up front instead of silently truncating them.
   */
  public static final class BcryptInputTooLongException extends RuntimeException {
    public BcryptInputTooLongException() {
      super("password exceeds the bcrypt input limit of "
          + BcryptParameterNames.MAX_TERMINATED_PASSWORD_BYTES
          + " UTF-8 bytes (72 including the NUL terminator)");
    }
  }

  /**
   * Control-flow signal that
   * {@link #hash(char[], PasswordHashPolicy, java.util.Optional)} was
   * asked to hash the empty password. bcrypt has no meaningful key for
   * it, so the provider refuses it before the generator runs instead of
   * storing a hash that every empty input would match. JS-SEC-133.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final class BcryptEmptyPasswordException extends RuntimeException {
    public BcryptEmptyPasswordException() {
      super("bcrypt cannot hash an empty password");
    }
  }

  /**
   * Control-flow signal that the password handed to
   * {@link #hash(char[], PasswordHashPolicy, java.util.Optional)}
   * contains U+0000. bcrypt terminates its key with a NUL byte, so a
   * password with an embedded NUL would be equivalent to the shorter
   * password in front of it ({@code a} and {@code a\0a} derive the same
   * hash). The message never repeats any part of the password.
   * JS-SEC-133 (CWE-327).
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final class BcryptNulCharacterException extends RuntimeException {
    public BcryptNulCharacterException() {
      super("bcrypt cannot hash a password that contains U+0000");
    }
  }
}
