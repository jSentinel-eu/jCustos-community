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
package eu.jsentinel.jcustos.credential.password.pepper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Applies the optional post-KDF pepper as
 * {@code HMAC-SHA-256(pepperKey, kdfOutput)}.
 *
 * <p>The construction is the one the Konzept §11 recommends: a stored
 * hash on its own is useless to an attacker who does not also exfiltrate
 * the pepper key. The key never travels with the password database.</p>
 *
 * <p>When the supplied {@link PepperReference} is absent, the KDF output
 * is returned verbatim — the pepper application is a pure no-op so the
 * envelope shape stays the same.</p>
 */
public final class PepperApplicator {

  private static final String HMAC_ALG = "HmacSHA256";

  private PepperApplicator() {
  }

  /**
   * Returns {@code HMAC-SHA-256(pepper.key, kdfOutput)} when
   * {@code pepper} is present, otherwise a copy of the KDF output.
   *
   * <p>The supplied {@code kdfOutput} array is <em>not</em> zeroed
   * here; the caller still owns it.</p>
   */
  public static byte[] apply(byte[] kdfOutput, Optional<PepperReference> pepper) {
    Objects.requireNonNull(kdfOutput, "kdfOutput");
    Objects.requireNonNull(pepper, "pepper");
    if (pepper.isEmpty()) {
      return kdfOutput.clone();
    }
    PepperReference ref = pepper.get();
    byte[] keyBytes = ref.copyKey();
    try {
      Mac mac;
      try {
        mac = Mac.getInstance(HMAC_ALG);
      } catch (NoSuchAlgorithmException e) {
        // HmacSHA256 is mandatory in every conformant JCA provider;
        // refusing to substitute a fallback (CWE-693).
        throw new PepperApplicationException(
            "HmacSHA256 unavailable in the current JCA provider");
      }
      mac.init(new SecretKeySpec(keyBytes, HMAC_ALG));
      return mac.doFinal(kdfOutput);
    } catch (java.security.InvalidKeyException e) {
      throw new PepperApplicationException("pepper key rejected by HMAC");
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /**
   * Generates a fresh 32-byte pepper key from {@link SecureRandom}.
   * Helper for tests and bootstrap tools — never auto-rotate keys at
   * runtime through this method: a key that exists only in the process is
   * lost at the next restart, and every hash it peppered with it.
   */
  public static byte[] generateKey() {
    byte[] key = new byte[PepperReference.MIN_KEY_BYTES];
    new SecureRandom().nextBytes(key);
    return key;
  }

  /**
   * Control-flow exception for pepper-application failures. Always
   * caught at the provider boundary and surfaced as
   * {@code ProviderError}.
   */
  public static final class PepperApplicationException extends RuntimeException {
    public PepperApplicationException(String message) {
      super(message);
    }
  }
}
