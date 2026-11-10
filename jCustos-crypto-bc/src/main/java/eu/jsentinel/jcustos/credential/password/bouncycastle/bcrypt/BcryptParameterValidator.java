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

import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashValidationException;

import java.util.Base64;
import java.util.Map;

/**
 * Bounds the bcrypt envelope parameters before any KDF call.
 *
 * <p>Enforces the cost-factor min/max, verifies the salt is exactly
 * {@value BcryptParameterNames#SALT_BYTES} bytes after base64 decoding
 * (CWE-20) and accepts the framing marker
 * {@link BcryptParameterNames#TERMINATOR} only when it is absent (legacy
 * hash) or carries the one supported value (JS-SEC-133). bcrypt's input
 * limit on the password itself is checked by the provider at hash/verify
 * time, not here, because it applies to the supplied password rather
 * than to a stored parameter.</p>
 */
public final class BcryptParameterValidator implements PasswordHashParameterValidator {

  @Override
  public String algorithm() {
    return BcryptParameterNames.ALGORITHM;
  }

  @Override
  public void validate(
      Map<String, String> parameters,
      Map<String, String> minimum,
      Map<String, String> maximum) {
    requireInRange(BcryptParameterNames.COST,
        requireInt(parameters, BcryptParameterNames.COST),
        minimum, maximum);

    String saltBase64 = parameters.get(BcryptParameterNames.SALT);
    if (saltBase64 == null || saltBase64.isEmpty()) {
      throw new PasswordHashValidationException(
          "missing bcrypt salt parameter");
    }
    byte[] salt;
    try {
      salt = Base64.getDecoder().decode(saltBase64);
    } catch (IllegalArgumentException e) {
      throw new PasswordHashValidationException(
          "bcrypt salt parameter is not valid base64");
    }
    if (salt.length != BcryptParameterNames.SALT_BYTES) {
      throw new PasswordHashValidationException(
          "bcrypt salt must be exactly "
              + BcryptParameterNames.SALT_BYTES + " bytes");
    }

    // JS-SEC-133 (CWE-327): the framing marker is either absent (legacy hash,
    // verified without the terminator and then rehashed) or names the one
    // supported framing. Anything else is a malformed or tampered envelope and
    // must not reach the KDF under a guessed interpretation.
    String terminator = parameters.get(BcryptParameterNames.TERMINATOR);
    if (terminator != null
        && !BcryptParameterNames.TERMINATOR_NUL.equals(terminator)) {
      throw new PasswordHashValidationException(
          "bcrypt terminator parameter has an unsupported value");
    }
  }

  private static int requireInt(Map<String, String> map, String key) {
    String raw = map.get(key);
    if (raw == null) {
      throw new PasswordHashValidationException(
          "missing bcrypt parameter: " + key);
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new PasswordHashValidationException(
          "bcrypt parameter is not an integer: " + key);
    }
  }

  private static void requireInRange(
      String key, int value,
      Map<String, String> minimum, Map<String, String> maximum) {
    Integer min = parseBoundary(minimum.get(key), key);
    Integer max = parseBoundary(maximum.get(key), key);
    if (min == null || max == null) {
      throw new PasswordHashValidationException(
          "policy is missing bounds for bcrypt parameter: " + key);
    }
    if (value < min) {
      throw new PasswordHashValidationException(
          "bcrypt parameter below minimum: " + key);
    }
    if (value > max) {
      throw new PasswordHashValidationException(
          "bcrypt parameter above maximum: " + key);
    }
  }

  private static Integer parseBoundary(String raw, String key) {
    if (raw == null) {
      return null;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new PasswordHashValidationException(
          "policy bound for bcrypt parameter is not an integer: " + key);
    }
  }
}
