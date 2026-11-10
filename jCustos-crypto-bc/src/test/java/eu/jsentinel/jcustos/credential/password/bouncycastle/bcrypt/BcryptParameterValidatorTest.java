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

import eu.jsentinel.jcustos.credential.password.policy.PasswordHashValidationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BcryptParameterValidatorTest {

  private final BcryptParameterValidator validator = new BcryptParameterValidator();
  private final Map<String, String> min = BcryptDefaults.minimumParameters();
  private final Map<String, String> max = BcryptDefaults.maximumParameters();

  private static String saltBase64(int length) {
    byte[] s = new byte[length];
    for (int i = 0; i < length; i++) s[i] = (byte) i;
    return Base64.getEncoder().encodeToString(s);
  }

  private Map<String, String> valid() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(BcryptParameterNames.COST,
        Integer.toString(BcryptDefaults.DEFAULT_COST));
    m.put(BcryptParameterNames.SALT,
        saltBase64(BcryptParameterNames.SALT_BYTES));
    return m;
  }

  @Test
  @DisplayName("Algorithm identifier matches the canonical name")
  void algorithmIdentifier() {
    assertEquals(BcryptParameterNames.ALGORITHM, validator.algorithm());
  }

  @Test
  @DisplayName("Reference parameters pass validation")
  void referenceParametersValid() {
    validator.validate(valid(), min, max);
  }

  @Test
  @DisplayName("Cost below the minimum is rejected")
  void costBelowMinimumRejected() {
    Map<String, String> params = valid();
    params.put(BcryptParameterNames.COST,
        Integer.toString(BcryptDefaults.MIN_COST - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Cost above the maximum is rejected")
  void costAboveMaximumRejected() {
    Map<String, String> params = valid();
    params.put(BcryptParameterNames.COST,
        Integer.toString(BcryptDefaults.MAX_COST + 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Salt of the wrong length is rejected")
  void wrongSaltLength() {
    Map<String, String> params = valid();
    params.put(BcryptParameterNames.SALT,
        saltBase64(BcryptParameterNames.SALT_BYTES - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Non-base64 salt is rejected")
  void nonBase64Salt() {
    Map<String, String> params = valid();
    params.put(BcryptParameterNames.SALT, "@@@@");
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Missing cost is rejected")
  void missingCost() {
    Map<String, String> params = valid();
    params.remove(BcryptParameterNames.COST);
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("JS-SEC-133: the terminator marker term=1 passes validation")
  void terminatorMarkerAccepted() {
    Map<String, String> params = valid();
    params.put(BcryptParameterNames.TERMINATOR, BcryptParameterNames.TERMINATOR_NUL);
    validator.validate(params, min, max);
  }

  @Test
  @DisplayName("JS-SEC-133: a legacy envelope without the terminator marker still passes validation")
  void legacyEnvelopeWithoutTerminatorAccepted() {
    Map<String, String> params = valid();
    assertFalse(params.containsKey(BcryptParameterNames.TERMINATOR));
    validator.validate(params, min, max);
  }

  @Test
  @DisplayName("JS-SEC-133: any terminator value other than 1 is rejected")
  void unsupportedTerminatorValueRejected() {
    for (String unsupported : new String[] {"0", "2", "true", "", " 1"}) {
      Map<String, String> params = valid();
      params.put(BcryptParameterNames.TERMINATOR, unsupported);
      assertThrows(PasswordHashValidationException.class,
          () -> validator.validate(params, min, max),
          "terminator value '" + unsupported + "' must not validate");
    }
  }

  @Test
  @DisplayName("Non-integer cost is rejected")
  void nonIntegerCost() {
    Map<String, String> params = valid();
    params.put(BcryptParameterNames.COST, "nope");
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }
}
