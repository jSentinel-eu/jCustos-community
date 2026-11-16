/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import eu.jsentinel.jcustos.bootstrap.MinimumLengthPasswordPolicy;
import eu.jsentinel.jcustos.bootstrap.PasswordPolicy;

import java.util.OptionalInt;

/**
 * The first administrator's password policy of the hardening layer
 * (JS-SEC-134; CWE-521): the minimum length of the base layer plus
 * {@link PasswordPreflight} - local blocklist and HIBP range query. Until
 * 00.84.00 the preflight ran for passwords set in the role administration
 * only, and the most privileged account accepted {@code password} or
 * {@code 12345678}.
 *
 * <p>Registered via
 * {@code META-INF/services/eu.jsentinel.jcustos.bootstrap.PasswordPolicy};
 * the persistence layer's {@code BootstrapWiring.passwordPolicy()} picks it
 * up for the first-administrator setup.
 */
public final class PreflightPasswordPolicy implements PasswordPolicy {

  /** Rejection text; never names the list that matched (CWE-209). */
  public static final String REJECTED =
      "Password rejected: this password is on a known-bad list. Choose another.";

  /** Minimum password length, as in the base layer. */
  public static final int MIN_LENGTH = 8;

  private final PasswordPolicy length = new MinimumLengthPasswordPolicy(MIN_LENGTH);

  @Override
  public PasswordPolicyResult validate(char[] password) {
    PasswordPolicyResult lengthResult = length.validate(password);
    if (!lengthResult.valid()) {
      return lengthResult;
    }
    return PasswordPreflight.isAcceptable(new String(password))
        ? PasswordPolicyResult.ok()
        : PasswordPolicyResult.violation(REJECTED);
  }

  @Override
  public OptionalInt minLength() {
    return length.minLength();
  }
}
