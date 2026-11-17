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
package eu.jsentinel.jcustos.credential.input;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Reason that input was rejected by the {@link PasswordInputValidator}.
 *
 * <p>The enum values are deliberately structural so audit sinks and
 * registration-form messages can specialise without ever embedding the
 * supplied password material (CWE-209 / CWE-522).</p>
 *
 * <p>Since 00.84.00 the enum has the constant {@link #COMPROMISED}; an
 * exhaustive {@code switch} over it needs a branch for it.</p>
 */
public enum PasswordInputViolation {
  TOO_SHORT,
  TOO_LONG,
  CONTAINS_CONTROL_CHARACTER,
  /** Password contains the user's username (case-insensitive). */
  CONTAINS_USERNAME,
  /** Password contains the local part of the user's email address. */
  CONTAINS_EMAIL_LOCAL_PART,
  /** Password contains the domain part of the user's email address. */
  CONTAINS_EMAIL_DOMAIN,
  /** Password contains an operator-supplied forbidden term. */
  CONTAINS_FORBIDDEN_TERM,
  /**
   * The configured
   * {@link eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker}
   * lists the password - a blocklist of common passwords or a breach corpus
   * (NIST SP 800-63B §5.1.1.2, CWE-521). Reported by
   * {@code PasswordChangeService} for a new password; the constant does not say
   * which list matched, and an adapter must not either (CWE-209).
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  COMPROMISED
}
