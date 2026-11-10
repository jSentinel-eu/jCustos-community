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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.credential.token.SelectorVerifierToken;

import java.util.Objects;

/**
 * Outcome of {@link PasswordResetService#issue}. Adapters must
 * surface the same generic public response for every variant —
 * leaking "user unknown" defeats the entire reset flow's
 * enumeration resistance (CWE-203).
 */
public sealed interface ResetTokenCreationResult
    permits ResetTokenCreationResult.Created,
            ResetTokenCreationResult.UnknownUser,
            ResetTokenCreationResult.Blocked {

  /**
   * Returned token. The wire form is
   * {@link SelectorVerifierToken#encode()}.
   */
  record Created(SelectorVerifierToken token)
      implements ResetTokenCreationResult {

    public Created {
      Objects.requireNonNull(token, "token");
    }
  }

  record UnknownUser() implements ResetTokenCreationResult {
    public static final UnknownUser INSTANCE = new UnknownUser();
  }

  /**
   * No token was issued although the request was well-formed: the
   * credential is {@code DISABLED}, or — when the service has a throttle
   * ({@link PasswordResetService#withAbuseDetection}) — the request was
   * refused by it (JS-SEC-121, CWE-799). A throttled request yields this
   * variant for unknown usernames as well, and it retires no open link.
   */
  record Blocked() implements ResetTokenCreationResult {
    public static final Blocked INSTANCE = new Blocked();
  }
}
