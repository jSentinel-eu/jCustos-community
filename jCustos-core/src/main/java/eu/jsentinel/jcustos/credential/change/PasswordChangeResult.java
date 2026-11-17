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
package eu.jsentinel.jcustos.credential.change;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.input.PasswordInputViolation;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleDecision;

import java.util.Objects;

/**
 * Outcome of {@link PasswordChangeService#change}.
 *
 * <p>Sealed so adapters pattern-match exhaustively. Every failure
 * variant collapses to a generic public response at the adapter
 * boundary; the differentiated structural reason stays in audit
 * (CWE-203 / CWE-209).</p>
 *
 * <p>Since 00.84.00 the type has the variants {@link VerificationUnavailable}
 * and {@link ResetRequired}; an exhaustive {@code switch} over the result
 * needs a branch for each.</p>
 */
public sealed interface PasswordChangeResult
    permits PasswordChangeResult.Succeeded,
            PasswordChangeResult.CurrentPasswordRejected,
            PasswordChangeResult.VerificationUnavailable,
            PasswordChangeResult.NewPasswordRejected,
            PasswordChangeResult.Blocked,
            PasswordChangeResult.ResetRequired,
            PasswordChangeResult.Conflict,
            PasswordChangeResult.NotFound {

  /**
   * Password successfully changed. {@code sessionDecision} is the
   * recommended action for the calling adapter.
   */
  record Succeeded(SessionHandlingDecision sessionDecision)
      implements PasswordChangeResult {

    public Succeeded {
      Objects.requireNonNull(sessionDecision, "sessionDecision");
    }
  }

  /**
   * Re-authentication failed — the supplied current password does not
   * verify (CWE-620). The store is untouched.
   */
  record CurrentPasswordRejected() implements PasswordChangeResult {
    public static final CurrentPasswordRejected INSTANCE = new CurrentPasswordRejected();
  }

  /**
   * The current password could not be checked right now - the verification
   * was shed under load (JS-SEC-126, CWE-703). This says nothing about the
   * password: the store is untouched, and the adapter answers "try again
   * later" (HTTP 503 or 429). It must not count a failed attempt and must not
   * audit a rejected password for it.
   *
   * <p>The same answer stands for a new password that could not be checked
   * against the compromised-password list under
   * {@link eu.jsentinel.jcustos.credential.compromised.CheckFailurePolicy#BLOCK}
   * ({@link PasswordChangeService#withCompromisedPasswordCheck}): the change
   * is refused, but the password is not reported as listed.</p>
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  record VerificationUnavailable() implements PasswordChangeResult {
    public static final VerificationUnavailable INSTANCE = new VerificationUnavailable();
  }

  /**
   * The new password violated the input policy (length, control chars,
   * etc.) and was rejected before hashing. Since 00.84.00 the violation is
   * {@link PasswordInputViolation#COMPROMISED} when the configured
   * compromised-password check lists the password; the check runs before the
   * current password is verified, so this result is returned whatever the
   * current password is.
   */
  record NewPasswordRejected(PasswordInputViolation violation)
      implements PasswordChangeResult {

    public NewPasswordRejected {
      Objects.requireNonNull(violation, "violation");
    }
  }

  /**
   * The current lifecycle status forbids credential changes (e.g.
   * {@code DISABLED}, {@code COMPROMISED}).
   */
  record Blocked(CredentialLifecycleDecision decision)
      implements PasswordChangeResult {

    public Blocked {
      Objects.requireNonNull(decision, "decision");
    }
  }

  /**
   * The credential still holds a secret that was declared compromised
   * ({@link eu.jsentinel.jcustos.credential.store.CredentialRecord#secretRotationRequired()}),
   * typically after {@code COMPROMISED -> MUST_CHANGE} (JS-SEC-161, CWE-620,
   * CWE-640). Knowing that secret proves nothing - whoever obtained the leak
   * knows it too - so it cannot authorise its own replacement: only the reset
   * flow, which proves possession of the account's recovery channel, writes the
   * new secret. The check runs before the current password is verified, so the
   * result says nothing about the password. The store is untouched; the adapter
   * answers generically, may offer the reset, and must not count a failed
   * attempt for it.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  record ResetRequired() implements PasswordChangeResult {
    public static final ResetRequired INSTANCE = new ResetRequired();
  }

  /**
   * A concurrent password change won the compare-and-swap race. The
   * caller may safely retry (CWE-362).
   */
  record Conflict() implements PasswordChangeResult {
    public static final Conflict INSTANCE = new Conflict();
  }

  /**
   * No credential exists under the supplied username.
   */
  record NotFound() implements PasswordChangeResult {
    public static final NotFound INSTANCE = new NotFound();
  }
}
