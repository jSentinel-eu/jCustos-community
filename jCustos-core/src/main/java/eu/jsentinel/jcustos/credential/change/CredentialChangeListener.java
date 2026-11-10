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

import java.time.Instant;

/**
 * Hook that the credential services call after a password was replaced
 * successfully — by {@link PasswordChangeService#change} or by
 * {@link eu.jsentinel.jcustos.credential.reset.PasswordResetService#consume}.
 *
 * <p>JS-SEC-128 (CWE-613): a new password must not extend the life of the
 * artefacts that were obtained with the old one. The services themselves only
 * know the credential store; what else has to die — sessions, remember-me
 * tokens, refresh tokens — is the listener's business.
 * {@link RevokingCredentialChangeListener} is the shipped implementation.</p>
 *
 * <p>The hook is optional: a service without a listener behaves as before
 * 00.84.00. It is called after the new hash is stored, so it cannot veto the
 * change; an exception it throws is logged by the calling service and does
 * not alter the result.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
@FunctionalInterface
public interface CredentialChangeListener {

  /** Why the credential changed. */
  enum Cause {
    /** The owner replaced the password and proved knowledge of the current one. */
    PASSWORD_CHANGED,
    /** A reset link was consumed. */
    PASSWORD_RESET
  }

  /**
   * Called once per successful change, after the new hash was stored.
   *
   * @param username the credential's username; non-blank
   * @param cause    which flow replaced the password; non-null
   * @param at       the instant the calling service stamped on the change; non-null
   */
  void credentialChanged(String username, Cause cause, Instant at);

  /**
   * @return a listener that does nothing — the default of both services
   */
  static CredentialChangeListener noop() {
    return (username, cause, at) -> { };
  }
}
