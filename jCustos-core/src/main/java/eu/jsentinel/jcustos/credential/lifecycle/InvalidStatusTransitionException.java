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
package eu.jsentinel.jcustos.credential.lifecycle;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;

import java.util.Objects;

/**
 * Thrown by {@link CredentialLifecycleService#transition} when the
 * requested transition is not part of the configured state machine, or -
 * since 00.84.00 - when it is, but the credential may not take it
 * ({@link #reason()}).
 * Messages describe only the states involved; they never carry the
 * username or credential payload (CWE-209).
 */
public final class InvalidStatusTransitionException extends RuntimeException {

  /**
   * Why a transition was refused.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public enum Reason {
    /** The pair of statuses is not part of the state machine. */
    NOT_IN_STATE_MACHINE,
    /**
     * The credential still holds the secret that was declared compromised;
     * only a password change or a consumed reset returns it to
     * {@link CredentialStatus#ACTIVE} (JS-SEC-161, CWE-284, CWE-620).
     */
    SECRET_ROTATION_REQUIRED,
    /**
     * The credential store does not keep the rotation proof, so the
     * knowledge that the credential was compromised would be lost on the way
     * out of {@link CredentialStatus#COMPROMISED}; only the reset leaves it
     * (JS-SEC-161).
     */
    ROTATION_NOT_RECORDED
  }

  private final CredentialStatus from;
  private final CredentialStatus to;
  private final Reason reason;

  public InvalidStatusTransitionException(
      CredentialStatus from, CredentialStatus to) {
    this(from, to, Reason.NOT_IN_STATE_MACHINE);
  }

  /**
   * @param from   the status the caller expected
   * @param to     the requested status
   * @param reason why the transition is refused; non-null
   * @since 00.84.00
   */
  public InvalidStatusTransitionException(
      CredentialStatus from, CredentialStatus to, Reason reason) {
    super(message(from, to, reason));
    this.from = from;
    this.to = to;
    this.reason = reason;
  }

  private static String message(CredentialStatus from, CredentialStatus to, Reason reason) {
    String pair = "transition " + Objects.requireNonNull(from)
        + " -> " + Objects.requireNonNull(to);
    return switch (Objects.requireNonNull(reason, "reason")) {
      case NOT_IN_STATE_MACHINE -> pair + " is not allowed";
      case SECRET_ROTATION_REQUIRED -> pair + " is refused: the credential still holds the"
          + " secret that was declared compromised; a password change or a reset must replace it"
          + " first";
      case ROTATION_NOT_RECORDED -> pair + " is refused: the credential store does not record the"
          + " rotation of a compromised secret (CredentialStore.recordsSecretRotation), so the"
          + " credential can leave COMPROMISED only through a reset";
    };
  }

  public CredentialStatus from() {
    return from;
  }

  public CredentialStatus to() {
    return to;
  }

  /**
   * @return why the transition was refused
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public Reason reason() {
    return reason;
  }
}
