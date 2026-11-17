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
package eu.jsentinel.jcustos.credential.compromised;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.util.Objects;

/**
 * The compromised-password step for a password that is about to be set: asks
 * the {@link CompromisedPasswordChecker} and applies the
 * {@link CompromisedPasswordPolicy} to its verdict (NIST SP 800-63B §5.1.1.2,
 * since 00.84.00).
 *
 * <p>{@code PasswordChangeService} and {@code PasswordResetService} run it
 * after the structural check of the new password and before the first KDF
 * run; an adapter that sets a password elsewhere - a registration, the first
 * administrator - runs the same step.</p>
 *
 * <ul>
 *   <li>{@link CompromisedPasswordPolicy#checkOnSetOrChange()} {@code false},
 *       or the {@link NoOpCompromisedPasswordChecker}: the checker is not
 *       asked, the outcome is {@link Outcome#ACCEPTED}.</li>
 *   <li>{@link CompromisedPasswordResult.Pwned}: {@link Outcome#LISTED}.</li>
 *   <li>{@link CompromisedPasswordResult.CheckFailed}, a {@code null} verdict
 *       or a thrown exception: decided by
 *       {@link CompromisedPasswordPolicy#onFailure()} -
 *       {@link CheckFailurePolicy#BLOCK} answers {@link Outcome#UNAVAILABLE},
 *       {@link CheckFailurePolicy#WARN} and {@link CheckFailurePolicy#ALLOW}
 *       answer {@link Outcome#ACCEPTED}. {@code BLOCK} and {@code WARN} log
 *       {@code credential/compromised-check-failed} with the failure reason,
 *       {@code ALLOW} logs it at debug level.</li>
 * </ul>
 *
 * <p>Nothing is logged about the password itself, and a hit is not logged at
 * all: the outcome carries it (CWE-532).</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class CompromisedPasswordScreen implements HasLogger {

  /** What the step decided for the new password. */
  public enum Outcome {
    /**
     * The password may be set: not listed, not checked, or the check failed
     * under {@code ALLOW} or {@code WARN}.
     */
    ACCEPTED,
    /** The checker lists the password; it must not be set. */
    LISTED,
    /**
     * The check could not be carried out and the policy is {@code BLOCK}: the
     * password must not be set now. This says nothing about the password -
     * the answer is "try again later", not "choose another one".
     */
    UNAVAILABLE
  }

  private final CompromisedPasswordChecker checker;
  private final CompromisedPasswordPolicy policy;

  /**
   * @param checker the checker; non-null
   * @param policy  when it runs and how a failed check counts; non-null
   */
  public CompromisedPasswordScreen(CompromisedPasswordChecker checker,
                                   CompromisedPasswordPolicy policy) {
    this.checker = Objects.requireNonNull(checker, "checker");
    this.policy = Objects.requireNonNull(policy, "policy");
    if (checker instanceof CompositeCompromisedPasswordChecker composite
        && composite.onFailure() != CheckFailurePolicy.BLOCK
        && policy.onFailure() == CheckFailurePolicy.BLOCK
        && policy.checkOnSetOrChange()) {
      logger().warn("credential/compromised-check-fails-open: the composite checker counts a"
          + " failed check as clean ({}), so the BLOCK policy never sees one; build the"
          + " composite with CheckFailurePolicy.BLOCK", composite.onFailure());
    }
  }

  /**
   * @return the step that never asks a checker - the default of the password services
   */
  public static CompromisedPasswordScreen none() {
    return new CompromisedPasswordScreen(
        NoOpCompromisedPasswordChecker.INSTANCE, CompromisedPasswordPolicy.disabled());
  }

  /**
   * @return whether {@link #screen(SecretValue)} asks the checker at all
   */
  public boolean isActive() {
    return policy.checkOnSetOrChange()
        && !(checker instanceof NoOpCompromisedPasswordChecker);
  }

  /**
   * @return the checker
   */
  public CompromisedPasswordChecker checker() {
    return checker;
  }

  /**
   * @return the policy
   */
  public CompromisedPasswordPolicy policy() {
    return policy;
  }

  /**
   * Decides whether {@code newPassword} may be set.
   *
   * @param newPassword the proposed password; non-null, left intact
   * @return the outcome
   */
  public Outcome screen(SecretValue newPassword) {
    Objects.requireNonNull(newPassword, "newPassword");
    if (!isActive()) {
      return Outcome.ACCEPTED;
    }
    CompromisedPasswordResult verdict;
    try {
      verdict = checker.check(newPassword);
    } catch (RuntimeException failure) {
      // Class name only: the message of a third-party checker might repeat its input.
      logger().warn("credential/compromised-checker-threw: {} threw {}; counted as a failed"
          + " check", checker.getClass().getSimpleName(), failure.getClass().getName());
      verdict = null;
    }
    if (verdict instanceof CompromisedPasswordResult.Pwned) {
      return Outcome.LISTED;
    }
    if (verdict instanceof CompromisedPasswordResult.Clean) {
      return Outcome.ACCEPTED;
    }
    CompromisedPasswordResult.FailureReason reason =
        verdict instanceof CompromisedPasswordResult.CheckFailed failed
            ? failed.reason() : CompromisedPasswordResult.FailureReason.UNKNOWN;
    CheckFailurePolicy onFailure = policy.onFailure();
    if (onFailure == CheckFailurePolicy.ALLOW) {
      logger().debug("credential/compromised-check-failed: no verdict ({}); the password is"
          + " accepted (CheckFailurePolicy.ALLOW)", reason);
      return Outcome.ACCEPTED;
    }
    if (onFailure == CheckFailurePolicy.WARN) {
      logger().warn("credential/compromised-check-failed: no verdict ({}); the password is"
          + " accepted (CheckFailurePolicy.WARN)", reason);
      return Outcome.ACCEPTED;
    }
    logger().warn("credential/compromised-check-failed: no verdict ({}); the password is not"
        + " set (CheckFailurePolicy.BLOCK)", reason);
    return Outcome.UNAVAILABLE;
  }
}
