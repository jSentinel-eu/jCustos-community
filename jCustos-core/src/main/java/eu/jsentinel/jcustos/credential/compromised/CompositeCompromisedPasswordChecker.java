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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Asks several {@link CompromisedPasswordChecker}s in turn - the local
 * blocklist first, the online range query of {@code jCustos-credentials-hibp}
 * second - and combines their verdicts (since 00.84.00).
 *
 * <ul>
 *   <li><strong>First hit wins.</strong> The first
 *       {@link CompromisedPasswordResult.Pwned} is returned at once; the
 *       checkers after it are not asked. With the local list first, a common
 *       password never reaches the network.</li>
 *   <li><strong>A failure is decided by {@link #onFailure()}.</strong> A checker
 *       that answers {@link CompromisedPasswordResult.CheckFailed}, answers
 *       {@code null} or throws counts as failed; the remaining checkers are
 *       still asked, because a later hit outweighs an earlier failure. When
 *       none of them lists the password, {@link CheckFailurePolicy#BLOCK}
 *       returns the first failure, {@link CheckFailurePolicy#ALLOW} and
 *       {@link CheckFailurePolicy#WARN} return
 *       {@link CompromisedPasswordResult.Clean} - {@code WARN} logs
 *       {@code credential/compromised-check-failed} for every failed checker.
 *       A thrown exception is logged with its class name only.</li>
 * </ul>
 *
 * <p><strong>With the password services</strong>
 * ({@code PasswordChangeService}, {@code PasswordResetService}) the service's
 * {@link CompromisedPasswordPolicy#onFailure()} decides on every
 * {@code CheckFailed} the composite returns - give the composite the same
 * {@link CheckFailurePolicy}. A composite with {@code ALLOW} or {@code WARN}
 * has already counted the failure as clean, so a service policy of
 * {@code BLOCK} never sees it; {@link CompromisedPasswordScreen} logs
 * {@code credential/compromised-check-fails-open} for that combination.</p>
 *
 * <p>No checker's verdict, reason or exception message carries the password,
 * and this class adds none (CWE-532).</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class CompositeCompromisedPasswordChecker
    implements CompromisedPasswordChecker, HasLogger {

  private final List<CompromisedPasswordChecker> checkers;
  private final CheckFailurePolicy onFailure;

  private CompositeCompromisedPasswordChecker(
      List<CompromisedPasswordChecker> checkers, CheckFailurePolicy onFailure) {
    this.checkers = checkers;
    this.onFailure = onFailure;
  }

  /**
   * Combines {@code first} and {@code more}, asked in this order.
   *
   * @param onFailure how a failed checker counts; non-null
   * @param first     the checker asked first - the local blocklist; non-null
   * @param more      the checkers asked after it - the online service; no
   *                  {@code null} element
   * @return the composite
   */
  public static CompositeCompromisedPasswordChecker of(
      CheckFailurePolicy onFailure,
      CompromisedPasswordChecker first,
      CompromisedPasswordChecker... more) {
    Objects.requireNonNull(first, "first");
    Objects.requireNonNull(more, "more");
    List<CompromisedPasswordChecker> all = new ArrayList<>(1 + more.length);
    all.add(first);
    all.addAll(List.of(more));
    return of(onFailure, all);
  }

  /**
   * Combines {@code checkers}, asked in list order.
   *
   * @param onFailure how a failed checker counts; non-null
   * @param checkers  at least one checker, the local blocklist first; no
   *                  {@code null} element
   * @return the composite
   * @throws IllegalArgumentException if {@code checkers} is empty
   */
  public static CompositeCompromisedPasswordChecker of(
      CheckFailurePolicy onFailure,
      List<? extends CompromisedPasswordChecker> checkers) {
    Objects.requireNonNull(onFailure, "onFailure");
    Objects.requireNonNull(checkers, "checkers");
    List<CompromisedPasswordChecker> copy = List.copyOf(checkers);
    if (copy.isEmpty()) {
      throw new IllegalArgumentException("a composite needs at least one checker");
    }
    return new CompositeCompromisedPasswordChecker(copy, onFailure);
  }

  /**
   * @return how a failed checker counts in the combined verdict
   */
  public CheckFailurePolicy onFailure() {
    return onFailure;
  }

  @Override
  public CompromisedPasswordResult check(SecretValue password) {
    Objects.requireNonNull(password, "password");
    CompromisedPasswordResult.CheckFailed firstFailure = null;
    for (CompromisedPasswordChecker checker : checkers) {
      CompromisedPasswordResult verdict = ask(checker, password);
      if (verdict instanceof CompromisedPasswordResult.Pwned) {
        return verdict;
      }
      if (verdict instanceof CompromisedPasswordResult.CheckFailed failed) {
        if (firstFailure == null) {
          firstFailure = failed;
        }
        if (onFailure == CheckFailurePolicy.WARN) {
          logger().warn("credential/compromised-check-failed: {} gave no verdict ({}); the"
                  + " password counts as not listed (CheckFailurePolicy.WARN)",
              checker.getClass().getSimpleName(), failed.reason());
        } else {
          logger().debug("credential/compromised-check-failed: {} gave no verdict ({}); {}",
              checker.getClass().getSimpleName(), failed.reason(), onFailure);
        }
      }
    }
    if (firstFailure != null && onFailure == CheckFailurePolicy.BLOCK) {
      return firstFailure;
    }
    return CompromisedPasswordResult.Clean.INSTANCE;
  }

  /** A checker that throws or answers {@code null} gave no verdict. */
  private CompromisedPasswordResult ask(CompromisedPasswordChecker checker, SecretValue password) {
    try {
      CompromisedPasswordResult verdict = checker.check(password);
      return verdict != null ? verdict
          : new CompromisedPasswordResult.CheckFailed(
              CompromisedPasswordResult.FailureReason.UNKNOWN);
    } catch (RuntimeException failure) {
      // Class name only: the message of a third-party checker is not ours to
      // vouch for, and it might repeat its input (CWE-532).
      logger().warn("credential/compromised-checker-threw: {} threw {}; counted as a failed"
          + " check", checker.getClass().getSimpleName(), failure.getClass().getName());
      return new CompromisedPasswordResult.CheckFailed(
          CompromisedPasswordResult.FailureReason.UNKNOWN);
    }
  }
}
