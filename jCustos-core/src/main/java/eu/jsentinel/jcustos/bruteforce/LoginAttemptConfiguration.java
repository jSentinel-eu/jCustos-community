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
package eu.jsentinel.jcustos.bruteforce;

import java.time.Duration;
import java.util.Objects;

/**
 * Tunable thresholds for {@link InMemoryLoginAttemptPolicy} and any
 * other {@link LoginAttemptPolicy} that wants the same vocabulary.
 * <p>
 * The lockout escalates exponentially: the first breach of
 * {@code failureThreshold} locks for {@code initialLockout}, the next
 * for {@code initialLockout × 2}, then {@code × 4}, and so on, capped
 * at {@code maxLockout}. The {@code window} bounds the rolling failure
 * count: failures older than {@code window} drop out of the count.
 * <p>
 * The record shape is stable. The counter on the client address alone
 * (JS-SEC-062) and the bound on concurrent credential checks (JS-SEC-063)
 * live in {@link LoginAttemptLimits}, which wraps this configuration as
 * {@link LoginAttemptLimits#perAccount()}.
 *
 * @param failureThreshold  failures within {@code window} that trigger a lockout
 * @param window            rolling window for failure counting
 * @param initialLockout    duration of the first lockout
 * @param maxLockout        cap for the progressive backoff
 */
public record LoginAttemptConfiguration(
    int failureThreshold,
    Duration window,
    Duration initialLockout,
    Duration maxLockout
) {

  public LoginAttemptConfiguration {
    if (failureThreshold < 1) {
      throw new IllegalArgumentException("failureThreshold must be >= 1");
    }
    Objects.requireNonNull(window, "window");
    Objects.requireNonNull(initialLockout, "initialLockout");
    Objects.requireNonNull(maxLockout, "maxLockout");
    if (window.isNegative() || window.isZero()) {
      throw new IllegalArgumentException("window must be positive");
    }
    if (initialLockout.isNegative() || initialLockout.isZero()) {
      throw new IllegalArgumentException("initialLockout must be positive");
    }
    if (maxLockout.compareTo(initialLockout) < 0) {
      throw new IllegalArgumentException("maxLockout must be >= initialLockout");
    }
  }

  /**
   * Defaults for normal end-user logins:
   * 5 failures / 15 min window / 15 min initial lockout / 4 h cap.
   */
  public static LoginAttemptConfiguration defaults() {
    return new LoginAttemptConfiguration(
        5, Duration.ofMinutes(15), Duration.ofMinutes(15), Duration.ofHours(4));
  }

  /**
   * Strict defaults intended for the bootstrap-admin endpoint:
   * 3 failures / 1 h window / 1 h initial lockout / 24 h cap.
   * <p>
   * The bootstrap endpoint hands out the very first administrator
   * account; a successful guess gives full control. The threshold sits
   * deliberately below the normal-login defaults.
   */
  public static LoginAttemptConfiguration strictBootstrap() {
    return new LoginAttemptConfiguration(
        3, Duration.ofHours(1), Duration.ofHours(1), Duration.ofHours(24));
  }
}
