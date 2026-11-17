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
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.function.Function;

/**
 * Loads {@link LoginAttemptConfiguration} from system properties and
 * environment variables, with a caller-supplied default.
 *
 * <h2>Sources, in order of precedence</h2>
 * <ol>
 *   <li>System property (highest)</li>
 *   <li>Environment variable</li>
 *   <li>Caller-provided default (lowest)</li>
 * </ol>
 *
 * <h2>Keys</h2>
 * <table>
 *   <caption>Configuration keys (default scope = login endpoint)</caption>
 *   <tr><th>System property</th><th>Environment variable</th></tr>
 *   <tr><td>{@code security.login.attempts.threshold}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_THRESHOLD}</td></tr>
 *   <tr><td>{@code security.login.attempts.window}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_WINDOW}</td></tr>
 *   <tr><td>{@code security.login.attempts.initial-lockout}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_INITIAL_LOCKOUT}</td></tr>
 *   <tr><td>{@code security.login.attempts.max-lockout}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_MAX_LOCKOUT}</td></tr>
 * </table>
 *
 * <h2>Keys of {@link #loadLimits()} (since 00.84.00)</h2>
 * <table>
 *   <caption>Additional keys of the login endpoint (JS-SEC-062, JS-SEC-063)</caption>
 *   <tr><th>System property</th><th>Environment variable</th><th>Default</th></tr>
 *   <tr><td>{@code security.login.attempts.address.threshold}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_ADDRESS_THRESHOLD}</td>
 *       <td>not set - no address counter</td></tr>
 *   <tr><td>{@code security.login.attempts.address.window}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_ADDRESS_WINDOW}</td>
 *       <td>the account window</td></tr>
 *   <tr><td>{@code security.login.attempts.address.initial-lockout}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_ADDRESS_INITIAL_LOCKOUT}</td>
 *       <td>the account initial lockout</td></tr>
 *   <tr><td>{@code security.login.attempts.address.max-lockout}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_ADDRESS_MAX_LOCKOUT}</td>
 *       <td>the larger of the account maximum and the address initial lockout</td></tr>
 *   <tr><td>{@code security.login.attempts.max-concurrent-checks}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_MAX_CONCURRENT_CHECKS}</td>
 *       <td>{@code 0} - unbounded</td></tr>
 *   <tr><td>{@code security.login.attempts.gate-wait}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_GATE_WAIT}</td>
 *       <td>{@code PT0.25S}</td></tr>
 *   <tr><td>{@code security.login.attempts.gate-retry-after}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_GATE_RETRY_AFTER}</td>
 *       <td>{@code PT1S}</td></tr>
 * </table>
 *
 * <p>The address counter is switched on by its threshold. An address window or lockout without
 * a threshold is refused - it would look like a configured counter that does not exist.
 *
 * <p>Duration values are parsed as ISO-8601 (e.g. {@code PT5M},
 * {@code PT1H}). The {@link #forBootstrap()} variant uses
 * {@code security.bootstrap.attempts.*} prefixes so the bootstrap
 * endpoint can be tuned independently of the normal login endpoint.
 *
 * <p>Invalid values fail fast with {@link IllegalArgumentException}.
 */
public final class LoginAttemptConfigurationLoader {

  public static final String LOGIN_THRESHOLD_PROPERTY = "security.login.attempts.threshold";
  public static final String LOGIN_THRESHOLD_ENV = "SECURITY_LOGIN_ATTEMPTS_THRESHOLD";
  public static final String LOGIN_WINDOW_PROPERTY = "security.login.attempts.window";
  public static final String LOGIN_WINDOW_ENV = "SECURITY_LOGIN_ATTEMPTS_WINDOW";
  public static final String LOGIN_INITIAL_LOCKOUT_PROPERTY = "security.login.attempts.initial-lockout";
  public static final String LOGIN_INITIAL_LOCKOUT_ENV = "SECURITY_LOGIN_ATTEMPTS_INITIAL_LOCKOUT";
  public static final String LOGIN_MAX_LOCKOUT_PROPERTY = "security.login.attempts.max-lockout";
  public static final String LOGIN_MAX_LOCKOUT_ENV = "SECURITY_LOGIN_ATTEMPTS_MAX_LOCKOUT";

  public static final String BOOTSTRAP_THRESHOLD_PROPERTY = "security.bootstrap.attempts.threshold";
  public static final String BOOTSTRAP_THRESHOLD_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_THRESHOLD";
  public static final String BOOTSTRAP_WINDOW_PROPERTY = "security.bootstrap.attempts.window";
  public static final String BOOTSTRAP_WINDOW_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_WINDOW";
  public static final String BOOTSTRAP_INITIAL_LOCKOUT_PROPERTY = "security.bootstrap.attempts.initial-lockout";
  public static final String BOOTSTRAP_INITIAL_LOCKOUT_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_INITIAL_LOCKOUT";
  public static final String BOOTSTRAP_MAX_LOCKOUT_PROPERTY = "security.bootstrap.attempts.max-lockout";
  public static final String BOOTSTRAP_MAX_LOCKOUT_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_MAX_LOCKOUT";

  public static final String LOGIN_ADDRESS_THRESHOLD_PROPERTY = "security.login.attempts.address.threshold";
  public static final String LOGIN_ADDRESS_THRESHOLD_ENV = "SECURITY_LOGIN_ATTEMPTS_ADDRESS_THRESHOLD";
  public static final String LOGIN_ADDRESS_WINDOW_PROPERTY = "security.login.attempts.address.window";
  public static final String LOGIN_ADDRESS_WINDOW_ENV = "SECURITY_LOGIN_ATTEMPTS_ADDRESS_WINDOW";
  public static final String LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY =
      "security.login.attempts.address.initial-lockout";
  public static final String LOGIN_ADDRESS_INITIAL_LOCKOUT_ENV =
      "SECURITY_LOGIN_ATTEMPTS_ADDRESS_INITIAL_LOCKOUT";
  public static final String LOGIN_ADDRESS_MAX_LOCKOUT_PROPERTY =
      "security.login.attempts.address.max-lockout";
  public static final String LOGIN_ADDRESS_MAX_LOCKOUT_ENV = "SECURITY_LOGIN_ATTEMPTS_ADDRESS_MAX_LOCKOUT";
  public static final String LOGIN_MAX_CONCURRENT_CHECKS_PROPERTY =
      "security.login.attempts.max-concurrent-checks";
  public static final String LOGIN_MAX_CONCURRENT_CHECKS_ENV =
      "SECURITY_LOGIN_ATTEMPTS_MAX_CONCURRENT_CHECKS";
  public static final String LOGIN_GATE_WAIT_PROPERTY = "security.login.attempts.gate-wait";
  public static final String LOGIN_GATE_WAIT_ENV = "SECURITY_LOGIN_ATTEMPTS_GATE_WAIT";
  public static final String LOGIN_GATE_RETRY_AFTER_PROPERTY = "security.login.attempts.gate-retry-after";
  public static final String LOGIN_GATE_RETRY_AFTER_ENV = "SECURITY_LOGIN_ATTEMPTS_GATE_RETRY_AFTER";

  private final Function<String, String> sysprop;
  private final Function<String, String> env;

  /** Default loader reading from {@link System#getProperty} and {@link System#getenv}. */
  public LoginAttemptConfigurationLoader() {
    this(System::getProperty, System::getenv);
  }

  /**
   * Test seam: inject custom sources.
   *
   * @param sysprop function returning system-property values (typically
   *                {@link System#getProperty})
   * @param env     function returning environment-variable values
   *                (typically {@link System#getenv})
   */
  public LoginAttemptConfigurationLoader(
      Function<String, String> sysprop,
      Function<String, String> env) {
    this.sysprop = Objects.requireNonNull(sysprop, "sysprop");
    this.env = Objects.requireNonNull(env, "env");
  }

  /**
   * Loads configuration for the standard login endpoint, falling back to
   * {@link LoginAttemptConfiguration#defaults()} when no source supplies
   * a value.
   */
  public LoginAttemptConfiguration forLogin() {
    return load(
        LoginAttemptConfiguration.defaults(),
        LOGIN_THRESHOLD_PROPERTY, LOGIN_THRESHOLD_ENV,
        LOGIN_WINDOW_PROPERTY, LOGIN_WINDOW_ENV,
        LOGIN_INITIAL_LOCKOUT_PROPERTY, LOGIN_INITIAL_LOCKOUT_ENV,
        LOGIN_MAX_LOCKOUT_PROPERTY, LOGIN_MAX_LOCKOUT_ENV);
  }

  /**
   * Loads configuration for the bootstrap-admin endpoint, falling back
   * to {@link LoginAttemptConfiguration#strictBootstrap()} when no
   * source supplies a value.
   */
  public LoginAttemptConfiguration forBootstrap() {
    return load(
        LoginAttemptConfiguration.strictBootstrap(),
        BOOTSTRAP_THRESHOLD_PROPERTY, BOOTSTRAP_THRESHOLD_ENV,
        BOOTSTRAP_WINDOW_PROPERTY, BOOTSTRAP_WINDOW_ENV,
        BOOTSTRAP_INITIAL_LOCKOUT_PROPERTY, BOOTSTRAP_INITIAL_LOCKOUT_ENV,
        BOOTSTRAP_MAX_LOCKOUT_PROPERTY, BOOTSTRAP_MAX_LOCKOUT_ENV);
  }

  /**
   * Loads the complete limits of the standard login endpoint (JS-SEC-062, JS-SEC-063): the
   * account thresholds of {@link #forLogin()}, the address counter and the bound on concurrent
   * credential checks. Without any of the additional keys the result equals
   * {@code LoginAttemptLimits.of(forLogin())} - no address counter, no bound.
   *
   * @return the limits
   * @throws IllegalArgumentException when a value is invalid, or an address key other than the
   *                                  threshold is set without the threshold
   * @since 00.84.00
   */
  public LoginAttemptLimits loadLimits() {
    LoginAttemptConfiguration perAccount = forLogin();
    LoginAttemptLimits limits = LoginAttemptLimits.of(perAccount);

    String threshold = value(LOGIN_ADDRESS_THRESHOLD_PROPERTY, LOGIN_ADDRESS_THRESHOLD_ENV);
    boolean addressDetails = value(LOGIN_ADDRESS_WINDOW_PROPERTY, LOGIN_ADDRESS_WINDOW_ENV) != null
        || value(LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY, LOGIN_ADDRESS_INITIAL_LOCKOUT_ENV) != null
        || value(LOGIN_ADDRESS_MAX_LOCKOUT_PROPERTY, LOGIN_ADDRESS_MAX_LOCKOUT_ENV) != null;
    if (threshold == null && addressDetails) {
      // fail closed: a window without a threshold would look like a counter that does not exist
      throw new IllegalArgumentException("The per-address login limit needs "
          + LOGIN_ADDRESS_THRESHOLD_PROPERTY + " (or " + LOGIN_ADDRESS_THRESHOLD_ENV
          + "); the other address keys alone do not switch it on.");
    }
    if (threshold != null) {
      int addressThreshold = readThreshold(LOGIN_ADDRESS_THRESHOLD_PROPERTY,
          LOGIN_ADDRESS_THRESHOLD_ENV, perAccount.failureThreshold());
      Duration window = readDuration(LOGIN_ADDRESS_WINDOW_PROPERTY, LOGIN_ADDRESS_WINDOW_ENV,
          perAccount.window());
      Duration initial = readDuration(LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY,
          LOGIN_ADDRESS_INITIAL_LOCKOUT_ENV, perAccount.initialLockout());
      Duration defaultMax = perAccount.maxLockout().compareTo(initial) < 0
          ? initial
          : perAccount.maxLockout();
      Duration max = readDuration(LOGIN_ADDRESS_MAX_LOCKOUT_PROPERTY,
          LOGIN_ADDRESS_MAX_LOCKOUT_ENV, defaultMax);
      limits = limits.withAddressLimit(
          new LoginAttemptLimits.AddressLimit(addressThreshold, window, initial, max));
    }

    limits = limits.withMaxConcurrentCredentialChecks(readNonNegative(
        LOGIN_MAX_CONCURRENT_CHECKS_PROPERTY, LOGIN_MAX_CONCURRENT_CHECKS_ENV,
        LoginAttemptLimits.UNBOUNDED_CREDENTIAL_CHECKS));
    Duration gateWait = readNonNegativeDuration(LOGIN_GATE_WAIT_PROPERTY, LOGIN_GATE_WAIT_ENV,
        LoginAttemptLimits.DEFAULT_GATE_WAIT);
    if (gateWait.compareTo(LoginAttemptLimits.MAX_GATE_WAIT) > 0) {
      throw new IllegalArgumentException("Login gate wait must not exceed "
          + LoginAttemptLimits.MAX_GATE_WAIT + ": " + gateWait);
    }
    return limits
        .withGateWait(gateWait)
        .withGateRetryAfter(readDuration(LOGIN_GATE_RETRY_AFTER_PROPERTY,
            LOGIN_GATE_RETRY_AFTER_ENV, LoginAttemptLimits.DEFAULT_GATE_RETRY_AFTER));
  }

  private String value(String property, String envVar) {
    return firstNonBlank(sysprop.apply(property), env.apply(envVar));
  }

  private int readNonNegative(String property, String envVar, int defaultValue) {
    String value = value(property, envVar);
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      if (parsed < 0) {
        throw new IllegalArgumentException(
            "Login attempt limit must be >= 0 (0 = unbounded): " + value);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "Invalid login attempt limit '" + value + "'. Expected a non-negative integer.", e);
    }
  }

  private Duration readNonNegativeDuration(String property, String envVar, Duration defaultValue) {
    String value = value(property, envVar);
    if (value == null) {
      return defaultValue;
    }
    try {
      Duration parsed = Duration.parse(value.trim());
      if (parsed.isNegative()) {
        throw new IllegalArgumentException(
            "Login attempt duration must not be negative: " + value);
      }
      return parsed;
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException(
          "Invalid login attempt duration '" + value
              + "'. Expected ISO-8601 (e.g. PT0.25S, PT1S).", e);
    }
  }

  private LoginAttemptConfiguration load(
      LoginAttemptConfiguration defaults,
      String thresholdProp, String thresholdEnv,
      String windowProp, String windowEnv,
      String initialProp, String initialEnv,
      String maxProp, String maxEnv) {
    int threshold = readThreshold(thresholdProp, thresholdEnv, defaults.failureThreshold());
    Duration window = readDuration(windowProp, windowEnv, defaults.window());
    Duration initial = readDuration(initialProp, initialEnv, defaults.initialLockout());
    Duration max = readDuration(maxProp, maxEnv, defaults.maxLockout());
    return new LoginAttemptConfiguration(threshold, window, initial, max);
  }

  private int readThreshold(String property, String envVar, int defaultValue) {
    String value = firstNonBlank(sysprop.apply(property), env.apply(envVar));
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      if (parsed < 1) {
        throw new IllegalArgumentException(
            "Login attempt threshold must be >= 1: " + value);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "Invalid login attempt threshold '" + value + "'. Expected a positive integer.", e);
    }
  }

  private Duration readDuration(String property, String envVar, Duration defaultValue) {
    String value = firstNonBlank(sysprop.apply(property), env.apply(envVar));
    if (value == null) {
      return defaultValue;
    }
    try {
      Duration parsed = Duration.parse(value.trim());
      if (parsed.isNegative() || parsed.isZero()) {
        throw new IllegalArgumentException(
            "Login attempt duration must be positive: " + value);
      }
      return parsed;
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException(
          "Invalid login attempt duration '" + value
              + "'. Expected ISO-8601 (e.g. PT5M, PT1H).", e);
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a;
    }
    if (b != null && !b.isBlank()) {
      return b;
    }
    return null;
  }
}
