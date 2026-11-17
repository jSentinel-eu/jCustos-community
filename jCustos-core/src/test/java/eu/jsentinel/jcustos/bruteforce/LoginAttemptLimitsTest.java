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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_ADDRESS_MAX_LOCKOUT_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_ADDRESS_THRESHOLD_ENV;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_ADDRESS_THRESHOLD_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_ADDRESS_WINDOW_ENV;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_ADDRESS_WINDOW_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_GATE_RETRY_AFTER_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_GATE_WAIT_ENV;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_GATE_WAIT_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_MAX_CONCURRENT_CHECKS_ENV;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_MAX_CONCURRENT_CHECKS_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_MAX_LOCKOUT_PROPERTY;
import static eu.jsentinel.jcustos.bruteforce.LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_PROPERTY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-062 / JS-SEC-063: {@link LoginAttemptLimits}, the successor of the stable
 * {@link LoginAttemptConfiguration}, and its loader keys.
 */
@DisplayName("LoginAttemptLimits and LoginAttemptConfigurationLoader.loadLimits()")
class LoginAttemptLimitsTest {

  private static LoginAttemptConfigurationLoader loader(Map<String, String> sys,
                                                        Map<String, String> env) {
    return new LoginAttemptConfigurationLoader(sys::get, env::get);
  }

  // ── the record ─────────────────────────────────────────────────────

  @Test
  @DisplayName("defaults keep today's behaviour: no address counter, no bound on concurrent checks")
  void defaultsChangeNothing() {
    LoginAttemptLimits limits = LoginAttemptLimits.defaults();
    assertEquals(LoginAttemptConfiguration.defaults(), limits.perAccount());
    assertEquals(Optional.empty(), limits.perAddress());
    assertEquals(LoginAttemptLimits.UNBOUNDED_CREDENTIAL_CHECKS, limits.maxConcurrentCredentialChecks());
    assertFalse(limits.credentialChecksBounded());
    assertEquals(Duration.ofMillis(250), limits.gateWait());
    assertEquals(Duration.ofSeconds(1), limits.gateRetryAfter());
    assertEquals(LoginAttemptLimits.of(LoginAttemptConfiguration.strictBootstrap()).perAccount(),
        LoginAttemptConfiguration.strictBootstrap());
  }

  @Test
  @DisplayName("the with-methods change one component each")
  void withMethods() {
    LoginAttemptLimits.AddressLimit address = new LoginAttemptLimits.AddressLimit(
        20, Duration.ofMinutes(10), Duration.ofMinutes(5), Duration.ofHours(1));
    LoginAttemptLimits limits = LoginAttemptLimits.defaults()
        .withAddressLimit(address)
        .withMaxConcurrentCredentialChecks(8)
        .withGateWait(Duration.ZERO)
        .withGateRetryAfter(Duration.ofSeconds(4));
    assertEquals(Optional.of(address), limits.perAddress());
    assertEquals(8, limits.maxConcurrentCredentialChecks());
    assertTrue(limits.credentialChecksBounded());
    assertEquals(Duration.ZERO, limits.gateWait());
    assertEquals(Duration.ofSeconds(4), limits.gateRetryAfter());
    assertEquals(new LoginAttemptConfiguration(20, Duration.ofMinutes(10), Duration.ofMinutes(5),
        Duration.ofHours(1)), address.asConfiguration());
  }

  @Test
  @DisplayName("invalid limits are refused - fail closed")
  void invalidLimitsAreRefused() {
    LoginAttemptLimits base = LoginAttemptLimits.defaults();
    assertThrows(IllegalArgumentException.class, () -> base.withMaxConcurrentCredentialChecks(-1));
    assertThrows(IllegalArgumentException.class, () -> base.withGateWait(Duration.ofMillis(-1)));
    assertThrows(IllegalArgumentException.class,
        () -> base.withGateWait(LoginAttemptLimits.MAX_GATE_WAIT.plusMillis(1)));
    assertThrows(IllegalArgumentException.class, () -> base.withGateRetryAfter(Duration.ZERO));
    assertThrows(NullPointerException.class, () -> base.withGateWait(null));
    assertThrows(NullPointerException.class, () -> base.withAddressLimit(null));
    assertThrows(NullPointerException.class, () -> LoginAttemptLimits.of(null));
    assertThrows(IllegalArgumentException.class, () -> new LoginAttemptLimits.AddressLimit(
        0, Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class, () -> new LoginAttemptLimits.AddressLimit(
        5, Duration.ofMinutes(1), Duration.ofMinutes(10), Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class, () -> new LoginAttemptLimits.AddressLimit(
        5, Duration.ZERO, Duration.ofMinutes(1), Duration.ofMinutes(1)));
    assertEquals(LoginAttemptLimits.MAX_GATE_WAIT,
        base.withGateWait(LoginAttemptLimits.MAX_GATE_WAIT).gateWait());
  }

  // ── the loader ─────────────────────────────────────────────────────

  @Test
  @DisplayName("loadLimits without any new key equals LoginAttemptLimits.of(forLogin())")
  void noKeysNoChange() {
    LoginAttemptConfigurationLoader loader = loader(Map.of(LOGIN_THRESHOLD_PROPERTY, "7"), Map.of());
    assertEquals(LoginAttemptLimits.of(loader.forLogin()), loader.loadLimits());
    assertEquals(7, loader.loadLimits().perAccount().failureThreshold());
  }

  @Test
  @DisplayName("the address threshold alone switches the counter on; the rest comes from the account thresholds")
  void addressThresholdAlone() {
    LoginAttemptLimits limits = loader(Map.of(LOGIN_ADDRESS_THRESHOLD_PROPERTY, "40"), Map.of())
        .loadLimits();
    LoginAttemptConfiguration account = LoginAttemptConfiguration.defaults();
    assertEquals(Optional.of(new LoginAttemptLimits.AddressLimit(40, account.window(),
        account.initialLockout(), account.maxLockout())), limits.perAddress());
  }

  @Test
  @DisplayName("every new key, from system properties and the environment")
  void everyKey() {
    Map<String, String> sys = new HashMap<>();
    sys.put(LOGIN_ADDRESS_THRESHOLD_PROPERTY, "30");
    sys.put(LOGIN_ADDRESS_WINDOW_PROPERTY, "PT30M");
    sys.put(LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY, "PT10M");
    sys.put(LOGIN_ADDRESS_MAX_LOCKOUT_PROPERTY, "PT2H");
    sys.put(LOGIN_GATE_RETRY_AFTER_PROPERTY, "PT3S");
    Map<String, String> env = new HashMap<>();
    env.put(LOGIN_MAX_CONCURRENT_CHECKS_ENV, "16");
    env.put(LOGIN_GATE_WAIT_ENV, "PT0.5S");
    env.put(LOGIN_ADDRESS_THRESHOLD_ENV, "99");

    LoginAttemptLimits limits = loader(sys, env).loadLimits();

    assertEquals(Optional.of(new LoginAttemptLimits.AddressLimit(30, Duration.ofMinutes(30),
        Duration.ofMinutes(10), Duration.ofHours(2))), limits.perAddress(),
        "the system property wins over the environment");
    assertEquals(16, limits.maxConcurrentCredentialChecks());
    assertEquals(Duration.ofMillis(500), limits.gateWait());
    assertEquals(Duration.ofSeconds(3), limits.gateRetryAfter());
  }

  @Test
  @DisplayName("an address initial lockout above the account maximum raises the default address maximum")
  void addressMaximumFollowsALongInitialLockout() {
    LoginAttemptLimits limits = loader(Map.of(
        LOGIN_ADDRESS_THRESHOLD_PROPERTY, "30",
        LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY, "PT6H",
        LOGIN_MAX_LOCKOUT_PROPERTY, "PT4H"), Map.of()).loadLimits();
    LoginAttemptLimits.AddressLimit address = limits.perAddress().orElseThrow();
    assertEquals(Duration.ofHours(6), address.initialLockout());
    assertEquals(Duration.ofHours(6), address.maxLockout());
  }

  @Test
  @DisplayName("an address window without a threshold is refused instead of silently ignored")
  void addressDetailsWithoutThresholdAreRefused() {
    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> loader(Map.of(), Map.of(LOGIN_ADDRESS_WINDOW_ENV, "PT1H")).loadLimits());
    assertTrue(refused.getMessage().contains(LOGIN_ADDRESS_THRESHOLD_PROPERTY));
  }

  @Test
  @DisplayName("invalid values fail fast")
  void invalidValuesFailFast() {
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_MAX_CONCURRENT_CHECKS_PROPERTY, "-1"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_MAX_CONCURRENT_CHECKS_PROPERTY, "many"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_GATE_WAIT_PROPERTY, "PT11S"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_GATE_WAIT_PROPERTY, "-PT1S"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_GATE_WAIT_PROPERTY, "soon"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_GATE_RETRY_AFTER_PROPERTY, "PT0S"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(
        Map.of(LOGIN_ADDRESS_THRESHOLD_PROPERTY, "0"), Map.of()).loadLimits());
    assertThrows(IllegalArgumentException.class, () -> loader(Map.of(
        LOGIN_ADDRESS_THRESHOLD_PROPERTY, "10",
        LOGIN_ADDRESS_INITIAL_LOCKOUT_PROPERTY, "PT2H",
        LOGIN_ADDRESS_MAX_LOCKOUT_PROPERTY, "PT1H"), Map.of()).loadLimits());
  }

  @Test
  @DisplayName("zero is a valid gate wait and the explicit 'unbounded' for concurrent checks")
  void zeroValues() {
    LoginAttemptLimits limits = loader(Map.of(
        LOGIN_GATE_WAIT_PROPERTY, "PT0S",
        LOGIN_MAX_CONCURRENT_CHECKS_PROPERTY, "0"), Map.of()).loadLimits();
    assertEquals(Duration.ZERO, limits.gateWait());
    assertFalse(limits.credentialChecksBounded());
  }
}
