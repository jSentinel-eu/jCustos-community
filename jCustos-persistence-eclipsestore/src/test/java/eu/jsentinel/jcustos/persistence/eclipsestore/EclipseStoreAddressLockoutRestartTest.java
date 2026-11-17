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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.StoreBackedLoginAttemptPolicy;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-062 (CWE-307) for the Eclipse-Store adapter: an address lockout earned by a password
 * spray survives a restart, in the unchanged stored format, and keeps its own limits after it -
 * although the account limits, which are much shorter, reach the store first.
 */
@DisplayName("EclipseStoreLoginAttemptStore - an address lockout survives a restart (JS-SEC-062)")
class EclipseStoreAddressLockoutRestartTest {

  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
  private static final String SPRAYER = "203.0.113.50";
  /** Accounts: 5 failures / 2 min window / 1 min lockout - deliberately short. */
  private static final LoginAttemptConfiguration ACCOUNT = new LoginAttemptConfiguration(
      5, Duration.ofMinutes(2), Duration.ofMinutes(1), Duration.ofMinutes(1));
  /** The address: 8 failures / 1 h window / 1 h lockout. */
  private static final LoginAttemptLimits LIMITS = LoginAttemptLimits.of(ACCOUNT).withAddressLimit(
      new LoginAttemptLimits.AddressLimit(8, Duration.ofHours(1), Duration.ofHours(1),
          Duration.ofHours(1)));

  @TempDir
  Path tempDir;

  private static StoreBackedLoginAttemptPolicy policy(LoginAttemptStore store, Instant now) {
    return new StoreBackedLoginAttemptPolicy(store, LIMITS, TenantId.DEFAULT,
        Clock.fixed(now, ZoneOffset.UTC), SubjectKeyCanonicalizer.defaults(), null);
  }

  private static LoginAttemptContext ctx(String user, String address, Instant at) {
    return new LoginAttemptContext(user, address, null, at);
  }

  @Test
  @DisplayName("spray, restart ten minutes later: the address is still locked, a fresh account from it is refused, the lockout ends on time")
  void addressLockoutSurvivesRestart() {
    LoginAttemptKey addressKey = LoginAttemptKey.forAddress(TenantId.DEFAULT, SPRAYER);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = storage.loginAttemptStore();
      for (int i = 0; i < 20; i++) {
        StoreBackedLoginAttemptPolicy policy = policy(store, T0.plusSeconds(i));
        LoginAttemptContext attempt = ctx("user-" + i, SPRAYER, T0.plusSeconds(i));
        if (policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.Allowed) {
          policy.recordFailure(attempt);
        }
      }
      assertEquals(8, store.failureCount(addressKey), "eight guesses were evaluated");
      assertTrue(storage.tables().loginAttempts.containsKey(addressKey),
          "the address key is persisted like any other key");
    }

    Instant lastFailure = T0.plusSeconds(7);
    Instant afterRestart = T0.plus(Duration.ofMinutes(10));
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = reopened.loginAttemptStore();
      assertEquals(8, store.failureCount(addressKey));

      // the account limits reach the restored store first: a login from elsewhere
      StoreBackedLoginAttemptPolicy policy = policy(store, afterRestart);
      LoginAttemptContext elsewhere = ctx("user-0", "198.51.100.7", afterRestart);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(elsewhere),
          "the sprayed account itself is not locked");
      policy.abandonAttempt(elsewhere);

      LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("someone-new", SPRAYER, afterRestart)),
          "an address lockout earned before the restart is still in force");
      assertEquals(Duration.between(afterRestart, lastFailure.plus(Duration.ofHours(1))),
          locked.remaining(), "with the address lockout, not the one-minute account lockout");

      Instant later = afterRestart.plus(Duration.ofMinutes(20));
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy(store, later).beforeAttempt(ctx("another", SPRAYER, later)),
          "past every account window the address entry is still kept");

      Instant lifted = lastFailure.plus(Duration.ofHours(1));
      assertEquals(LoginAttemptDecision.allowed(),
          policy(store, lifted).beforeAttempt(ctx("late", SPRAYER, lifted)),
          "the lockout ends on time");
    }
  }
}
