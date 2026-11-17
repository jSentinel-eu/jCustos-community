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

import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
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
 * JS-SEC-166 (CWE-307) for the Eclipse-Store adapter: an account lockout earned by guesses from
 * many addresses survives a restart, in the unchanged stored format - the account key is an
 * ordinary {@link LoginAttemptKey} with a reserved user id.
 */
@DisplayName("EclipseStoreLoginAttemptStore - an account lockout survives a restart (JS-SEC-166)")
class EclipseStoreAccountLockoutRestartTest {

  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
  /** 5 failures within 30 min lock the account for 15 min. */
  private static final LoginAttemptConfiguration ACCOUNT = new LoginAttemptConfiguration(
      5, Duration.ofMinutes(30), Duration.ofMinutes(15), Duration.ofMinutes(15));

  @TempDir
  Path tempDir;

  private static StoreBackedLoginAttemptPolicy policy(LoginAttemptStore store, Instant now) {
    return new StoreBackedLoginAttemptPolicy(store, LoginAttemptLimits.of(ACCOUNT),
        TenantId.DEFAULT, Clock.fixed(now, ZoneOffset.UTC), SubjectKeyCanonicalizer.defaults(),
        NoopJCustosAuditService.INSTANCE);
  }

  private static LoginAttemptContext ctx(String user, String address, Instant at) {
    return new LoginAttemptContext(user, address, null, at);
  }

  @Test
  @DisplayName("guesses from 20 addresses, restart five minutes later: the account is still locked from every address, the lockout ends on time")
  void accountLockoutSurvivesRestart() {
    LoginAttemptKey accountKey = LoginAttemptKey.forAccount(TenantId.DEFAULT, "alice");
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = storage.loginAttemptStore();
      int evaluated = 0;
      for (int i = 0; i < 20; i++) {
        Instant at = T0.plusSeconds(i);
        StoreBackedLoginAttemptPolicy policy = policy(store, at);
        LoginAttemptContext guess = ctx("alice", "203.0.113." + i, at);
        if (policy.beforeAttempt(guess) instanceof LoginAttemptDecision.Allowed) {
          policy.recordFailure(guess);
          evaluated++;
        }
      }
      assertEquals(ACCOUNT.failureThreshold(), evaluated, "five guesses were evaluated");
      assertEquals(ACCOUNT.failureThreshold(), store.failureCount(accountKey));
      assertTrue(storage.tables().loginAttempts.containsKey(accountKey),
          "the account key is persisted like any other key");
    }

    Instant lastFailure = T0.plusSeconds(ACCOUNT.failureThreshold() - 1L);
    Instant afterRestart = T0.plus(Duration.ofMinutes(5));
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = reopened.loginAttemptStore();
      assertEquals(ACCOUNT.failureThreshold(), store.failureCount(accountKey));

      StoreBackedLoginAttemptPolicy policy = policy(store, afterRestart);
      LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("ALICE", "198.51.100.7", afterRestart)),
          "an account lockout earned before the restart refuses an address never used before");
      assertEquals(Duration.between(afterRestart, lastFailure.plus(ACCOUNT.initialLockout())),
          locked.remaining());
      LoginAttemptContext other = ctx("bob", "203.0.113.1", afterRestart);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(other),
          "the addresses the guesses came from are not locked");
      policy.abandonAttempt(other);

      Instant lifted = lastFailure.plus(ACCOUNT.initialLockout());
      LoginAttemptContext owner = ctx("alice", "198.51.100.7", lifted);
      StoreBackedLoginAttemptPolicy later = policy(store, lifted);
      assertEquals(LoginAttemptDecision.allowed(), later.beforeAttempt(owner),
          "the lockout ends on time");
      assertEquals(LoginAttemptDecision.allowed(), later.confirmSuccess(owner));
      assertEquals(0, store.failureCount(accountKey), "the owner's login clears the account");
    }
  }
}
