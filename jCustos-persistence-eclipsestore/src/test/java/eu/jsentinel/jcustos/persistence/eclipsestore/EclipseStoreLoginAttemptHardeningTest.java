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
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.StoreBackedLoginAttemptPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-122 (CWE-307, CWE-770) and JS-SEC-123 (CWE-367) for the Eclipse-Store adapter: the real
 * storage on a temp directory, driven through the real {@link StoreBackedLoginAttemptPolicy}.
 */
@DisplayName("EclipseStoreLoginAttemptStore - lockouts under capacity pressure and across restarts")
class EclipseStoreLoginAttemptHardeningTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  /** 5 failures / 15 min window / 15 min lockout. */
  private static final LoginAttemptConfiguration CONFIG = LoginAttemptConfiguration.defaults();

  @TempDir
  Path tempDir;

  private static StoreBackedLoginAttemptPolicy policy(LoginAttemptStore store, Instant now) {
    return new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT,
        Clock.fixed(now, ZoneOffset.UTC));
  }

  private static LoginAttemptContext ctx(String user) {
    return new LoginAttemptContext(user, "10.0.0.1", null, T0);
  }

  private static LoginAttemptKey key(String user) {
    return new LoginAttemptKey(TenantId.DEFAULT, user, "10.0.0.1");
  }

  private static void failedLogin(StoreBackedLoginAttemptPolicy policy, String user) {
    if (policy.beforeAttempt(ctx(user)) instanceof LoginAttemptDecision.Allowed) {
      policy.recordFailure(ctx(user));
    }
  }

  @Test
  @DisplayName("an active lockout survives a spray of more than maxEntries new keys; the persistent map stays bounded")
  void lockoutSurvivesKeySpray() {
    int cap = 20;
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = new EclipseStoreLoginAttemptStore(storage, cap);

      StoreBackedLoginAttemptPolicy atT0 = policy(store, T0);
      for (int i = 0; i < CONFIG.failureThreshold(); i++) {
        failedLogin(atT0, "victim");
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, atT0.beforeAttempt(ctx("victim")));

      for (int i = 0; i < cap * 3; i++) {
        StoreBackedLoginAttemptPolicy later = policy(store, T0.plusMillis(10L * (i + 1)));
        failedLogin(later, "spray-" + i);
        assertTrue(storage.root().loginAttempts.size() <= cap,
            "persistent map over the bound: " + storage.root().loginAttempts.size());
        assertInstanceOf(LoginAttemptDecision.LockedOut.class, later.beforeAttempt(ctx("victim")),
            "the victim's lockout was pushed out after " + (i + 1) + " sprayed keys");
      }
      assertEquals(CONFIG.failureThreshold(), store.failureCount(key("victim")));

      // the lockout ends when its time is up
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy(store, T0.plus(Duration.ofMinutes(15)).minusMillis(1)).beforeAttempt(ctx("victim")));
      assertEquals(LoginAttemptDecision.allowed(),
          policy(store, T0.plus(Duration.ofMinutes(15))).beforeAttempt(ctx("victim")));
      assertFalse(storage.root().loginAttempts.containsKey(key("victim")),
          "the expired counter is gone from the persistent map as well");
    }
  }

  @Test
  @DisplayName("with only locked keys left, a further key is refused and nothing is written for it")
  void onlyLockedKeysLeft_newKeyIsRefused() {
    int cap = 2;
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = new EclipseStoreLoginAttemptStore(storage, cap);
      StoreBackedLoginAttemptPolicy policy = policy(store, T0);
      for (int account = 0; account < 6; account++) {
        for (int i = 0; i < CONFIG.failureThreshold(); i++) {
          failedLogin(policy, "account-" + account);
        }
      }
      assertEquals(cap, storage.root().loginAttempts.size());
      LoginAttemptDecision.LockedOut refusal = assertInstanceOf(
          LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("someone-new")));
      assertEquals(Duration.ofMinutes(15), refusal.remaining());
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("account-0")));
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("account-1")));
    }
  }

  @Test
  @DisplayName("a lockout survives a restart, is still protected against a spray afterwards, and ends on time")
  void lockoutSurvivesRestart() {
    int cap = 20;
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      StoreBackedLoginAttemptPolicy policy = policy(new EclipseStoreLoginAttemptStore(storage, cap), T0);
      for (int i = 0; i < CONFIG.failureThreshold(); i++) {
        failedLogin(policy, "victim");
      }
      failedLogin(policy, "bystander");
      // an attempt in flight at shutdown: working state only, must not be persisted
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(ctx("in-flight")));
      assertEquals(List.of(key("victim"), key("bystander")),
          List.copyOf(storage.root().loginAttempts.keySet()));
    }

    Instant afterRestart = T0.plus(Duration.ofMinutes(5));
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = new EclipseStoreLoginAttemptStore(reopened, cap);
      assertEquals(CONFIG.failureThreshold(), store.failureCount(key("victim")));
      assertEquals(1, store.failureCount(key("bystander")));
      assertEquals(0, store.failureCount(key("in-flight")));

      StoreBackedLoginAttemptPolicy policy = policy(store, afterRestart);
      LoginAttemptDecision.LockedOut locked = assertInstanceOf(
          LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("victim")),
          "a lockout earned before the restart is still in force");
      assertEquals(Duration.ofMinutes(10), locked.remaining());

      // the lockout rebuilt from counter + timestamp is protected like a fresh one
      for (int i = 0; i < cap * 2; i++) {
        failedLogin(policy, "spray-" + i);
        assertTrue(reopened.root().loginAttempts.size() <= cap);
      }
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(ctx("victim")));
      assertEquals(LoginAttemptDecision.allowed(),
          policy(store, T0.plus(Duration.ofMinutes(15))).beforeAttempt(ctx("victim")));
    }
  }

  @Test
  @DisplayName("a storage that already holds more keys than the bound is trimmed on first use")
  void oversizedStorageIsTrimmed() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      // written through an adapter with a generous bound - stands for a pre-00.84.00 storage
      LoginAttemptStore generous = new EclipseStoreLoginAttemptStore(storage, 1_000);
      for (int i = 0; i < 50; i++) {
        generous.recordFailure(key("old-" + i), T0.plusSeconds(i));
      }
      assertEquals(50, storage.root().loginAttempts.size());
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore bounded = new EclipseStoreLoginAttemptStore(reopened, 10);
      bounded.recordFailure(key("new"), T0.plusSeconds(100));
      assertEquals(10, reopened.root().loginAttempts.size());
      assertEquals(1, bounded.failureCount(key("new")));
      assertEquals(1, bounded.failureCount(key("old-49")), "the most recent counters are the ones kept");
      assertEquals(0, bounded.failureCount(key("old-0")));
    }
    try (EclipseStoreJCustosStorage again = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertEquals(10, again.root().loginAttempts.size(), "the trim itself was persisted");
    }
  }

  @Test
  @DisplayName("the working state is not part of the stored format")
  void workingStateIsNotPersisted() throws IOException {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      StoreBackedLoginAttemptPolicy policy = policy(storage.loginAttemptStore(), T0);
      failedLogin(policy, "alice");
      policy.beforeAttempt(ctx("alice"));
    }
    StringBuilder dictionary = new StringBuilder();
    try (Stream<Path> files = Files.walk(tempDir)) {
      for (Path file : files.filter(path -> path.getFileName().toString().endsWith(".ptd")).toList()) {
        dictionary.append(Files.readString(file, StandardCharsets.UTF_8));
      }
    }
    assertTrue(dictionary.toString().contains("loginAttempts"),
        "sanity: the type dictionary was found and describes the root");
    assertFalse(dictionary.toString().contains("loginAttemptRuntime"),
        "the transient working state must not appear in the type dictionary");
    assertFalse(dictionary.toString().contains("WorkingState"));
    assertFalse(dictionary.toString().contains("InMemoryLoginAttemptStore"));
  }
}
