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
package eu.jsentinel.jcustos.demo.app.security.model;

import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.demo.app.TestDirectories;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-134: the directory hashes and verifies through the credential pipeline it is given
 * (by default the one the bootstrap configured), upgrades an outdated hash on login, and
 * reports a shed verification as unavailable, not as a wrong password (JS-SEC-126).
 */
@DisplayName("InMemoryDemoUserDirectory — credential pipeline and rehash on successful login")
class InMemoryDemoUserDirectoryRehashTest {

  @Test
  @DisplayName("a stored hash is the pipeline's envelope and verifies; no drift → stored hash unchanged")
  void noDrift_noRehash() {
    InMemoryDemoUserDirectory directory =
        TestDirectories.withDemoAccounts(PasswordHashingServices.defaults());

    String before = directory.storedPasswordHash("user").orElseThrow();
    assertTrue(before.startsWith("$pwh$"), "the pipeline's envelope, not a legacy hash: " + before);

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("user", "user"));

    assertTrue(resolved.isPresent());
    assertEquals(before, directory.storedPasswordHash("user").orElseThrow(),
        "no parameter drift → stored hash must not be touched");
  }

  @Test
  @DisplayName("a hash below the policy's parameters is upgraded on login")
  void driftDetected_rehash() {
    PasswordHashingService older = PasswordHashingServices.defaults(pbkdf2Policy(1,
        Pbkdf2Defaults.MIN_ITERATIONS));
    String oldHash = older.hash("legacy".toCharArray()).encodedHash();

    PasswordHashingService newer = PasswordHashingServices.defaults(pbkdf2Policy(2,
        Pbkdf2Defaults.DEFAULT_ITERATIONS));
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(newer, false);
    HashSet<AuthorizationRole> roles = new HashSet<>();
    roles.add(AuthorizationRole.USER);
    directory.registerWithHashedPassword(
        "legacy", oldHash, new MyUser(99L, "Legacy User", roles));

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("legacy", "legacy"));

    assertTrue(resolved.isPresent(), "verify must still succeed against the older hash");
    String hashAfter = directory.storedPasswordHash("legacy").orElseThrow();
    assertNotEquals(oldHash, hashAfter, "drift must trigger a re-hash; stored hash must change");
    assertTrue(directory.findByCredentials(new Credentials("legacy", "legacy")).isPresent(),
        "the upgraded hash verifies");
  }

  @Test
  @DisplayName("findByCredentials with wrong password → no rehash")
  void wrongPassword_noRehash() {
    InMemoryDemoUserDirectory directory =
        TestDirectories.withDemoAccounts(PasswordHashingServices.defaults());
    String before = directory.storedPasswordHash("user").orElseThrow();

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("user", "wrong"));

    assertTrue(resolved.isEmpty());
    assertEquals(before, directory.storedPasswordHash("user").orElseThrow());
  }

  @Test
  @DisplayName("findByCredentials with unknown username → empty, no side effects")
  void unknownUser_empty() {
    InMemoryDemoUserDirectory directory =
        new InMemoryDemoUserDirectory(PasswordHashingServices.defaults(), false);

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("nobody", "anything"));

    assertTrue(resolved.isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-126: a verification shed by the KDF limiter is unavailable, not wrong")
  void shedVerificationIsUnavailable() {
    KdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    InMemoryDemoUserDirectory directory = TestDirectories.withDemoAccounts(
        PasswordHashingServices.defaults(Pbkdf2Defaults.referencePolicy(), limiter));
    Optional<KdfExecutionLimiter.Lease> held = limiter.acquire();
    try {
      assertThrows(CredentialVerificationUnavailableException.class,
          () -> directory.findByCredentials(new Credentials("user", "user")));
      assertThrows(CredentialVerificationUnavailableException.class,
          () -> directory.findByCredentials(new Credentials("nobody", "whatever")));
    } finally {
      held.orElseThrow().close();
    }
    assertTrue(directory.findByCredentials(new Credentials("user", "user")).isPresent());
  }

  /** A PBKDF2 policy with the given version and iteration count. */
  private static PasswordHashPolicy pbkdf2Policy(int version, int iterations) {
    Map<String, String> defaults = new LinkedHashMap<>(Pbkdf2Defaults.defaultParameters());
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(iterations));
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(version)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2Defaults.maximumParameters())
        .build();
  }
}
