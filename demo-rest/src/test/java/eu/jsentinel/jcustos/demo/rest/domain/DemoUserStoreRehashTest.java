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
package eu.jsentinel.jcustos.demo.rest.domain;

import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoUserStore — rehash on successful login")
class DemoUserStoreRehashTest {

  private static PasswordHashPolicy fastPolicy(int iterations) {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(iterations));
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Pbkdf2ParameterNames.ITERATIONS, "500");
    min.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "10000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  @Test
  @DisplayName("authenticate with same policy → no drift → stored hash unchanged")
  void noDrift_noRehash() {
    PasswordHashingService service = PasswordHashingServices.defaults(fastPolicy(1000));
    DemoUserStore store = new DemoUserStore(service,
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);

    String hashBefore = store.storedPasswordHash("admin").orElseThrow();
    Optional<DemoUser> user = store.authenticate("admin", "admin");

    assertTrue(user.isPresent(), "credentials must verify");
    assertEquals(hashBefore, store.storedPasswordHash("admin").orElseThrow(),
        "no parameter drift → stored hash must not be touched");
  }

  @Test
  @DisplayName("authenticate when stored hash has fewer iterations than the policy default → rehash")
  void driftDetected_rehash() {
    // Seed the store at the lower iteration count
    DemoUserStore seedStore = new DemoUserStore(
        PasswordHashingServices.defaults(fastPolicy(1000)),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);
    String hashBefore = seedStore.storedPasswordHash("admin").orElseThrow();
    assertTrue(hashBefore.contains("$p=i=1000,"),
        "seed hash must record 1000 iterations: " + hashBefore);

    // Build a new store under a higher-iteration policy and import the
    // older hash so authenticate sees parameter drift.
    DemoUserStore upgradeStore = new DemoUserStore(
        PasswordHashingServices.defaults(fastPolicy(2000)),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);
    upgradeStore.register(new DemoUser(
        "drift-user", "Drift User", hashBefore, DemoRole.ROLE_ADMIN));

    String hashBeforeUpgrade =
        upgradeStore.storedPasswordHash("drift-user").orElseThrow();
    Optional<DemoUser> result = upgradeStore.authenticate("drift-user", "admin");

    assertTrue(result.isPresent(), "verify must still succeed against the older hash");
    String hashAfter = upgradeStore.storedPasswordHash("drift-user").orElseThrow();
    assertNotEquals(hashBeforeUpgrade, hashAfter,
        "drift must trigger a re-hash; stored hash must change");
    assertTrue(hashAfter.contains("$p=i=2000,"),
        "fresh hash must reflect the newer iteration count: " + hashAfter);
  }

  @Test
  @DisplayName("authenticate with wrong password → no rehash, no change")
  void wrongPassword_noRehash() {
    DemoUserStore store = new DemoUserStore(
        PasswordHashingServices.defaults(fastPolicy(1000)),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);
    String hashBefore = store.storedPasswordHash("admin").orElseThrow();

    Optional<DemoUser> user = store.authenticate("admin", "wrong");

    assertTrue(user.isEmpty());
    assertEquals(hashBefore, store.storedPasswordHash("admin").orElseThrow());
  }

  @Test
  @DisplayName("authenticate against unknown user → returns empty without touching the store")
  void unknownUser_noChange() {
    DemoUserStore store = new DemoUserStore(
        PasswordHashingServices.defaults(fastPolicy(1000)),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);

    Optional<DemoUser> result = store.authenticate("nobody", "anything");

    assertTrue(result.isEmpty());
  }
}
