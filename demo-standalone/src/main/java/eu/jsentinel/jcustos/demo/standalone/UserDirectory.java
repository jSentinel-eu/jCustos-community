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
package eu.jsentinel.jcustos.demo.standalone;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory user directory shared across the demo's
 * {@code AuthenticationService} and {@code AuthorizationService}
 * SPI implementations. Singleton.
 *
 * <p>Passwords are stored as hashes of the credential pipeline
 * ({@code JCustosServiceResolver.credentialHashingService()}) and
 * verified through it — never in clear text, never compared with
 * {@code String.equals} (JS-SEC-137). An unknown name costs one KDF run
 * like a wrong password (CWE-208); a verification shed under load
 * surfaces as {@link CredentialVerificationUnavailableException}
 * (JS-SEC-126).
 *
 * <p>The directory starts empty. The fixed-password demo accounts
 * ({@code admin/admin}, {@code librarian/librarian}, {@code alice/alice})
 * exist only when the development switch
 * {@value #INSECURE_SEED_ACCOUNTS_PROPERTY}{@code =true} is set; the CLI
 * refuses the switch outside {@code DEVELOPMENT} mode.
 */
public final class UserDirectory implements HasLogger {

  /**
   * Development switch for the fixed-password demo accounts. Off by default
   * (JS-SEC-137): a copied application must not be usable with
   * {@code admin/admin}.
   */
  public static final String INSECURE_SEED_ACCOUNTS_PROPERTY = "jcustos.demo.insecure-seed-accounts";

  private static final UserDirectory INSTANCE = new UserDirectory();

  private final Map<String, Stored> byUsername = new ConcurrentHashMap<>();

  private UserDirectory() {
    if (insecureSeedAccountsRequested()) {
      seedInsecureDemoAccounts();
    }
  }

  public static UserDirectory instance() {
    return INSTANCE;
  }

  /** @return whether {@value #INSECURE_SEED_ACCOUNTS_PROPERTY} is set to {@code true} */
  public static boolean insecureSeedAccountsRequested() {
    return Boolean.getBoolean(INSECURE_SEED_ACCOUNTS_PROPERTY);
  }

  /**
   * Adds the fixed-password demo accounts if they are missing.
   * <strong>Development only.</strong>
   */
  public synchronized void seedInsecureDemoAccounts() {
    if (byUsername.containsKey("admin")) {
      return;
    }
    logger().warn("{}=true: seeding fixed-password demo accounts - local development only",
        INSECURE_SEED_ACCOUNTS_PROPERTY);
    addUser("admin", "admin", new User("admin", "Administrator",
        EnumSet.of(Role.ADMIN, Role.LIBRARIAN, Role.MEMBER)));
    addUser("librarian", "librarian", new User("librarian", "Librarian",
        EnumSet.of(Role.LIBRARIAN, Role.MEMBER)));
    addUser("alice", "alice", new User("alice", "Alice",
        EnumSet.of(Role.MEMBER)));
  }

  public void addUser(String username, String password, User user) {
    Objects.requireNonNull(password, "password");
    String hash = hashing().hash(password.toCharArray()).encodedHash();
    byUsername.put(username, new Stored(user, hash));
  }

  /**
   * @return the user, or empty for an unknown name or a wrong password
   * @throws CredentialVerificationUnavailableException when the verification
   *         was shed under load — answer "try again later"
   */
  public Optional<User> findByCredentials(Credentials credentials) {
    if (credentials == null || credentials.username() == null || credentials.password() == null) {
      return Optional.empty();
    }
    PasswordHashingService service = hashing();
    char[] raw = credentials.password().toCharArray();
    try {
      Stored stored = byUsername.get(credentials.username());
      CredentialVerificationResult result = stored == null
          ? service.verifyAgainstNothing(raw)
          : service.verify(raw, stored.passwordHash());
      CredentialVerificationUnavailableException.throwIfUnavailable(result);
      return stored != null && result instanceof CredentialVerificationResult.Verified
          ? Optional.of(stored.user())
          : Optional.empty();
    } finally {
      Arrays.fill(raw, '\0');
    }
  }

  /** Test seam: the stored hash of {@code username}, or empty. */
  Optional<String> storedPasswordHash(String username) {
    Stored stored = byUsername.get(username);
    return stored == null ? Optional.empty() : Optional.of(stored.passwordHash());
  }

  private static PasswordHashingService hashing() {
    return JCustosServiceResolver.credentialHashingService();
  }

  private record Stored(User user, String passwordHash) { }
}
