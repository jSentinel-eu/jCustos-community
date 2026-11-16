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

import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * In-memory {@link DemoUserDirectory}. Demo-only — never use as a
 * production user store.
 * <p>
 * Pre-populates {@code user/user} (USER) and {@code demo/demo} (NERD).
 * The administrator entry is intentionally absent — the bootstrap flow
 * creates the first administrator.
 * <p>
 * Passwords are hashed and verified through the credential pipeline the
 * bootstrap configured ({@link ConfiguredHashingService}, JS-SEC-134) - the
 * pipeline {@code BootstrapWiring} hashes the first administrator with, so
 * the administrator {@code SetupView} creates can log in. An unknown user
 * name costs the same key derivation as a known one, and a verification the
 * KDF limiter shed is reported as "try again later", never as a wrong
 * password (JS-SEC-126).
 */
public final class InMemoryDemoUserDirectory implements DemoUserDirectory {

  private final PasswordHashingService hashing;
  private final Map<String, StoredUser> byUsername = new ConcurrentHashMap<>();
  private final Map<Long, MyUser> byId = new ConcurrentHashMap<>();

  public InMemoryDemoUserDirectory() {
    this(ConfiguredHashingService.INSTANCE);
  }

  /**
   * @param hashing the credential pipeline to hash and verify with
   */
  public InMemoryDemoUserDirectory(PasswordHashingService hashing) {
    this.hashing = Objects.requireNonNull(hashing, "hashing");
    addUser("user", "user", createMyUser(2L, "Herr User", AuthorizationRole.USER));
    addUser("demo", "demo", createMyUser(3L, "Herr Demo", AuthorizationRole.NERD));
  }

  // ── Public API ────────────────────────────────────────────────

  @Override
  public Optional<MyUser> findByCredentials(Credentials credentials) {
    return resolve(credentials);
  }

  @Override
  public Optional<MyUser> findById(Long id) {
    return Optional.ofNullable(byId.get(id));
  }

  @Override
  public Stream<MyUser> all() {
    return byUsername.values().stream().map(stored -> stored.user);
  }

  @Override
  public synchronized boolean hasAnyAdministrator() {
    return byUsername.values().stream()
        .anyMatch(stored -> stored.user.roles().contains(AuthorizationRole.ADMIN));
  }

  @Override
  public synchronized void addUser(String username, String plaintextPassword, MyUser user) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(plaintextPassword);
    Objects.requireNonNull(user);
    char[] raw = plaintextPassword.toCharArray();
    String hash;
    try {
      hash = hashing.hash(raw).encodedHash();
    } finally {
      Arrays.fill(raw, '\0');
    }
    byUsername.put(username, new StoredUser(user, hash));
    byId.put(user.id(), user);
    audit(new UserCreated(
        Instant.now(Clock.systemUTC()), username, firstRoleOf(user), null));
  }

  @Override
  public synchronized void registerWithHashedPassword(String username, String passwordHash, MyUser user) {
    if (byUsername.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    byUsername.put(username, new StoredUser(user, passwordHash));
    byId.put(user.id(), user);
  }

  @Override
  public synchronized void deleteUser(Long id) {
    MyUser removed = byId.remove(id);
    if (removed == null) return;
    String username = byUsername.entrySet().stream()
        .filter(e -> e.getValue().user.equals(removed))
        .map(Map.Entry::getKey)
        .findFirst()
        .orElse(null);
    byUsername.values().removeIf(stored -> stored.user.equals(removed));
    if (username != null) {
      audit(new UserDeleted(
          Instant.now(Clock.systemUTC()), username, null));
    }
  }

  @Override
  public synchronized void enableBootstrapMode() {
    byUsername.values().removeIf(stored -> stored.user.roles().contains(AuthorizationRole.ADMIN));
    byId.values().removeIf(user -> user.roles().contains(AuthorizationRole.ADMIN));
  }

  @Override
  public PasswordHashingService hashingService() {
    return hashing;
  }

  @Override
  public synchronized void assignRole(Long id, AuthorizationRole role) {
    Objects.requireNonNull(role, "role");
    if (id == null) return;
    MyUser current = byId.get(id);
    if (current == null || current.roles().contains(role)) {
      return;
    }
    EnumSet<AuthorizationRole> next = roleSetOf(current);
    next.add(role);
    replace(current, new MyUser(current.id(), current.name(), next));
    audit(new RoleAssigned(
        Instant.now(Clock.systemUTC()), current.id().toString(), role.name(), null));
  }

  @Override
  public synchronized void revokeRole(Long id, AuthorizationRole role) {
    Objects.requireNonNull(role, "role");
    if (id == null) return;
    MyUser current = byId.get(id);
    if (current == null || !current.roles().contains(role)) {
      return;
    }
    EnumSet<AuthorizationRole> next = roleSetOf(current);
    next.remove(role);
    replace(current, new MyUser(current.id(), current.name(), next));
    audit(new RoleRevoked(
        Instant.now(Clock.systemUTC()), current.id().toString(), role.name(), null));
  }

  private static EnumSet<AuthorizationRole> roleSetOf(MyUser user) {
    EnumSet<AuthorizationRole> set = EnumSet.noneOf(AuthorizationRole.class);
    set.addAll(user.roles());
    return set;
  }

  /**
   * Picks a stable label for {@link UserCreated#role()} — the user's
   * "primary" role for audit purposes. {@code MyUser} carries a set of
   * roles; this method returns the highest-privilege one (ADMIN > Q_ADMIN
   * > NERD > USER > NOBODY) or the literal {@code "USER"} if the set is
   * empty.
   */
  private static String firstRoleOf(MyUser user) {
    if (user.roles().contains(AuthorizationRole.ADMIN)) return AuthorizationRole.ADMIN.name();
    if (user.roles().contains(AuthorizationRole.Q_ADMIN)) return AuthorizationRole.Q_ADMIN.name();
    if (user.roles().contains(AuthorizationRole.NERD)) return AuthorizationRole.NERD.name();
    if (user.roles().contains(AuthorizationRole.USER)) return AuthorizationRole.USER.name();
    return AuthorizationRole.NOBODY.name();
  }

  /**
   * Replaces the stored {@link MyUser} in both indexes. The username and
   * password-hash bindings stay attached to the new instance.
   */
  private void replace(MyUser oldUser, MyUser newUser) {
    byId.put(newUser.id(), newUser);
    byUsername.replaceAll((username, stored) ->
        stored.user.equals(oldUser) ? new StoredUser(newUser, stored.passwordHash) : stored);
  }

  private static void audit(eu.jsentinel.jcustos.audit.AuditEvent event) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // never block role admin because the audit sink failed
    }
  }

  // ── Helpers ───────────────────────────────────────────────────

  static MyUser createMyUser(Long id, String name, AuthorizationRole... roles) {
    Objects.requireNonNull(id);
    Objects.requireNonNull(name);
    Objects.requireNonNull(roles);
    HashSet<AuthorizationRole> roleSet = new HashSet<>();
    Collections.addAll(roleSet, roles);
    roleSet.add(AuthorizationRole.USER);
    return new MyUser(id, name, roleSet);
  }

  private Optional<MyUser> resolve(Credentials credentials) {
    if (credentials == null
        || credentials.username() == null
        || credentials.password() == null) {
      return Optional.empty();
    }
    char[] raw = credentials.password().toCharArray();
    try {
      StoredUser stored = byUsername.get(credentials.username());
      if (stored == null) {
        // Same derivation cost as a known name - no user enumeration by timing.
        CredentialVerificationUnavailableException.throwIfUnavailable(
            hashing.verifyAgainstNothing(raw));
        return Optional.empty();
      }
      CredentialVerificationResult result = hashing.verify(raw, stored.passwordHash);
      CredentialVerificationUnavailableException.throwIfUnavailable(result);
      if (!(result instanceof CredentialVerificationResult.Verified)) {
        return Optional.empty();
      }
      rehashIfOutdated(credentials.username(), stored, raw);
      return Optional.of(stored.user);
    } finally {
      Arrays.fill(raw, '\0');
    }
  }

  /**
   * Upgrades a hash the configured policy calls outdated. The login has
   * already succeeded against the stored hash, so a failure keeps the old
   * hash and the user has to choose a new password (JS-SEC-133).
   */
  private void rehashIfOutdated(String username, StoredUser stored, char[] raw) {
    if (!(hashing.needsRehash(stored.passwordHash) instanceof RehashDecision.Required)) {
      return;
    }
    try {
      String freshHash = hashing.hash(raw).encodedHash();
      byUsername.put(username, new StoredUser(stored.user, freshHash));
    } catch (RuntimeException rehashFailure) {
      HasLogger.staticLogger().warn("The password hash of user id {} could not be upgraded "
          + "({}); the user has to choose a new password.",
          stored.user.id(), rehashFailure.getClass().getSimpleName());
    }
  }

  /** Test seam: returns the stored hash for the given username, or empty. */
  public synchronized Optional<String> storedPasswordHash(String username) {
    StoredUser stored = byUsername.get(username);
    return stored == null ? Optional.empty() : Optional.of(stored.passwordHash);
  }

  private record StoredUser(MyUser user, String passwordHash) {
  }
}
