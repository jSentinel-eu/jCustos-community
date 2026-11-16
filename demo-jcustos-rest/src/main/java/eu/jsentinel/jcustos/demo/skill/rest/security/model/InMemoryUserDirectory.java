package eu.jsentinel.jcustos.demo.skill.rest.security.model;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * In-memory {@link UserDirectory}.
 *
 * <p>Passwords are hashed and verified through the credential pipeline
 * the bootstrap configured ({@code JCustosServiceResolver.credentialHashingService()},
 * looked up per call, so the directory may be created before
 * {@code install()}). A hash that the pipeline reports as outdated is
 * replaced on the next successful login.
 *
 * <p>The directory starts <strong>empty</strong>. The fixed-password
 * demo accounts
 * <ul>
 *   <li>{@code admin / admin} — ADMIN + USER roles</li>
 *   <li>{@code user / user} — USER role only</li>
 * </ul>
 * exist only when the development switch
 * {@value #INSECURE_SEED_ACCOUNTS_PROPERTY}{@code =true} is set, and the
 * server refuses to start with it outside {@code DEVELOPMENT} mode.
 * <strong>Migrate to the InitialAdminBootstrapService token flow
 * ({@code jcustos-rest-persistence}) before any deployment.</strong>
 */
public final class InMemoryUserDirectory implements UserDirectory, HasLogger {

  /**
   * Development switch for the fixed-password demo accounts. Off by default
   * (JS-SEC-137): a copied server must not be administrable with
   * {@code admin/admin}.
   */
  public static final String INSECURE_SEED_ACCOUNTS_PROPERTY = "jcustos.demo.insecure-seed-accounts";

  private final Supplier<PasswordHashingService> hashing;
  private final Map<String, StoredUser> byUsername = new ConcurrentHashMap<>();
  private final Map<Long, User> byId = new ConcurrentHashMap<>();

  /** Hashes through the pipeline the bootstrap configured. */
  public InMemoryUserDirectory() {
    this.hashing = JCustosServiceResolver::credentialHashingService;
  }

  /** Hashes through {@code hashingService} — for tests and explicit wiring. */
  public InMemoryUserDirectory(PasswordHashingService hashingService) {
    Objects.requireNonNull(hashingService, "hashingService");
    this.hashing = () -> hashingService;
  }

  /** @return whether {@value #INSECURE_SEED_ACCOUNTS_PROPERTY} is set to {@code true} */
  public static boolean insecureSeedAccountsRequested() {
    return Boolean.getBoolean(INSECURE_SEED_ACCOUNTS_PROPERTY);
  }

  /**
   * Adds the fixed-password demo accounts. <strong>Development only.</strong>
   * Called by {@link UserDirectoryProvider} when
   * {@value #INSECURE_SEED_ACCOUNTS_PROPERTY} is set.
   */
  public synchronized void seedInsecureDemoAccounts() {
    logger().warn("{}=true: seeding fixed-password demo accounts - local development only",
        INSECURE_SEED_ACCOUNTS_PROPERTY);
    addUser("admin", "admin",
        new User(1L, "Administrator",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    addUser("user", "user",
        new User(2L, "Regular User",
            EnumSet.of(AuthorizationRole.USER)));
  }

  @Override
  public Optional<User> findByCredentials(Credentials credentials) {
    if (credentials == null
        || credentials.username() == null
        || credentials.password() == null) {
      return Optional.empty();
    }
    PasswordHashingService service = hashing.get();
    char[] raw = credentials.password().toCharArray();
    try {
      StoredUser stored = byUsername.get(credentials.username());
      if (stored == null) {
        // CWE-208: an unknown name costs one KDF run, like a wrong password.
        CredentialVerificationUnavailableException.throwIfUnavailable(
            service.verifyAgainstNothing(raw));
        return Optional.empty();
      }
      CredentialVerificationResult result = service.verify(raw, stored.passwordHash);
      // JS-SEC-126: "could not verify" is not "wrong" - the caller answers "try again later".
      CredentialVerificationUnavailableException.throwIfUnavailable(result);
      if (!(result instanceof CredentialVerificationResult.Verified)) {
        return Optional.empty();
      }
      if (service.needsRehash(stored.passwordHash) instanceof RehashDecision.Required) {
        rehash(credentials.username(), stored, raw, service);
      }
      return Optional.of(stored.user);
    } finally {
      Arrays.fill(raw, '\0');
    }
  }

  /**
   * Replaces an outdated hash after a successful login. A failure keeps the
   * old hash and the login: a provider can refuse a legacy password for the
   * new parameters (bcrypt: longer than 71 bytes or containing U+0000,
   * JS-SEC-133) — such a user has to choose a new password.
   */
  private void rehash(String username, StoredUser stored, char[] raw, PasswordHashingService service) {
    try {
      String freshHash = service.hash(raw).encodedHash();
      byUsername.computeIfPresent(username, (k, current) ->
          current == stored ? new StoredUser(stored.user, freshHash) : current);
    } catch (RuntimeException failure) {
      logger().warn("Password hash of user id {} could not be upgraded ({}); "
          + "the user has to choose a new password", stored.user.id(), failure.getClass().getName());
    }
  }

  @Override
  public Optional<User> findById(Long id) {
    return id == null ? Optional.empty() : Optional.ofNullable(byId.get(id));
  }

  @Override
  public Stream<User> all() {
    return byUsername.values().stream().map(stored -> stored.user);
  }

  @Override
  public boolean hasAnyAdministrator() {
    return byUsername.values().stream()
        .anyMatch(stored -> stored.user.roles().contains(AuthorizationRole.ADMIN));
  }

  @Override
  public synchronized void registerWithHashedPassword(String username, String passwordHash, User user) {
    if (byUsername.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    byUsername.put(username, new StoredUser(user, passwordHash));
    byId.put(user.id(), user);
  }

  @Override
  public synchronized void addUser(String username, String plaintextPassword, User user) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(plaintextPassword);
    Objects.requireNonNull(user);
    String hash = hashing.get().hash(plaintextPassword.toCharArray()).encodedHash();
    byUsername.put(username, new StoredUser(user, hash));
    byId.put(user.id(), user);
    audit(new UserCreated(Instant.now(Clock.systemUTC()), username, firstRoleOf(user), null));
  }

  @Override
  public synchronized void deleteUser(Long id) {
    User removed = byId.remove(id);
    if (removed == null) return;
    String username = byUsername.entrySet().stream()
        .filter(e -> e.getValue().user.equals(removed))
        .map(Map.Entry::getKey)
        .findFirst().orElse(null);
    byUsername.values().removeIf(stored -> stored.user.equals(removed));
    if (username != null) {
      audit(new UserDeleted(Instant.now(Clock.systemUTC()), username, null));
    }
  }

  @Override
  public synchronized void assignRole(Long id, AuthorizationRole role) {
    Objects.requireNonNull(role, "role");
    if (id == null) return;
    User current = byId.get(id);
    if (current == null || current.roles().contains(role)) return;
    EnumSet<AuthorizationRole> next = roleSetOf(current);
    next.add(role);
    replace(current, new User(current.id(), current.name(), next));
    audit(new RoleAssigned(Instant.now(Clock.systemUTC()),
        current.id().toString(), role.name(), null));
  }

  @Override
  public synchronized void revokeRole(Long id, AuthorizationRole role) {
    Objects.requireNonNull(role, "role");
    if (id == null) return;
    User current = byId.get(id);
    if (current == null || !current.roles().contains(role)) return;
    EnumSet<AuthorizationRole> next = roleSetOf(current);
    next.remove(role);
    replace(current, new User(current.id(), current.name(), next));
    audit(new RoleRevoked(Instant.now(Clock.systemUTC()),
        current.id().toString(), role.name(), null));
  }

  @Override
  public PasswordHashingService hashingService() {
    return hashing.get();
  }

  /** Test seam: the stored hash of {@code username}, or empty. */
  public Optional<String> storedPasswordHash(String username) {
    StoredUser stored = byUsername.get(username);
    return stored == null ? Optional.empty() : Optional.of(stored.passwordHash);
  }

  private static EnumSet<AuthorizationRole> roleSetOf(User user) {
    EnumSet<AuthorizationRole> set = EnumSet.noneOf(AuthorizationRole.class);
    set.addAll(user.roles());
    return set;
  }

  private static String firstRoleOf(User user) {
    if (user.roles().contains(AuthorizationRole.ADMIN)) return AuthorizationRole.ADMIN.name();
    if (user.roles().contains(AuthorizationRole.USER)) return AuthorizationRole.USER.name();
    return "USER";
  }

  private void replace(User oldUser, User newUser) {
    byId.put(newUser.id(), newUser);
    byUsername.replaceAll((username, stored) ->
        stored.user.equals(oldUser) ? new StoredUser(newUser, stored.passwordHash) : stored);
  }

  private static void audit(eu.jsentinel.jcustos.audit.AuditEvent event) {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // audit must never block user-management calls
    }
  }

  private record StoredUser(User user, String passwordHash) {
  }
}
