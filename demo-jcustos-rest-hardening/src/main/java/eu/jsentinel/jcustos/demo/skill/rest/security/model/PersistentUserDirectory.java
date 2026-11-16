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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Persistent {@link UserDirectory} backed by an injected
 * {@link UserDirectoryPersistence} — usually
 * {@link EclipseStoreUserDirectoryPersistence} in production,
 * {@link InMemoryUserDirectoryPersistence} in tests.
 *
 * <p>The directory keeps an in-memory working copy
 * ({@code byUsername} / {@code byId}) for fast reads. Every mutation
 * pushes a fresh snapshot to the persistence layer; failures are
 * logged at {@code ERROR} <em>before</em> the exception propagates,
 * so callers (e.g. {@code InitialAdminBootstrapService}) that catch
 * blanket {@code RuntimeException} still leave a diagnostic trail.
 *
 * <p>Passwords are hashed and verified through the credential pipeline
 * the bootstrap configured ({@code JCustosServiceResolver.credentialHashingService()},
 * looked up per call) — the same pipeline the first-admin bootstrap
 * hashes with, so the administrator it creates can log in (JS-SEC-134).
 * A hash the pipeline reports as outdated is replaced on the next
 * successful login.
 *
 * <p>Compared to the previous {@code users.ser}-based design this
 * avoids Java serialization entirely — neither {@link User}
 * nor {@link StoredUser} needs to implement
 * {@link java.io.Serializable}; record-header changes evolve via
 * Eclipse-Store's type-mapping.
 */
public final class PersistentUserDirectory implements UserDirectory, HasLogger {

  private final UserDirectoryPersistence persistence;
  private final Supplier<PasswordHashingService> hashing;
  private final Map<String, StoredUser> byUsername = new ConcurrentHashMap<>();
  private final Map<Long, User> byId = new ConcurrentHashMap<>();

  /** Hashes through the pipeline the bootstrap configured. */
  public PersistentUserDirectory(UserDirectoryPersistence persistence) {
    this(persistence, JCustosServiceResolver::credentialHashingService);
  }

  /** Hashes through {@code hashingService} — for tests and explicit wiring. */
  public PersistentUserDirectory(UserDirectoryPersistence persistence,
                                 PasswordHashingService hashingService) {
    this(persistence, constant(hashingService));
  }

  private PersistentUserDirectory(UserDirectoryPersistence persistence,
                                  Supplier<PasswordHashingService> hashing) {
    this.persistence = Objects.requireNonNull(persistence, "persistence");
    this.hashing = hashing;
    Map<String, StoredUser> snapshot = persistence.load();
    snapshot.forEach((username, stored) -> {
      byUsername.put(username, stored);
      byId.put(stored.user().id(), stored.user());
    });
    logger().info("PersistentUserDirectory loaded {} user(s)", snapshot.size());
  }

  // ── UserDirectory ──────────────────────────────────────────────

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
      CredentialVerificationResult result = service.verify(raw, stored.passwordHash());
      // JS-SEC-126: "could not verify" is not "wrong" - the caller answers "try again later".
      CredentialVerificationUnavailableException.throwIfUnavailable(result);
      if (!(result instanceof CredentialVerificationResult.Verified)) {
        return Optional.empty();
      }
      if (service.needsRehash(stored.passwordHash()) instanceof RehashDecision.Required) {
        rehash(credentials.username(), stored, raw, service);
      }
      return Optional.of(stored.user());
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
  private synchronized void rehash(String username, StoredUser stored, char[] raw,
                                   PasswordHashingService service) {
    try {
      String fresh = service.hash(raw).encodedHash();
      if (byUsername.get(username) == stored) {
        byUsername.put(username, new StoredUser(stored.user(), fresh));
        save();
      }
    } catch (RuntimeException failure) {
      logger().warn("Password hash of user id {} could not be upgraded ({}); "
          + "the user has to choose a new password", stored.user().id(), failure.getClass().getName());
    }
  }

  @Override
  public Optional<User> findById(Long id) {
    return id == null ? Optional.empty() : Optional.ofNullable(byId.get(id));
  }

  @Override
  public Stream<User> all() {
    return byUsername.values().stream().map(StoredUser::user);
  }

  @Override
  public boolean hasAnyAdministrator() {
    return byUsername.values().stream()
        .anyMatch(stored -> stored.user().roles().contains(AuthorizationRole.ADMIN));
  }

  @Override
  public synchronized void addUser(String username, String plaintextPassword, User user) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(plaintextPassword);
    Objects.requireNonNull(user);
    String hash = hashing.get().hash(plaintextPassword.toCharArray()).encodedHash();
    byUsername.put(username, new StoredUser(user, hash));
    byId.put(user.id(), user);
    save();
    audit(new UserCreated(Instant.now(Clock.systemUTC()), username, firstRoleOf(user), null));
  }

  @Override
  public synchronized void registerWithHashedPassword(String username, String passwordHash, User user) {
    if (byUsername.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    byUsername.put(username, new StoredUser(user, passwordHash));
    byId.put(user.id(), user);
    save();
  }

  @Override
  public synchronized void deleteUser(Long id) {
    User removed = byId.remove(id);
    if (removed == null) return;
    String username = byUsername.entrySet().stream()
        .filter(e -> e.getValue().user().equals(removed))
        .map(Map.Entry::getKey).findFirst().orElse(null);
    byUsername.values().removeIf(stored -> stored.user().equals(removed));
    save();
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
    save();
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
    save();
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
    return stored == null ? Optional.empty() : Optional.of(stored.passwordHash());
  }

  // ── Internal ───────────────────────────────────────────────────

  /**
   * Pushes the current state to the persistence layer. Logs the
   * username inventory at {@code ERROR} before re-throwing so the
   * jCustos-Core's blanket
   * {@code RuntimeException → InternalError("could not persist
   * administrator")} catch doesn't swallow all diagnostic info.
   */
  private void save() {
    try {
      Map<String, StoredUser> snapshot = new LinkedHashMap<>(byUsername);
      persistence.save(snapshot);
    } catch (RuntimeException failure) {
      logger().error("Failed to persist user directory ({} user(s) in memory): {}",
          byUsername.size(), failure.toString(), failure);
      throw failure;
    }
  }

  private void replace(User oldUser, User newUser) {
    byId.put(newUser.id(), newUser);
    byUsername.replaceAll((username, stored) ->
        stored.user().equals(oldUser) ? new StoredUser(newUser, stored.passwordHash()) : stored);
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

  private static Supplier<PasswordHashingService> constant(PasswordHashingService service) {
    Objects.requireNonNull(service, "hashingService");
    return () -> service;
  }

  private static void audit(eu.jsentinel.jcustos.audit.AuditEvent event) {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // audit must never block user-management calls
    }
  }
}
