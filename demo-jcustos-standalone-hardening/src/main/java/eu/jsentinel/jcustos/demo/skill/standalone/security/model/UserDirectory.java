package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.demo.skill.standalone.security.roles.AuthorizationRole;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Application user store. Decoupled from the concrete in-memory
 * implementation so a future backend swap (DB, LDAP, IAM) does not
 * touch consumers.
 */
public interface UserDirectory {

  /**
   * Verifies the credentials. An unknown username costs one KDF run like
   * a wrong password, so the answer time does not reveal which names exist
   * (CWE-208).
   *
   * @return the user, or empty for unknown name or wrong password
   * @throws CredentialVerificationUnavailableException when the
   *         verification was shed under load (JS-SEC-126) — neither a
   *         success nor a failed attempt; answer "try again later"
   */
  Optional<User> findByCredentials(Credentials credentials);

  default boolean checkCredentials(Credentials credentials) {
    return findByCredentials(credentials).isPresent();
  }

  Optional<User> findById(Long id);

  Stream<User> all();

  void addUser(String username, String plaintextPassword, User user);

  /**
   * Adds a user whose password was already hashed elsewhere (typically
   * the bootstrap flow's {@code InitialAdminBootstrapService}). Bypasses
   * the directory's own hashing — the hash must come from
   * {@link #hashingService()}, or the user cannot log in.
   */
  void registerWithHashedPassword(String username, String passwordHash, User user);

  void deleteUser(Long id);

  /** @return {@code true} if at least one user has the {@code ADMIN} role */
  boolean hasAnyAdministrator();

  void assignRole(Long id, AuthorizationRole role);

  void revokeRole(Long id, AuthorizationRole role);

  /**
   * The password pipeline the directory hashes and verifies with — the one
   * the bootstrap configured through {@code .credentials(c -> c.hashing(...))}
   * (JS-SEC-134). Every component that writes a password hash for this
   * directory must use it.
   */
  PasswordHashingService hashingService();
}
