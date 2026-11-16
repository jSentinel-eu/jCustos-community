package eu.jsentinel.jcustos.demo.skill.vaadin.security.model;

import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Application user store. Decoupled from the concrete in-memory
 * implementation so a future backend swap (DB, LDAP, IAM) does not
 * touch consumers.
 */
public interface UserDirectory {

  /**
   * Looks the user up and verifies the password.
   *
   * @return the user when the password matches, otherwise empty
   * @throws eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException
   *     when the password could not be checked (the KDF limiter shed the
   *     verification, JS-SEC-126) - "try again later", not "wrong password"
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
   * the directory's own hasher.
   */
  void registerWithHashedPassword(String username, String passwordHash, User user);

  void deleteUser(Long id);

  /** @return {@code true} if at least one user has the {@code ADMIN} role */
  boolean hasAnyAdministrator();

  void assignRole(Long id, AuthorizationRole role);

  void revokeRole(Long id, AuthorizationRole role);

  /**
   * The credential pipeline this directory hashes and verifies with - the
   * service the bootstrap configured with {@code .credentials(c -> c.hashing(...))}
   * (JS-SEC-134). The first-administrator setup hashes with the same service,
   * so the administrator it creates can log in.
   */
  PasswordHashingService hashingService();
}
