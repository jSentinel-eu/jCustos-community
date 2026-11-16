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

import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Demo-side user directory contract. Decoupled from the concrete
 * {@code InMemoryDemoUserDirectory} implementation so different storage
 * back-ends (database, LDAP, IAM) can plug in without touching the
 * consumers.
 * <p>
 * Lives in {@code demo-vaadin} on purpose — it is demo-specific. The
 * project-neutral abstractions are
 * {@link eu.jsentinel.jcustos.authentication.AuthenticationService}
 * and {@link eu.jsentinel.jcustos.bootstrap.AdministratorAccountStore}.
 */
public interface DemoUserDirectory {

  /** @return user matching the credentials, or empty if unknown / wrong password */
  Optional<MyUser> findByCredentials(Credentials credentials);

  /** Convenience boolean counterpart of {@link #findByCredentials(Credentials)}. */
  default boolean checkCredentials(Credentials credentials) {
    return findByCredentials(credentials).isPresent();
  }

  /** @return user with the given id, if present */
  Optional<MyUser> findById(Long id);

  /** All known users. The returned stream is independent of the directory state. */
  Stream<MyUser> all();

  /** @return {@code true} if at least one user has the {@code ADMIN} role */
  boolean hasAnyAdministrator();

  /**
   * Adds a user with a plaintext password. Demo-only — the password is
   * hashed at storage time but never stored as plaintext.
   */
  void addUser(String username, String plaintextPassword, MyUser user);

  /**
   * Adds a user whose password is already hashed by the bootstrap service.
   * Used by {@code VaadinAdministratorAccountStore} when the first
   * administrator is created via the bootstrap flow.
   */
  void registerWithHashedPassword(String username, String passwordHash, MyUser user);

  /** Removes the user with the given id. No-op if unknown. */
  void deleteUser(Long id);

  /**
   * Removes any pre-populated administrator entries. Called by the
   * bootstrap wiring before the first-run setup so the demo cannot fall
   * back to a pre-installed admin account.
   */
  void enableBootstrapMode();

  /**
   * The credential pipeline this directory hashes and verifies passwords
   * with. The first-administrator setup must hash with the same pipeline,
   * otherwise the administrator it creates cannot log in (JS-SEC-134).
   */
  PasswordHashingService hashingService();

  /**
   * Adds {@code role} to the user identified by {@code id}. No-op if the
   * user already has the role or the id is unknown. Implementations that
   * persist users immutably must rebuild and re-store the {@link MyUser}.
   * Implementations that emit audit events should publish a
   * {@code RoleAssigned} entry.
   * <p>
   * Default throws — directories that don't support role mutation should
   * leave this method untouched and reject the call at the boundary.
   */
  default void assignRole(Long id, AuthorizationRole role) {
    throw new UnsupportedOperationException("role assignment not supported");
  }

  /**
   * Removes {@code role} from the user identified by {@code id}. No-op if
   * the user doesn't have the role or the id is unknown. Implementations
   * should publish a {@code RoleRevoked} audit entry.
   */
  default void revokeRole(Long id, AuthorizationRole role) {
    throw new UnsupportedOperationException("role revocation not supported");
  }
}
