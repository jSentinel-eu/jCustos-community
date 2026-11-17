package eu.jsentinel.jcustos.demo.skill.rest;

import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * A real directory whose credential check throws for one user name - the shape of a lookup that
 * breaks on a crafted input (XR09-6). Every other call reaches the directory underneath.
 */
final class BreakingUserDirectory implements UserDirectory {

  private final String breaksFor;
  private final UserDirectory delegate;

  BreakingUserDirectory(String breaksFor, UserDirectory delegate) {
    this.breaksFor = breaksFor;
    this.delegate = delegate;
  }

  @Override
  public Optional<User> findByCredentials(Credentials credentials) {
    if (breaksFor.equals(credentials.username())) {
      throw new IllegalStateException("the directory lookup failed on this input");
    }
    return delegate.findByCredentials(credentials);
  }

  @Override
  public Optional<User> findById(Long id) {
    return delegate.findById(id);
  }

  @Override
  public Stream<User> all() {
    return delegate.all();
  }

  @Override
  public void addUser(String username, String plaintextPassword, User user) {
    delegate.addUser(username, plaintextPassword, user);
  }

  @Override
  public void registerWithHashedPassword(String username, String passwordHash, User user) {
    delegate.registerWithHashedPassword(username, passwordHash, user);
  }

  @Override
  public void deleteUser(Long id) {
    delegate.deleteUser(id);
  }

  @Override
  public boolean hasAnyAdministrator() {
    return delegate.hasAnyAdministrator();
  }

  @Override
  public void assignRole(Long id, AuthorizationRole role) {
    delegate.assignRole(id, role);
  }

  @Override
  public void revokeRole(Long id, AuthorizationRole role) {
    delegate.revokeRole(id, role);
  }

  @Override
  public PasswordHashingService hashingService() {
    return delegate.hashingService();
  }
}
