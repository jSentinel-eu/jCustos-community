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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.RehashDecision;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory demo user store. Demo-only — not for production.
 * <p>
 * JS-SEC-137 (CWE-798, CWE-1188): the store starts <strong>empty</strong>. Accounts with
 * fixed, publicly known passwords ({@code editor/editor}, {@code viewer/viewer} and, without
 * a bootstrap flow, {@code admin/admin}) are created only when the caller asks for them by
 * name with {@link InsecureSeed}; the server does so only when the development switch
 * {@value #INSECURE_SEED_ACCOUNTS_PROPERTY} is set. The first administrator of a regular
 * start comes from the bootstrap mechanism.
 * <p>
 * {@link #authenticate(String, String)} runs a key derivation for unknown user names as
 * well (CWE-203, CWE-208) and reports a verification the KDF limiter shed as
 * {@link CredentialVerificationUnavailableException}, never as a wrong password
 * (JS-SEC-126).
 */
public final class DemoUserStore implements HasLogger {

  /**
   * Development switch for the fixed-password demo accounts (JS-SEC-137). Off unless the
   * system property is exactly {@code true}. Never set it on anything reachable by others.
   */
  public static final String INSECURE_SEED_ACCOUNTS_PROPERTY = "jcustos.demo.insecure-seed-accounts";

  /** Which fixed-password demo accounts a new store is seeded with. */
  public enum InsecureSeed {
    /** No accounts; the regular start. */
    NONE,
    /** {@code editor/editor} and {@code viewer/viewer}. */
    DEMO_ACCOUNTS,
    /** {@code editor/editor}, {@code viewer/viewer} and {@code admin/admin}. */
    DEMO_ACCOUNTS_AND_ADMINISTRATOR
  }

  private final Map<String, DemoUser> users = new LinkedHashMap<>();
  private final PasswordHashingService hashingService;

  /**
   * Creates an empty store.
   *
   * @param hashingService the password-hashing pipeline; non-null
   */
  public DemoUserStore(PasswordHashingService hashingService) {
    this(hashingService, InsecureSeed.NONE);
  }

  /**
   * Creates a store with the named fixed-password demo accounts.
   *
   * @param hashingService the password-hashing pipeline; non-null
   * @param seed           which demo accounts to create; non-null
   */
  public DemoUserStore(PasswordHashingService hashingService, InsecureSeed seed) {
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    Objects.requireNonNull(seed, "seed");
    if (seed == InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR) {
      register("admin", "admin", "Admin User", DemoRole.ROLE_ADMIN);
    }
    if (seed != InsecureSeed.NONE) {
      register("editor", "editor", "Editor User", DemoRole.ROLE_EDITOR);
      register("viewer", "viewer", "Viewer User", DemoRole.ROLE_VIEWER);
      logger().warn("Development switch {} is on: {} demo account(s) with fixed, publicly "
              + "known passwords were created. Never expose this instance.",
          INSECURE_SEED_ACCOUNTS_PROPERTY, users.size());
    }
  }

  /**
   * @return {@code true} when the development switch {@value #INSECURE_SEED_ACCOUNTS_PROPERTY}
   *         is set to {@code true}
   */
  public static boolean insecureSeedAccountsRequested() {
    return Boolean.getBoolean(INSECURE_SEED_ACCOUNTS_PROPERTY);
  }

  private void register(String username, String plaintextPassword, String displayName, DemoRole role) {
    String hash = hashingService.hash(plaintextPassword.toCharArray()).encodedHash();
    users.put(username, new DemoUser(username, displayName, hash, role));
  }

  /**
   * Verifies a user name and password.
   *
   * @param username user name as typed
   * @param password password as typed
   * @return the user when the password verified, otherwise empty
   * @throws CredentialVerificationUnavailableException when the verification could not be
   *         carried out - the KDF limiter shed it (JS-SEC-126). That is no verdict: the
   *         caller answers "try again later" and counts no failed attempt.
   */
  public synchronized Optional<DemoUser> authenticate(String username, String password) {
    char[] raw = password.toCharArray();
    DemoUser user = users.get(username);
    if (user == null) {
      // unknown user — still run a comparable dummy KDF so the response
      // is not distinguishable from a wrong password (CWE-203, CWE-208)
      CredentialVerificationUnavailableException.throwIfUnavailable(
          hashingService.verifyAgainstNothing(raw));
      return Optional.empty();
    }
    CredentialVerificationResult result =
        hashingService.verify(raw, user.passwordHash());
    // JS-SEC-126 (CWE-703): a shed verification is "could not verify", not "wrong".
    CredentialVerificationUnavailableException.throwIfUnavailable(result);
    if (!(result instanceof CredentialVerificationResult.Verified)) {
      return Optional.empty();
    }
    DemoUser current = user;
    RehashDecision rehash = hashingService.needsRehash(current.passwordHash());
    if (rehash instanceof RehashDecision.Required) {
      try {
        String freshHash = hashingService.hash(raw).encodedHash();
        DemoUser upgraded = new DemoUser(
            current.username(), current.displayName(), freshHash, current.role());
        users.put(upgraded.username(), upgraded);
        current = upgraded;
      } catch (RuntimeException rehashFailure) {
        // Login already succeeded against the existing hash. A rehash can fail for a
        // password the new algorithm refuses - JS-SEC-133: bcrypt rejects a legacy password
        // of 72 bytes or one containing U+0000 - so the old hash stays and the user has to
        // choose a new password. Only the exception type is logged, never the password.
        logger().warn("Password hash of a user could not be upgraded ({}); the old hash stays "
            + "in place and the user should choose a new password.",
            rehashFailure.getClass().getSimpleName());
      }
    }
    return Optional.of(current);
  }

  /** Test seam: returns the stored hash for the given username, or empty. */
  public synchronized Optional<String> storedPasswordHash(String username) {
    DemoUser user = users.get(username);
    return user == null ? Optional.empty() : Optional.of(user.passwordHash());
  }

  public synchronized void register(DemoUser user) {
    if (users.containsKey(user.username())) {
      throw new IllegalStateException("user already exists: " + user.username());
    }
    users.put(user.username(), user);
    audit(new UserCreated(
        Instant.now(Clock.systemUTC()),
        user.username(), user.role().name(), null));
  }

  /**
   * Hashes the plaintext password and registers the new user. Throws
   * {@link IllegalStateException} if the username already exists. Emits
   * a {@link UserCreated} audit event on success.
   */
  public synchronized DemoUser create(
      String username, String plaintextPassword, String displayName, DemoRole role) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(plaintextPassword, "password");
    Objects.requireNonNull(role, "role");
    if (users.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    String hash = hashingService.hash(plaintextPassword.toCharArray()).encodedHash();
    DemoUser user = new DemoUser(
        username, displayName == null ? username : displayName, hash, role);
    users.put(username, user);
    audit(new UserCreated(
        Instant.now(Clock.systemUTC()), username, role.name(), null));
    return user;
  }

  /**
   * Removes the user identified by {@code username}. No-op if unknown.
   * Emits a {@link UserDeleted} audit event when a real deletion occurs.
   *
   * @return {@code true} if a user was removed
   */
  public synchronized boolean deleteUser(String username) {
    Objects.requireNonNull(username, "username");
    DemoUser removed = users.remove(username);
    if (removed == null) {
      return false;
    }
    audit(new UserDeleted(
        Instant.now(Clock.systemUTC()), username, null));
    return true;
  }

  public synchronized boolean hasAnyAdministrator() {
    return users.values().stream().anyMatch(u -> u.role() == DemoRole.ROLE_ADMIN);
  }

  /**
   * Snapshot of all registered users, in insertion order. Used by the
   * {@code GET /api/admin/users} endpoint that backs the rest-client
   * Role-Admin-UI.
   */
  public synchronized List<DemoUser> listAll() {
    return List.copyOf(users.values());
  }

  /**
   * Replaces the role of the user identified by {@code username}. No-op
   * if the user is unknown or already has the role. On a real change
   * publishes both a {@link RoleRevoked} (for the previous role) and a
   * {@link RoleAssigned} (for the new role) audit event; audit failures
   * are swallowed so the mutation always succeeds.
   *
   * @return {@code true} if a change was applied
   */
  public synchronized boolean setRole(String username, DemoRole newRole) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(newRole, "newRole");
    DemoUser current = users.get(username);
    if (current == null || current.role() == newRole) {
      return false;
    }
    DemoUser updated = new DemoUser(
        current.username(), current.displayName(), current.passwordHash(), newRole);
    users.put(username, updated);
    audit(new RoleRevoked(
        Instant.now(Clock.systemUTC()),
        username, current.role().name(), null));
    audit(new RoleAssigned(
        Instant.now(Clock.systemUTC()),
        username, newRole.name(), null));
    return true;
  }

  private static void audit(AuditEvent event) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // never block role admin because the audit sink failed
    }
  }
}
