package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

/**
 * Persisted user record — {@link User} plus the hashed
 * password as it should be stored by any {@link UserDirectoryPersistence}
 * implementation.
 *
 * <p>Top-level public record (no inner type) so Eclipse-Store's
 * type-mapping sees the same canonical class regardless of which
 * persistence backend reads / writes it.
 *
 * <p>The password hash is opaque to the persistence layer — the
 * format (the {@code $pwh$v=1$…} envelope of PBKDF2, Argon2id, …)
 * lives entirely inside the
 * {@link eu.jsentinel.jcustos.credential.password.PasswordHashingService}
 * the directory hashes with.
 */
public record StoredUser(User user, String passwordHash) {
}
