package eu.jsentinel.jcustos.demo.skill.rest.security.model;

import java.util.Objects;

/**
 * Static holder for the {@link UserDirectory} singleton.
 *
 * <p>Needed because consumers loaded via {@link java.util.ServiceLoader}
 * — {@code MyAuthenticationService},
 * {@code MyAuthorizationService} — cannot receive the
 * directory through constructor injection. The default directory is
 * created on first use; tests can replace it via
 * {@link #setDirectory(UserDirectory)} and reset with {@link #reset()}.
 */
public final class UserDirectoryProvider {

  private static volatile UserDirectory directory;

  private UserDirectoryProvider() {
  }

  public static UserDirectory directory() {
    UserDirectory local = directory;
    if (local != null) return local;
    synchronized (UserDirectoryProvider.class) {
      if (directory == null) directory = buildDefault();
      return directory;
    }
  }

  /** Test seam — install a custom directory. */
  public static void setDirectory(UserDirectory replacement) {
    directory = Objects.requireNonNull(replacement, "replacement");
  }

  /** Test seam — the default directory is rebuilt on next use. */
  public static synchronized void reset() {
    directory = null;
  }

  private static UserDirectory buildDefault() {
    InMemoryUserDirectory created = new InMemoryUserDirectory();
    if (InMemoryUserDirectory.insecureSeedAccountsRequested()) {
      created.seedInsecureDemoAccounts();
    }
    return created;
  }
}
