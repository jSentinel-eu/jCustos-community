package eu.jsentinel.jcustos.demo.skill.vaadin.security.model;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Replacement for the layer-1 {@code jcustos-vaadin} provider.
 *
 * <p>Default wires an {@link EclipseStoreUserDirectoryPersistence}
 * under {@code ./data/jcustos-vaadin-persistence/users}, then injects it into a
 * {@link PersistentUserDirectory}. The Eclipse-Store-backed
 * persistence runs in its own {@code EmbeddedStorageManager}
 * independent of the framework storage.
 *
 * <p>Lazy via the
 * <a href="https://en.wikipedia.org/wiki/Initialization-on-demand_holder_idiom">
 * Initialization-on-Demand Holder</a> idiom: the storage is opened the
 * first time {@link #directory()} is called <em>and</em> no test
 * override is installed via {@link #setDirectory(UserDirectory)}. So
 * loading {@code UserDirectoryProvider} (e.g. by a static-analysis
 * tool or a PIT mutation worker) does NOT touch the filesystem.
 *
 * <p>Test seam: {@link #setDirectory(UserDirectory)} swaps the
 * singleton — pair with {@link InMemoryUserDirectoryPersistence} for
 * stateless tests. Call it <em>before</em> any production call to
 * {@link #directory()} to keep the holder uninitialised.
 */
public final class UserDirectoryProvider {

  public static final Path USERS_STORAGE_DIR = Path.of("./data/jcustos-vaadin-persistence/users");

  /**
   * Test seam — installed via {@link #setDirectory(UserDirectory)}.
   * When non-null this wins over the lazy holder.
   */
  private static volatile UserDirectory override;

  private UserDirectoryProvider() {
  }

  /**
   * Holder class — the JVM guarantees that {@code INSTANCE} is
   * initialised on first read of {@link Holder}, not at load time
   * of {@link UserDirectoryProvider}.
   */
  private static final class Holder {
    static final UserDirectory INSTANCE = buildDefault();
  }

  public static UserDirectory directory() {
    UserDirectory swap = override;
    return swap != null ? swap : Holder.INSTANCE;
  }

  /** Test seam — install a custom directory. */
  public static void setDirectory(UserDirectory replacement) {
    override = Objects.requireNonNull(replacement, "replacement");
  }

  /**
   * Test seam — clear any test override. The next call to
   * {@link #directory()} returns {@link Holder#INSTANCE} (constructing
   * it lazily if not yet initialised).
   */
  public static void reset() {
    override = null;
  }

  private static UserDirectory buildDefault() {
    UserDirectoryPersistence persistence =
        new EclipseStoreUserDirectoryPersistence(USERS_STORAGE_DIR);
    Runtime.getRuntime().addShutdownHook(new Thread(persistence::close,
        "user-directory-persistence-shutdown"));
    // JS-SEC-134: hash and verify with the service the bootstrap configured,
    // resolved per call - the same one the first-administrator setup uses.
    return new PersistentUserDirectory(persistence, ConfiguredHashingService.INSTANCE);
  }
}
