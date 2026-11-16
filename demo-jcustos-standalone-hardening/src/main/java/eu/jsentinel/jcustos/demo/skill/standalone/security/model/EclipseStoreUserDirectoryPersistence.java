package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

import com.svenruppert.dependencies.core.logger.HasLogger;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Eclipse-Store-backed {@link UserDirectoryPersistence}.
 *
 * <p>Since V00.74.20 the persistence does <strong>not</strong> open
 * its own {@code EmbeddedStorageManager} — it shares the app-side
 * manager from the {@code JCustosStoragePair} that
 * {@link eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.JCustosStorageProvider}
 * maintains. The pair's lifecycle owns the shutdown.
 */
public final class EclipseStoreUserDirectoryPersistence
    implements UserDirectoryPersistence, HasLogger {

  public static final class AppUsersRoot {
    public Map<String, StoredUser> byUsername = new LinkedHashMap<>();
  }

  private final EmbeddedStorageManager manager;
  private final AppUsersRoot root;
  private final AtomicBoolean closed = new AtomicBoolean(false);

  public EclipseStoreUserDirectoryPersistence(EmbeddedStorageManager manager) {
    this.manager = Objects.requireNonNull(manager, "manager");
    Object existing = manager.root();
    if (existing instanceof AppUsersRoot loaded) {
      this.root = loaded;
    } else {
      this.root = new AppUsersRoot();
      manager.setRoot(this.root);
      manager.storeRoot();
    }
    logger().info("EclipseStoreUserDirectoryPersistence ready ({} user(s) loaded)",
        root.byUsername.size());
  }

  @Override
  public Map<String, StoredUser> load() {
    return new LinkedHashMap<>(root.byUsername);
  }

  @Override
  public void save(Map<String, StoredUser> snapshot) {
    if (closed.get()) {
      throw new IllegalStateException("persistence is closed");
    }
    root.byUsername.clear();
    root.byUsername.putAll(snapshot);
    manager.store(root.byUsername);
  }

  @Override
  public void close() {
    closed.compareAndSet(false, true);
  }
}
