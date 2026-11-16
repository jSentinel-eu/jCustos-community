package eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap;

import eu.jsentinel.jcustos.demo.skill.rest.security.storage.AppStoragePaths;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStorageFactory;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStoragePair;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

/**
 * Lazy singleton holder for the {@link JCustosStoragePair} that
 * carries both the jCustos framework storage and the application's
 * Eclipse-Store manager under one parent directory.
 *
 * <p>The first call to {@link #pair()} opens (or creates) the pair at
 * {@link AppStoragePaths#baseDir()} via
 * {@link JCustosStorageFactory#openAt(java.nio.file.Path)} and
 * registers one JVM shutdown hook. The pair's two-phase
 * {@code close()} closes the app storage first and the framework
 * storage second (V00.74.20+).
 *
 * <p>Tests can install a custom pair via
 * {@link #setPair(JCustosStoragePair)} before any consumer
 * initialises.
 */
public final class JCustosStorageProvider {

  private static volatile JCustosStoragePair current;

  private JCustosStorageProvider() {
  }

  public static JCustosStoragePair pair() {
    JCustosStoragePair local = current;
    if (local != null) return local;
    synchronized (JCustosStorageProvider.class) {
      if (current == null) {
        current = JCustosStorageFactory.openAt(AppStoragePaths.baseDir());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          JCustosStoragePair live = current;
          if (live != null) {
            live.close();
          }
        }, "jcustos-storage-pair-shutdown"));
      }
      return current;
    }
  }

  /** Convenience accessor for the framework storage. */
  public static EclipseStoreJCustosStorage framework() {
    return pair().framework();
  }

  /** Convenience accessor for the application storage manager. */
  public static EmbeddedStorageManager app() {
    return pair().app();
  }

  /** Test seam — install a custom pair before any production use. */
  public static synchronized void setPair(JCustosStoragePair replacement) {
    current = replacement;
  }
}
