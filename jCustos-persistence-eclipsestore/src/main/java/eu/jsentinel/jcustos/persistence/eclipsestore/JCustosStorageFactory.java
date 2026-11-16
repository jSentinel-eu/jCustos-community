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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.util.CapacityBound;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Entry point for opening a {@link JCustosStoragePair} — the
 * Phase-1-Public-API of the V00.74.20 Storage-Pair architecture.
 *
 * <p>Consumers open a pair once at process startup and close it once
 * at shutdown:
 *
 * <pre>{@code
 * try (var pair = JCustosStorageFactory.openAt(Path.of("/var/data/myapp"))) {
 *   VaadinSecurity.bootstrap()
 *       .audit(a -> a.storeBacked(pair.framework().auditEventStore()))
 *       .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
 *       .install();
 *   // Use pair.app() for domain data via app.root()
 * }
 * }</pre>
 *
 * <p>The {@code openAt(Path)} overload defaults to
 * {@link StorageLayout#DEFAULT}. Consumers who need a non-default
 * sub-directory layout (e.g. {@code new StorageLayout(".", "users")}
 * to retain the V00.70 single-storage layout) pass the explicit
 * overload.
 *
 * <p>This Phase-1 skeleton throws {@link UnsupportedOperationException}
 * from the two-arg overload; the real implementation lands in
 * Prompt 005 of the V00.74.20 plan.
 *
 * @since 00.74.20
 */
@ExperimentalJCustosApi
public final class JCustosStorageFactory {

  private JCustosStorageFactory() {
    // utility class — never instantiated
  }

  /**
   * Opens a storage pair under {@code parent} using
   * {@link StorageLayout#DEFAULT}.
   *
   * @param parent parent directory under which the framework and app
   *               sub-directories will be created or read
   * @return a freshly opened {@link JCustosStoragePair}
   * @throws NullPointerException     if {@code parent} is {@code null}
   * @throws IllegalArgumentException with one of the Konzept §6
   *                                  validation codes if {@code parent}
   *                                  exists and is not a writable
   *                                  directory
   */
  public static JCustosStoragePair openAt(Path parent) {
    return openAt(parent, StorageLayout.DEFAULT);
  }

  /**
   * Opens a storage pair under {@code parent} using the supplied
   * {@code layout}.
   *
   * @param parent parent directory under which the framework and app
   *               sub-directories will be created or read
   * @param layout sub-directory layout to use
   * @return a freshly opened {@link JCustosStoragePair}
   * @throws NullPointerException     if either argument is {@code null}
   * @throws IllegalArgumentException with one of the Konzept §6
   *                                  validation codes if {@code parent}
   *                                  exists and is not a writable
   *                                  directory
   * @throws IllegalStateException    {@code persistence/storage-permissions} or
   *                                  {@code persistence/foreign-root}, see
   *                                  {@link #openAt(Path, StorageLayout, int)}
   */
  public static JCustosStoragePair openAt(Path parent, StorageLayout layout) {
    return openAt(parent, layout, EclipseStoreJCustosStorage.DEFAULT_MAX_ENTRIES_PER_STORE);
  }

  /**
   * Opens a storage pair under {@code parent} with an explicit bound for the
   * framework stores that are filled with keys arriving in requests
   * (JS-SEC-125, CWE-770) — see
   * {@link EclipseStoreJCustosStorage#openAt(Path, int)}.
   *
   * @param parent             parent directory under which the framework and
   *                           app sub-directories will be created or read
   * @param layout             sub-directory layout to use
   * @param maxEntriesPerStore upper bound on the entries of each
   *                           request-keyed framework store; at least 1
   * @return a freshly opened {@link JCustosStoragePair}
   * @throws NullPointerException     if {@code parent} or {@code layout} is {@code null}
   * @throws IllegalArgumentException as for {@link #openAt(Path, StorageLayout)},
   *                                  or when {@code maxEntriesPerStore < 1}
   * @throws IllegalStateException    {@code persistence/storage-permissions} when a storage
   *                                  directory cannot be restricted to its owner on POSIX,
   *                                  {@code persistence/foreign-root} when the framework
   *                                  directory holds another application's storage (JS-SEC-136)
   * @since 00.84.00
   */
  public static JCustosStoragePair openAt(Path parent, StorageLayout layout,
                                          int maxEntriesPerStore) {
    Objects.requireNonNull(parent, "parent");
    Objects.requireNonNull(layout, "layout");
    CapacityBound.requirePositiveCapacity(maxEntriesPerStore);
    ensureParentIsWritableDirectory(parent);
    // JS-SEC-136 (CWE-367): the app storage starts at the directory the check resolved
    Path appDir = hardenStorageTree(parent, layout);

    Path frameworkDir = parent.resolve(layout.frameworkSubdir());

    EmbeddedStorageManager frameworkMgr = null;
    EmbeddedStorageManager appMgr       = null;
    try {
      frameworkMgr = EclipseStoreJCustosStorage.initStorageManager(frameworkDir);
      appMgr       = EmbeddedStorage.start(appDir);
      StorageTreeHardening.restrictStorageFiles(appDir, "persistence/storage-permissions");
      return new JCustosStoragePair(
          new EclipseStoreJCustosStorage(frameworkMgr, maxEntriesPerStore, Clock.systemUTC()),
          appMgr,
          parent,
          layout,
          new AtomicBoolean(false));
    } catch (RuntimeException openFailure) {
      // Roll back any half-opened manager. The original failure is the
      // one consumers care about; secondary shutdown failures get
      // swallowed by safelyShutdown so they cannot mask the primary.
      safelyShutdown(appMgr);
      safelyShutdown(frameworkMgr);
      throw openFailure;
    }
  }

  /**
   * Validates that {@code parent} either does not yet exist (then the
   * Eclipse-Store {@code start(dir)} call will create it) or, if it
   * exists, is a writable directory. Carries the Konzept §6 codes
   * {@code persistence/storage-pair-parent-not-directory} and
   * {@code persistence/storage-pair-parent-not-writable} in the
   * IllegalArgumentException message.
   */
  private static void ensureParentIsWritableDirectory(Path parent) {
    if (!Files.exists(parent)) {
      return; // EmbeddedStorage.start will create it
    }
    if (!Files.isDirectory(parent)) {
      throw new IllegalArgumentException(
          "persistence/storage-pair-parent-not-directory: " + parent);
    }
    if (!Files.isWritable(parent)) {
      throw new IllegalArgumentException(
          "persistence/storage-pair-parent-not-writable: " + parent);
    }
  }

  /**
   * JS-SEC-017 (CWE-276): pre-create the storage tree owner-only ({@code 0700})
   * on POSIX before {@code EmbeddedStorage.start}, so the framework store — which holds
   * session handles, role assignments, login-attempt records and token hashes — is never
   * group/other-readable under a default umask.
   *
   * <p>RF (exit-review): hardening runs through the single {@link StorageTreeHardening}
   * helper (was a private copy that duplicated the facade + events-module logic). The
   * framework sub-directory is intentionally <em>not</em> hardened here — it is hardened
   * downstream by {@link EclipseStoreJCustosStorage#initStorageManager(Path)}, so hardening
   * it here too would harden it twice. Only the parent and the app sub-directory (opened via a
   * bare {@code EmbeddedStorage.start}) need hardening at this level.
   *
   * <p>JS-SEC-136 (CWE-276, CWE-732): existing directories are restricted too. The parent is
   * restricted when it belongs to the process user and reported otherwise; the two storage
   * directories must be owner-only, and one that cannot be made so stops the open.
   *
   * @return the real path of the checked app directory, where the app storage is started
   */
  private static Path hardenStorageTree(Path parent, StorageLayout layout) {
    StorageTreeHardening.hardenOwnerOnly(parent, "persistence/storage-permissions",
        "the framework store holds session handles, roles and token hashes");
    return StorageTreeHardening.requireOwnerOnlyDirectory(parent.resolve(layout.appSubdir()),
        "persistence/storage-permissions",
        "the app store shares the framework's owner-only tree");
  }

  /**
   * Best-effort shutdown of a possibly-null storage manager during
   * roll-back. Secondary failures are swallowed because the original
   * open-failure is what the caller needs to see.
   */
  private static void safelyShutdown(EmbeddedStorageManager mgr) {
    if (mgr == null) return;
    try {
      mgr.shutdown();
    } catch (RuntimeException secondary) {
      // Swallow — primary openFailure is rethrown by the caller.
    }
  }
}
