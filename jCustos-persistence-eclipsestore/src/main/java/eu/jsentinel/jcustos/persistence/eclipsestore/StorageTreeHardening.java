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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Single home for the POSIX owner-only ({@code 0700}) hardening of an Eclipse-Store
 * storage directory (JS-SEC-017 / JS-SEC-037 / JS-SEC-038, CWE-276).
 *
 * <p>RF (exit-review, reuse): three byte-identical copies of this hardening previously
 * lived in {@link JCustosStorageFactory} (as {@code hardenStorageTree} /
 * {@code createOwnerOnly} / {@code warnIfGroupOrOtherAccessible}),
 * {@link EclipseStoreJCustosStorage} and the events module's
 * {@code EclipseStoreEventStorage}. Duplicated security-critical code drifts — the next
 * permission-policy change would land in one copy and silently miss the others (exactly the
 * JS-SEC-017 → JS-SEC-038 regression class this line already had to patch twice). All three
 * now call this helper. Because the events persistence module depends on this one, the type is
 * {@code public} so it can be shared across package boundaries.
 *
 * <h2>Existing directories (JS-SEC-136, CWE-276, CWE-732)</h2>
 * <p>Until 00.84.00 the hardening applied to a directory it created; a directory that was
 * already there — a volume mount, a directory laid out by a deployment tool, a backup target —
 * only earned a warning and stayed as open as it was. Now an existing directory that belongs
 * to the user the process runs as is restricted to {@code 0700}. {@link #hardenOwnerOnly}
 * still never fails; {@link #requireOwnerOnly} refuses a directory it cannot make owner-only.
 * Below the directory Eclipse Store creates its files with the process umask, usually readable
 * for everyone; they are protected by the directory above them, and
 * {@link #restrictStorageFiles} takes the same rights away from them, so that a tree that is
 * copied or archived does not carry open modes with it.</p>
 *
 * <p>On a filesystem without POSIX attributes all of this is a no-op: owner-only permissions
 * cannot be enforced there and the directory relies on its ACLs (JS-SEC-016).</p>
 *
 * @since 00.79.40
 */
@ExperimentalJCustosApi
public final class StorageTreeHardening {

  private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY =
      PosixFilePermissions.fromString("rwx------");
  /** Everything beyond the owner's bits. */
  private static final Set<PosixFilePermission> GROUP_OR_OTHERS = EnumSet.of(
      PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
      PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ,
      PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE);

  /** Directories Eclipse Store creates below a storage directory: one per channel. */
  private static final String CHANNEL_DIRECTORY_GLOB = "channel_*";
  /** The type dictionary Eclipse Store keeps next to the channel directories. */
  private static final String TYPE_DICTIONARY_GLOB = "*.ptd";

  private StorageTreeHardening() {
    // utility class — never instantiated
  }

  /**
   * Makes {@code dir} owner-only ({@code 0700}) on POSIX before Eclipse-Store opens it, so the
   * store is never group/other-readable under a default umask: a missing directory is created
   * owner-only, and an existing one that belongs to the process user is restricted
   * (JS-SEC-136). Best-effort: a directory that cannot be restricted — it belongs to another
   * user, or the filesystem refuses — is reported with a warning and never blocks the open;
   * callers that must not open such a directory use {@link #requireOwnerOnly}. A no-op on
   * non-POSIX filesystems (which rely on directory ACLs instead).
   *
   * @param dir             storage directory to harden; created if missing
   * @param logPrefix       stable log/audit code prefix for the warning
   *                        (e.g. {@code "persistence/storage-permissions"})
   * @param storeDescription short human phrase naming what the store holds, appended to the
   *                        exposure warning (e.g. "the framework store holds session handles,
   *                        roles and token hashes")
   */
  public static void hardenOwnerOnly(Path dir, String logPrefix, String storeDescription) {
    Optional<String> problem = restrict(dir, logPrefix, StorageTreeHardening::processUser);
    if (problem.isPresent()) {
      HasLogger.staticLogger().warn("{}: {}; {}", logPrefix, problem.get(), storeDescription);
    }
  }

  /**
   * Like {@link #hardenOwnerOnly}, but fails when {@code dir} is not owner-only afterwards
   * (JS-SEC-136, CWE-276, CWE-732): it belongs to another user, it is not a directory, or its
   * permissions could not be restricted. The files Eclipse Store already keeps in the
   * directory are restricted as well ({@link #restrictStorageFiles}). A no-op on non-POSIX
   * filesystems, where owner and permissions cannot be checked (JS-SEC-016).
   *
   * @param dir              storage directory; created owner-only if missing
   * @param logPrefix        stable code that starts the exception message and the log lines
   * @param storeDescription short human phrase naming what the store holds
   * @throws IllegalStateException when the directory cannot be made owner-only
   * @since 00.84.00
   */
  public static void requireOwnerOnly(Path dir, String logPrefix, String storeDescription) {
    requireOwnerOnly(dir, logPrefix, storeDescription, StorageTreeHardening::processUser);
  }

  /** Test seam: {@code whoAmI} names the principal the directory has to belong to. */
  static void requireOwnerOnly(Path dir, String logPrefix, String storeDescription,
                               Function<Path, Optional<UserPrincipal>> whoAmI) {
    Optional<String> problem = restrict(dir, logPrefix, whoAmI);
    if (problem.isPresent()) {
      throw new IllegalStateException(logPrefix + ": " + problem.get() + "; " + storeDescription
          + ". Hand the directory to the user the process runs as and restrict it to 0700,"
          + " or choose another directory.");
    }
    restrictStorageFiles(dir, logPrefix);
  }

  /**
   * Takes group and other access away from what Eclipse Store keeps in {@code dir}: the
   * channel directories, the files in them and the type dictionary (JS-SEC-136). Nothing else
   * in the directory is touched, so pointing a storage at a directory that also holds other
   * files does not change those. Best-effort — the directory above is what protects the
   * files; a file that cannot be restricted is reported with a warning. A no-op on non-POSIX
   * filesystems.
   *
   * @param dir       storage directory or the target of a backup
   * @param logPrefix stable log code prefix for the warning
   * @since 00.84.00
   */
  public static void restrictStorageFiles(Path dir, String logPrefix) {
    if (!isPosix(dir) || !Files.isDirectory(dir)) {
      return;
    }
    try {
      try (DirectoryStream<Path> dictionaries = Files.newDirectoryStream(dir, TYPE_DICTIONARY_GLOB)) {
        for (Path dictionary : dictionaries) {
          dropGroupAndOthers(dictionary);
        }
      }
      try (DirectoryStream<Path> channels = Files.newDirectoryStream(dir, CHANNEL_DIRECTORY_GLOB)) {
        for (Path channel : channels) {
          if (!Files.isDirectory(channel, LinkOption.NOFOLLOW_LINKS)) {
            continue;
          }
          dropGroupAndOthers(channel);
          try (DirectoryStream<Path> files = Files.newDirectoryStream(channel)) {
            for (Path file : files) {
              dropGroupAndOthers(file);
            }
          }
        }
      }
    } catch (IOException | RuntimeException restrictFailure) {
      HasLogger.staticLogger().warn("{}: could not restrict the files in {} to their owner: {}",
          logPrefix, dir, restrictFailure.toString());
    }
  }

  /**
   * @return empty when {@code dir} is owner-only now (or the filesystem has no POSIX
   *     attributes); otherwise what is wrong with it, as a phrase for a message
   */
  private static Optional<String> restrict(Path dir, String logPrefix,
                                           Function<Path, Optional<UserPrincipal>> whoAmI) {
    if (!isPosix(dir)) {
      return Optional.empty();
    }
    try {
      if (!Files.exists(dir)) {
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY));
      }
      // The configured path may be a symbolic link to the real location; it is followed, as
      // Eclipse Store follows it.
      PosixFileAttributes attributes = Files.readAttributes(dir, PosixFileAttributes.class);
      if (!attributes.isDirectory()) {
        return Optional.of(dir + " is not a directory");
      }
      Optional<UserPrincipal> self = whoAmI.apply(dir);
      if (self.isEmpty() || !self.get().equals(attributes.owner())) {
        return Optional.of(dir + " belongs to '" + attributes.owner().getName()
            + "', not to the user this process runs as, and has the permissions "
            + PosixFilePermissions.toString(attributes.permissions()));
      }
      EnumSet<PosixFilePermission> ownerBits = EnumSet.noneOf(PosixFilePermission.class);
      ownerBits.addAll(attributes.permissions());
      if (ownerBits.removeAll(GROUP_OR_OTHERS)) {
        // rights are taken away, never added: the owner's own bits stay as they are
        Files.setPosixFilePermissions(dir, ownerBits);
        HasLogger.staticLogger().warn(
            "{}: {} was accessible beyond its owner ({}) and has been restricted to {}",
            logPrefix, dir, PosixFilePermissions.toString(attributes.permissions()),
            PosixFilePermissions.toString(ownerBits));
        // some mounts accept the call and keep their fixed mode: believe what is there now
        Set<PosixFilePermission> effective = Files.getPosixFilePermissions(dir);
        if (effective.stream().anyMatch(GROUP_OR_OTHERS::contains)) {
          return Optional.of(dir + " is still accessible beyond its owner ("
              + PosixFilePermissions.toString(effective) + "); the filesystem ignored the change");
        }
      }
      return Optional.empty();
    } catch (IOException | RuntimeException hardenFailure) {
      return Optional.of("could not restrict " + dir + " to its owner: " + hardenFailure);
    }
  }

  private static boolean isPosix(Path path) {
    return path.getFileSystem().supportedFileAttributeViews().contains("posix");
  }

  /** Removes group and other access from one entry the process owns; symbolic links are left alone. */
  private static void dropGroupAndOthers(Path entry) throws IOException {
    PosixFileAttributes attributes =
        Files.readAttributes(entry, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (attributes.isSymbolicLink()) {
      return;
    }
    EnumSet<PosixFilePermission> ownerBits = EnumSet.noneOf(PosixFilePermission.class);
    ownerBits.addAll(attributes.permissions());
    if (ownerBits.removeAll(GROUP_OR_OTHERS)) {
      Files.setPosixFilePermissions(entry, ownerBits);
    }
  }

  /**
   * The principal that files created by this process belong to — the approach of
   * {@code FileBootstrapTokenStore} (JS-SEC-130): resolved from {@code user.name}; where that
   * name has no entry in the user database (a container running under an arbitrary uid), the
   * owner of a probe file created in the directory is used instead.
   *
   * @return the principal, or empty when it cannot be determined
   */
  private static Optional<UserPrincipal> processUser(Path dir) {
    try {
      return Optional.of(dir.getFileSystem().getUserPrincipalLookupService()
          .lookupPrincipalByName(System.getProperty("user.name")));
    } catch (IOException | RuntimeException lookupFailed) {
      // fall through to the probe
    }
    Path probe = null;
    try {
      probe = Files.createTempFile(dir, ".storage-owner-", ".probe",
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      return Optional.of(Files.getOwner(probe, LinkOption.NOFOLLOW_LINKS));
    } catch (IOException | RuntimeException probeFailed) {
      return Optional.empty();
    } finally {
      if (probe != null) {
        try {
          Files.deleteIfExists(probe);
        } catch (IOException ignored) {
          // best effort — an empty probe file carries nothing
        }
      }
    }
  }
}
