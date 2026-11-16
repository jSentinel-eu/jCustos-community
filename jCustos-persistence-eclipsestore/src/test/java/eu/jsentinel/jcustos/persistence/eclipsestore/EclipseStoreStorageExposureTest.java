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

import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * JS-SEC-136 (CWE-276, CWE-530, CWE-732, CWE-665, CWE-754): the security store is not left
 * readable for other local users - not in a directory that existed before, not in a backup -
 * and a storage that belongs to something else is refused instead of replaced.
 */
@DisplayName("Eclipse-Store storage - JS-SEC-136: existing directories, backups, foreign roots")
class EclipseStoreStorageExposureTest {

  private static final Set<PosixFilePermission> OPEN_DIRECTORY =
      PosixFilePermissions.fromString("rwxr-xr-x");

  @TempDir
  Path base;

  private void assumePosix() {
    assumeTrue(base.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "owner and permissions exist on POSIX filesystems only (JS-SEC-016)");
  }

  private static boolean openBeyondOwner(Path path) throws IOException {
    return Files.getPosixFilePermissions(path).stream()
        .anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"));
  }

  private static List<Path> everythingBelow(Path directory) throws IOException {
    try (Stream<Path> walk = Files.walk(directory)) {
      return walk.toList();
    }
  }

  private static void assertOwnerOnlyTree(Path directory) throws IOException {
    List<Path> entries = everythingBelow(directory);
    assertTrue(entries.size() > 2, "sanity: the tree holds the storage files");
    for (Path entry : entries) {
      assertFalse(openBeyondOwner(entry), entry + " is accessible beyond its owner: "
          + PosixFilePermissions.toString(Files.getPosixFilePermissions(entry)));
    }
  }

  // ── existing storage directories ───────────────────────────────────

  @Test
  @DisplayName("a storage directory that already exists with 0755 is restricted to its owner when it is opened")
  void existingDirectoryIsRestricted() throws IOException {
    assumePosix();
    Path store = base.resolve("mounted-volume");
    Files.createDirectory(store, PosixFilePermissions.asFileAttribute(OPEN_DIRECTORY));
    Files.setPosixFilePermissions(store, OPEN_DIRECTORY); // independent of the umask
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(store)) {
      assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(store));
      storage.auditEventStore();
    }
  }

  @Test
  @DisplayName("the channel directory, the data files and the type dictionary carry no rights for group or others")
  void storageFilesAreRestricted() throws IOException {
    assumePosix();
    Path store = base.resolve("store");
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(store)) {
      storage.auditEventStore();
      assertOwnerOnlyTree(store);
    }
    // a tree that was copied with open modes, or written by a release before 00.84.00
    for (Path entry : everythingBelow(store)) {
      Files.setPosixFilePermissions(entry, Files.isDirectory(entry)
          ? OPEN_DIRECTORY : PosixFilePermissions.fromString("rw-r--r--"));
    }
    Path unrelated = Files.writeString(store.resolve("notes.txt"), "not a storage file");
    Files.setPosixFilePermissions(unrelated, PosixFilePermissions.fromString("rw-r--r--"));
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(store)) {
      reopened.auditEventStore();
      for (Path entry : everythingBelow(store)) {
        if (!entry.equals(unrelated)) {
          assertFalse(openBeyondOwner(entry), entry + " stayed open");
        }
      }
      assertEquals(PosixFilePermissions.fromString("rw-r--r--"),
          Files.getPosixFilePermissions(unrelated),
          "only what Eclipse Store keeps is touched - not other files in the directory");
    }
  }

  @Test
  @DisplayName("the storage pair restricts an existing framework and an existing app directory")
  void pairRestrictsExistingDirectories() throws IOException {
    assumePosix();
    Path parent = base.resolve("pair");
    Path framework = parent.resolve(StorageLayout.DEFAULT.frameworkSubdir());
    Path app = parent.resolve(StorageLayout.DEFAULT.appSubdir());
    for (Path directory : List.of(parent, framework, app)) {
      Files.createDirectories(directory);
      Files.setPosixFilePermissions(directory, OPEN_DIRECTORY);
    }
    try (JCustosStoragePair pair = JCustosStorageFactory.openAt(parent)) {
      pair.framework().auditEventStore();
      for (Path directory : List.of(parent, framework, app)) {
        assertFalse(openBeyondOwner(directory), directory + " stayed open");
      }
      assertOwnerOnlyTree(app);
    }
  }

  @Test
  @DisplayName("a directory that belongs to another user is refused, with a message that says so, and is left as it is")
  void foreignOwnerIsRefused() throws IOException {
    assumePosix();
    Path store = base.resolve("someone-elses");
    Files.createDirectory(store);
    Files.setPosixFilePermissions(store, OPEN_DIRECTORY);
    UserPrincipal owner = Files.getOwner(store);
    UserPrincipal other;
    try {
      other = store.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName("root");
    } catch (IOException noSuchUser) {
      assumeTrue(false, "no second principal to compare with");
      return;
    }
    assumeFalse(other.equals(owner), "the test runs as root");

    // the process "is" the other principal: the directory is somebody else's from its point of view
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> StorageTreeHardening.requireOwnerOnly(store, "persistence/storage-permissions",
            "the framework store holds session handles, roles and token hashes",
            directory -> Optional.of(other)));
    assertTrue(refused.getMessage().startsWith("persistence/storage-permissions: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("belongs to '" + owner.getName() + "'"), refused.getMessage());
    assertEquals(OPEN_DIRECTORY, Files.getPosixFilePermissions(store), "a refused directory is not changed");

    assertThrows(IllegalStateException.class,
        () -> StorageTreeHardening.requireOwnerOnly(store, "persistence/storage-permissions",
            "the framework store holds session handles, roles and token hashes",
            directory -> Optional.empty()),
        "an owner that cannot be determined is not good enough either");
  }

  @Test
  @DisplayName("a path that is a file is refused; the lenient variant only reports")
  void notADirectory() throws IOException {
    assumePosix();
    Path file = Files.writeString(base.resolve("a-file"), "x");
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> StorageTreeHardening.requireOwnerOnly(file, "persistence/storage-permissions", "the store"));
    assertTrue(refused.getMessage().contains("is not a directory"), refused.getMessage());
    StorageTreeHardening.hardenOwnerOnly(file, "persistence/storage-permissions", "the store");
  }

  // ── backup ─────────────────────────────────────────────────────────

  @Test
  @DisplayName("a backup is written owner-only: the target directory, the channel directory and every file")
  void backupIsOwnerOnly() throws IOException {
    assumePosix();
    Path backup = base.resolve("backup");
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(base.resolve("live"))) {
      storage.auditEventStore();
      storage.issueFullBackup(backup);
    }
    assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(backup));
    assertOwnerOnlyTree(backup);
  }

  @Test
  @DisplayName("an existing empty backup target with 0755 is restricted before anything is written into it")
  void existingBackupTargetIsRestricted() throws IOException {
    assumePosix();
    Path backup = base.resolve("shared-backups");
    Files.createDirectory(backup);
    Files.setPosixFilePermissions(backup, OPEN_DIRECTORY);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(base.resolve("live"))) {
      storage.issueFullBackup(backup);
    }
    assertOwnerOnlyTree(backup);
    try (EclipseStoreJCustosStorage restored = EclipseStoreJCustosStorage.openAt(backup)) {
      restored.auditEventStore();
    }
  }

  @Test
  @DisplayName("a target that already holds something is refused by the export and its permissions stay untouched")
  void nonEmptyBackupTargetIsLeftAlone() throws IOException {
    assumePosix();
    Path target = base.resolve("not-empty");
    Files.createDirectory(target);
    Files.setPosixFilePermissions(target, OPEN_DIRECTORY);
    Path resident = Files.writeString(target.resolve("resident.txt"), "x");
    Files.setPosixFilePermissions(resident, PosixFilePermissions.fromString("rw-r--r--"));
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(base.resolve("live"))) {
      assertThrows(RuntimeException.class, () -> storage.issueFullBackup(target));
    }
    assertEquals(OPEN_DIRECTORY, Files.getPosixFilePermissions(target));
    assertEquals(PosixFilePermissions.fromString("rw-r--r--"), Files.getPosixFilePermissions(resident));
  }

  // ── foreign root ───────────────────────────────────────────────────

  private static void writeForeignStorage(Path directory, Object root) {
    EmbeddedStorageManager foreign = EmbeddedStorage.start(directory);
    try {
      foreign.setRoot(root);
      foreign.storeRoot();
    } finally {
      foreign.shutdown();
    }
  }

  private static Object rootOf(Path directory) {
    EmbeddedStorageManager manager = EmbeddedStorage.start(directory);
    try {
      return manager.root();
    } finally {
      manager.shutdown();
    }
  }

  @Test
  @DisplayName("a storage with another application's root is refused with persistence/foreign-root and stays as it was")
  void foreignRootIsNotReplaced() {
    Path directory = base.resolve("app-data");
    writeForeignStorage(directory, "the application's own root");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> EclipseStoreJCustosStorage.openAt(directory));
    assertTrue(refused.getMessage().startsWith("persistence/foreign-root: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("java.lang.String"),
        "the message names what was found: " + refused.getMessage());

    // the refusal released the directory, and the other application's data is untouched
    assertEquals("the application's own root", rootOf(directory));
  }

  @Test
  @DisplayName("swapped directories of a storage pair fail the start; neither storage is changed or left locked")
  void swappedPairDirectoriesAreRefused() {
    Path parent = base.resolve("pair");
    StorageLayout layout = new StorageLayout("framework-data", "app-data");
    try (JCustosStoragePair pair = JCustosStorageFactory.openAt(parent, layout)) {
      pair.app().setRoot("domain data");
      pair.app().storeRoot();
      pair.framework().bootstrapStateStore();
    }
    // the layout with the two names exchanged: the framework side now points at the app's data
    StorageLayout swapped = new StorageLayout("app-data", "framework-data");
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> JCustosStorageFactory.openAt(parent, swapped));
    assertTrue(refused.getMessage().startsWith("persistence/foreign-root: "), refused.getMessage());

    assertEquals("domain data", rootOf(parent.resolve("app-data")));
    try (JCustosStoragePair again = JCustosStorageFactory.openAt(parent, layout)) {
      assertEquals("domain data", again.app().root());
    }
  }

  @Test
  @DisplayName("a storage without a root - never used - is adopted as before")
  void storageWithoutRootIsAdopted() {
    Path directory = base.resolve("never-used");
    EmbeddedStorage.start(directory).shutdown();
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(directory)) {
      storage.sessionStore();
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(directory)) {
      assertTrue(reopened.sessionStore().findAll().isEmpty());
    }
  }
}
