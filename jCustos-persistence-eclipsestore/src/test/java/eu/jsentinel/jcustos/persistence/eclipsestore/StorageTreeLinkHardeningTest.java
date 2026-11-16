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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * JS-SEC-136 (CWE-367, CWE-59): the storage directory that is checked is the directory the
 * storage opens. A symbolic link as storage directory is refused, the checked path is resolved
 * once, and a directory above it that another user can replace is reported. Real directories
 * and links in a temporary directory.
 */
@DisplayName("JS-SEC-136 — the checked storage directory is the one that is opened")
class StorageTreeLinkHardeningTest {

  private static final String CODE = "persistence/storage-permissions";

  @TempDir
  Path base;

  private void assumePosix() {
    assumeTrue(base.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "owner and permission checks exist on POSIX filesystems only (JS-SEC-016)");
  }

  private Path ownerOnlyDirectory(String name) throws Exception {
    Path dir = Files.createDirectory(base.resolve(name));
    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
    return dir;
  }

  @Test
  @DisplayName("a storage directory that is a symbolic link is refused, also by openAt")
  void symbolicLinkAsStorageDirectoryIsRefused() throws Exception {
    assumePosix();
    Path target = ownerOnlyDirectory("real-store");
    Path link = Files.createSymbolicLink(base.resolve("store-link"), target);

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> StorageTreeHardening.requireOwnerOnly(link, CODE, "the store"));
    assertTrue(refused.getMessage().startsWith(CODE), refused.getMessage());
    assertTrue(refused.getMessage().contains("symbolic link"), refused.getMessage());

    assertThrows(IllegalStateException.class, () -> EclipseStoreJCustosStorage.openAt(link));
    try (var entries = Files.list(target)) {
      assertEquals(0L, entries.count(), "nothing was written behind the link");
    }
    assertDoesNotThrow(() -> StorageTreeHardening.hardenOwnerOnly(link, CODE, "the store"),
        "the best-effort variant reports and does not throw");
  }

  @Test
  @DisplayName("the checked directory is returned as its real path - a link above it is resolved once")
  void realPathIsReturned() throws Exception {
    assumePosix();
    Path realParent = ownerOnlyDirectory("real-parent");
    Path linkedParent = Files.createSymbolicLink(base.resolve("linked-parent"), realParent);

    Path checked = StorageTreeHardening.requireOwnerOnlyDirectory(
        linkedParent.resolve("store"), CODE, "the store");

    assertEquals(realParent.toRealPath().resolve("store"), checked);
    assertTrue(Files.isDirectory(checked));
  }

  @Test
  @DisplayName("a directory above the storage that group or others may write is reported")
  void writableAncestorIsReported() throws Exception {
    assumePosix();
    assumeTrue(base.getFileSystem().supportedFileAttributeViews().contains("unix"),
        "the sticky bit is read through the unix attribute view");
    UserPrincipal self = Files.getOwner(base);
    Path open = Files.createDirectory(base.resolve("open"));
    Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwxrwxrwx"));
    Path store = Files.createDirectory(open.resolve("store")).toRealPath();

    Optional<String> problem = StorageTreeHardening.ancestorProblem(store, self);

    assertTrue(problem.isPresent(), "a world-writable parent without the sticky bit");
    assertTrue(problem.get().contains(open.toRealPath().toString()), problem.get());

    Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwx------"));
    assertEquals(Optional.empty(), StorageTreeHardening.ancestorProblem(store, self),
        "an owner-only parent below a sound chain is fine");
  }

  @Test
  @DisplayName("openAt still opens an ordinary owner-only directory")
  void ordinaryDirectoryOpens() throws Exception {
    assumePosix();
    Path dir = ownerOnlyDirectory("store");
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(dir)) {
      assertTrue(storage.sessionStore().findAll().isEmpty());
    }
  }
}
