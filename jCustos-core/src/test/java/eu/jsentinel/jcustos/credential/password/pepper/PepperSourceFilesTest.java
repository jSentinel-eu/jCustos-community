/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.pepper;

import com.svenruppert.functional.result.Result;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The owner and directory rules of {@link PepperSourceFiles}: a key file that belongs to another
 * user than the process user is refused, so is a key directory that belongs to another user or
 * that group or others can write, and a key directory is read as the directory that was checked.
 * A test cannot create a file that another user owns without privileges, so the seam names a
 * different principal as "the process user" instead.
 */
@DisplayName("PepperSourceFiles - key files and key directories must belong to the process user")
class PepperSourceFilesTest {

  private static final String SYNTHETIC = "synthetic";

  @TempDir
  Path dir;

  @BeforeEach
  void posixOnly() {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner checks need POSIX attributes");
  }

  private Path ownerOnlyFile(Path directory, String content) throws IOException {
    Path file = directory.resolve("pepper-2026");
    Files.writeString(file, content, StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("r--------"));
    return file;
  }

  private UserPrincipal someoneElse(Path file) throws IOException {
    UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);
    UserPrincipal root = file.getFileSystem().getUserPrincipalLookupService()
        .lookupPrincipalByName("root");
    assumeTrue(!root.equals(owner), "the test must not run as root");
    return root;
  }

  @Test
  @DisplayName("a file of the process user is read; one that belongs to someone else is refused")
  void ownerMustBeTheProcessUser() throws IOException {
    Path file = ownerOnlyFile(dir, SYNTHETIC);
    UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);

    assertArrayEquals(SYNTHETIC.getBytes(StandardCharsets.US_ASCII),
        PepperSourceFiles.readTrusted(file, 64, "test/code"),
        "the process user is resolved and owns the file it created");

    UserPrincipal someoneElse = someoneElse(file);
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.readTrusted(file, 64, "test/code", f -> Result.success(someoneElse)));
    assertTrue(refused.getMessage().contains("not to the user this process runs as"),
        refused.getMessage());
    assertTrue(refused.getMessage().contains(owner.getName()), refused.getMessage());
  }

  @Test
  @DisplayName("SP05: a process user that cannot be determined refuses the file and says so - not 'belongs to another user'")
  void undeterminableProcessUserIsNamedAsSuch() throws IOException {
    Path file = ownerOnlyFile(dir, SYNTHETIC);
    String reason = "the lookup of user.name failed with UserPrincipalNotFoundException";

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.readTrusted(file, 64, "test/code", f -> Result.failure(reason)));

    assertTrue(refused.getMessage().startsWith("test/code: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("the user this process runs as cannot be determined ("
        + reason + ")"), refused.getMessage());
    assertFalse(refused.getMessage().contains("belongs to"), refused.getMessage());

    IllegalStateException directory = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.openDirectory(dir, "test/code", d -> Result.failure(reason)));
    assertTrue(directory.getMessage().contains("cannot be determined (" + reason + ")"),
        directory.getMessage());
    assertTrue(directory.getMessage().contains("the key directory " + dir), directory.getMessage());
  }

  @Test
  @DisplayName("a key directory that belongs to someone else is refused")
  void keyDirectoryOwnerMustBeTheProcessUser() throws IOException {
    UserPrincipal someoneElse = someoneElse(dir);

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.openDirectory(dir, "test/code", d -> Result.success(someoneElse)));

    assertTrue(refused.getMessage().contains("the key directory " + dir + " belongs to '"),
        refused.getMessage());
    assertTrue(refused.getMessage().contains("or to the superuser"), refused.getMessage());
  }

  @Test
  @DisplayName("the key directory is read as it was checked: a directory swapped in after the check never supplies a key")
  void swappedKeyDirectoryNeverSuppliesAKey() throws IOException {
    Path keys = Files.createDirectory(dir.resolve("keys"),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    ownerOnlyFile(keys, "checked");

    try (PepperSourceFiles.KeyDirectory opened = PepperSourceFiles.openDirectory(keys, "test/code")) {
      assumeTrue(opened.pinned(), "the JDK offers no secure directory stream here");
      // after the check: the checked directory is moved aside and another one takes its name
      Files.move(keys, dir.resolve("keys-aside"));
      Path planted = Files.createDirectory(keys,
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      ownerOnlyFile(planted, "planted");

      byte[] read;
      try {
        read = opened.read("pepper-2026", 64);
      } catch (IllegalStateException refused) {
        assertTrue(refused.getMessage().contains("was replaced"), refused.getMessage());
        return;
      }
      assertNotEquals("planted", new String(read, StandardCharsets.US_ASCII),
          "the planted directory supplied the key");
    }
  }

  @Test
  @DisplayName("the size bound is exact: maxBytes is read, maxBytes + 1 is refused")
  void sizeBound() throws IOException {
    Path file = ownerOnlyFile(dir, SYNTHETIC);
    assertArrayEquals(SYNTHETIC.getBytes(StandardCharsets.US_ASCII),
        PepperSourceFiles.readTrusted(file, SYNTHETIC.length(), "test/code"));
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.readTrusted(file, SYNTHETIC.length() - 1, "test/code"));
    assertTrue(refused.getMessage().startsWith("test/code: "), refused.getMessage());
    assertNotEquals(-1, refused.getMessage().indexOf("larger than"));
  }
}
