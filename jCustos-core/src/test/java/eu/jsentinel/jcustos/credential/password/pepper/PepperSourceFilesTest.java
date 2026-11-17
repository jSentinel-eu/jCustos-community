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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The owner rule of {@link PepperSourceFiles}: a key file that belongs to another user than the
 * process user is refused. A test cannot create a file that another user owns without
 * privileges, so the seam names a different principal as "the process user" instead.
 */
@DisplayName("PepperSourceFiles - a key file must belong to the process user")
class PepperSourceFilesTest {

  @TempDir
  Path dir;

  @BeforeEach
  void posixOnly() {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner checks need POSIX attributes");
  }

  private Path ownerOnlyFile() throws IOException {
    Path file = dir.resolve("pepper-2026");
    Files.writeString(file, "synthetic", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("r--------"));
    return file;
  }

  @Test
  @DisplayName("a file of the process user is read; one that belongs to someone else is refused")
  void ownerMustBeTheProcessUser() throws IOException {
    Path file = ownerOnlyFile();
    UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);

    assertArrayEquals("synthetic".getBytes(StandardCharsets.US_ASCII),
        PepperSourceFiles.readTrusted(file, 64, "test/code"),
        "the process user is resolved and owns the file it created");

    UserPrincipal someoneElse = file.getFileSystem().getUserPrincipalLookupService()
        .lookupPrincipalByName("root");
    assumeTrue(!someoneElse.equals(owner), "the test must not run as root");
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.readTrusted(file, 64, "test/code", f -> Optional.of(someoneElse)));
    assertTrue(refused.getMessage().contains("not to the user this process runs as"),
        refused.getMessage());
    assertTrue(refused.getMessage().contains(owner.getName()), refused.getMessage());

    assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.readTrusted(file, 64, "test/code", f -> Optional.empty()),
        "an undeterminable process user refuses the file");
  }

  @Test
  @DisplayName("the size bound is exact: maxBytes is read, maxBytes + 1 is refused")
  void sizeBound() throws IOException {
    Path file = ownerOnlyFile();
    assertArrayEquals("synthetic".getBytes(StandardCharsets.US_ASCII),
        PepperSourceFiles.readTrusted(file, "synthetic".length(), "test/code"));
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> PepperSourceFiles.readTrusted(file, "synthetic".length() - 1, "test/code"));
    assertTrue(refused.getMessage().startsWith("test/code: "), refused.getMessage());
    assertNotEquals(-1, refused.getMessage().indexOf("larger than"));
  }
}
