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
package eu.jsentinel.jcustos.bootstrap;

import eu.jsentinel.jcustos.credential.CredentialTestKit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * JS-SEC-130 (CWE-367, CWE-59): the token file that passed the trust check is
 * the file that is read. Real files; the store's seam swaps the file between
 * check and read, exactly where a local attacker would have to strike.
 */
@DisplayName("JS-SEC-130 — the bootstrap token file that is checked is the file that is read")
class BootstrapTokenFileReadTest {

  private static final String GENUINE = new BootstrapTokenGenerator().generate().value();
  private static final String PLANTED = "PLAN-TEDB-YLXC-ALUS-ER22";
  private static final Instant CREATED = Instant.parse("2026-11-16T10:00:00Z");

  @TempDir
  Path dir;

  private static void assumePosix() {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner and permission checks exist on POSIX filesystems only (JS-SEC-016)");
  }

  private static void writeOwnerOnly(Path file, String token) throws IOException {
    Files.writeString(file, "token=" + token + "\ncreatedAt=" + CREATED + "\n");
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
  }

  @Test
  @DisplayName("an untouched file in the generator's format is read")
  void genuineFileIsRead() throws IOException {
    assumePosix();
    Path file = dir.resolve("bootstrap-token");
    writeOwnerOnly(file, GENUINE);
    assertEquals(GENUINE, new FileBootstrapTokenStore(file).load().orElseThrow().value());
  }

  @Test
  @DisplayName("a symbolic link swapped in after the check is not followed")
  void linkSwappedInAfterTheCheckIsNotFollowed() throws IOException {
    assumePosix();
    Path file = dir.resolve("bootstrap-token");
    writeOwnerOnly(file, GENUINE);
    Path planted = dir.resolve("planted");
    writeOwnerOnly(planted, PLANTED);
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(file);
    store.afterTrustCheck = () -> {
      try {
        Files.delete(file);
        Files.createSymbolicLink(file, planted);
      } catch (IOException swapFailed) {
        throw new UncheckedIOException(swapFailed);
      }
    };

    assertTrue(store.load().isEmpty(), "the planted token must not be adopted");
  }

  @Test
  @DisplayName("a regular file swapped in after the check is not read")
  void fileSwappedInAfterTheCheckIsNotRead() throws IOException {
    assumePosix();
    Path file = dir.resolve("bootstrap-token");
    writeOwnerOnly(file, GENUINE);
    Path planted = dir.resolve("planted");
    writeOwnerOnly(planted, PLANTED);
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(file);
    store.afterTrustCheck = () -> {
      try {
        Files.move(planted, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
      } catch (IOException swapFailed) {
        throw new UncheckedIOException(swapFailed);
      }
    };

    assertTrue(store.load().isEmpty(), "another file than the one checked must not be read");
  }

  @Test
  @DisplayName("a file larger than the limit is not read")
  void oversizedFileIsNotRead() throws IOException {
    assumePosix();
    Path file = dir.resolve("bootstrap-token");
    String padding = "#".repeat(FileBootstrapTokenStore.MAX_TOKEN_FILE_BYTES);
    Files.writeString(file, "token=" + GENUINE + "\ncreatedAt=" + CREATED + "\n" + padding + "\n");
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));

    assertTrue(new FileBootstrapTokenStore(file).load().isEmpty());
  }
}
