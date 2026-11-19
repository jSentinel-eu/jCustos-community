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
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Decision F25 (option a, JS-SEC-162, RF08): the pepper file source stays strict, and the
 * documentation tells Kubernetes users to copy the key with an init container from the secret
 * volume into an owner-only key directory. This test proves the recipe against the real
 * checks of {@link FilePepperService} with real directories.
 *
 * <p>A Kubernetes secret volume is a tree of symbolic links ({@code pepper-2026} points to
 * {@code ..data/pepper-2026}, {@code ..data} to a time-stamped directory), so it is refused as
 * it is. An {@code emptyDir} is created with mode {@code 0777} and without the sticky bit -
 * with {@code fsGroup} the kubelet adds the set-group-id bit - so the {@code emptyDir}
 * itself is refused as key directory: whoever can write it could put a key file of their own
 * in place of the checked one. The recipe therefore creates a sub-directory {@code 0700},
 * owned by the user the application runs as, inside the {@code emptyDir} and copies the key
 * into it with mode {@code 0400}. The directories above the key directory are not checked
 * (class comment of {@code PepperSourceFiles}), so that sub-directory loads.
 *
 * <p>Owner and permissions need POSIX attributes; the test is skipped without them.
 */
@DisplayName("F25 — the Kubernetes recipe: an owner-only key directory inside an emptyDir loads, the emptyDir itself is refused")
class FilePepperServiceKubernetesRecipeTest {

  private static final String KEY_ID = "pepper-2026";

  /** The mode Kubernetes gives an emptyDir: everybody may write, no sticky bit. */
  private static final String EMPTY_DIR_PERMISSIONS = "rwxrwxrwx";

  /** The set-group-id bit the kubelet adds to an emptyDir when the pod sets fsGroup. */
  private static final int EMPTY_DIR_WITH_FS_GROUP_MODE = 02777;

  private static final SecureRandom RANDOM = new SecureRandom();

  @TempDir
  Path pod;

  @BeforeEach
  void posixOnly() {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner and permission checks need POSIX attributes");
  }

  @Test
  @DisplayName("the recipe: key copied from the secret volume into a 0700 sub-directory of a 0777 emptyDir, file 0400 - loads")
  void ownerOnlyKeyDirectoryInsideEmptyDirLoads() throws IOException {
    byte[] key = key();
    Path secretVolume = secretVolume(key);
    Path emptyDir = emptyDir();

    // the init container, running as the application's user
    Path keyDirectory = Files.createDirectory(emptyDir.resolve("pepper"));
    Files.setPosixFilePermissions(keyDirectory, PosixFilePermissions.fromString("rwx------"));
    Path keyFile = Files.copy(secretVolume.resolve(KEY_ID), keyDirectory.resolve(KEY_ID));
    Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("r--------"));
    assertTrue(Files.isRegularFile(keyFile, LinkOption.NOFOLLOW_LINKS),
        "the copy is a regular file, not the secret volume's link");

    FilePepperService pepper = FilePepperService.fromDirectory(keyDirectory)
        .activeKeyId(KEY_ID).load();

    assertEquals(Optional.of(KEY_ID), pepper.activeKeyId());
    assertArrayEquals(key, pepper.resolve(KEY_ID).orElseThrow());
    assertEquals(EMPTY_DIR_PERMISSIONS,
        PosixFilePermissions.toString(Files.getPosixFilePermissions(emptyDir)),
        "the parent stayed writable for everybody: the directories above are not checked");
  }

  @Test
  @DisplayName("the emptyDir itself (0777, no sticky bit) as key directory is refused with the documented message")
  void emptyDirItselfIsRefused() throws IOException {
    Path emptyDir = emptyDir();
    Path keyFile = Files.writeString(emptyDir.resolve(KEY_ID),
        Base64.getEncoder().encodeToString(key()) + "\n", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("r--------"));

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(emptyDir).activeKeyId(KEY_ID).load());

    String message = refused.getMessage();
    assertTrue(message.startsWith("pepper/key-file-rejected: the key directory " + emptyDir
        + " can be written by group or others"), message);
    if (emptyDir.getFileSystem().supportedFileAttributeViews().contains("unix")) {
      assertTrue(message.contains("(mode 777), who can put a key file of their own in place of"
          + " the checked one; restrict it to 0700 or 0755"), message);
    }
  }

  @Test
  @DisplayName("with fsGroup (set-group-id bit, 2777) the emptyDir is refused as well, the sub-directory still loads")
  void emptyDirWithFsGroup() throws IOException {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("unix"),
        "the set-group-id bit needs the unix attribute view");
    byte[] key = key();
    Path emptyDir = emptyDir();
    Files.setAttribute(emptyDir, "unix:mode", EMPTY_DIR_WITH_FS_GROUP_MODE);
    assumeTrue((Integer) Files.getAttribute(emptyDir, "unix:mode") % 010000
            == EMPTY_DIR_WITH_FS_GROUP_MODE,
        "this filesystem does not keep the set-group-id bit for the test user");
    Path keyFile = Files.writeString(emptyDir.resolve(KEY_ID),
        Base64.getEncoder().encodeToString(key) + "\n", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("r--------"));

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(emptyDir).activeKeyId(KEY_ID).load());
    assertTrue(refused.getMessage().contains("can be written by group or others (mode 2777)"),
        refused.getMessage());

    Path keyDirectory = Files.createDirectory(emptyDir.resolve("pepper"));
    Files.setPosixFilePermissions(keyDirectory, PosixFilePermissions.fromString("rwx------"));
    Files.move(keyFile, keyDirectory.resolve(KEY_ID));
    assertArrayEquals(key, FilePepperService.fromDirectory(keyDirectory).activeKeyId(KEY_ID).load()
        .resolve(KEY_ID).orElseThrow());
  }

  @Test
  @DisplayName("the secret volume itself is refused: its key file is a symbolic link")
  void secretVolumeItselfIsRefused() throws IOException {
    Path secretVolume = secretVolume(key());

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(secretVolume).activeKeyId(KEY_ID).load());

    assertTrue(refused.getMessage().startsWith("pepper/key-file-rejected: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("is a symbolic link"), refused.getMessage());
  }

  // ── helpers ────────────────────────────────────────────────────

  private static byte[] key() {
    byte[] key = new byte[32];
    RANDOM.nextBytes(key);
    return key;
  }

  /** An emptyDir as Kubernetes creates it: mode 0777, no sticky bit. */
  private Path emptyDir() throws IOException {
    Path emptyDir = Files.createDirectory(pod.resolve("keys-volume"));
    Files.setPosixFilePermissions(emptyDir, PosixFilePermissions.fromString(EMPTY_DIR_PERMISSIONS));
    return emptyDir;
  }

  /**
   * A secret volume in the layout the kubelet writes: the data in a time-stamped directory,
   * {@code ..data} pointing to it and the key name pointing into {@code ..data}; files 0644.
   */
  private Path secretVolume(byte[] key) throws IOException {
    Path volume = Files.createDirectory(pod.resolve("secret-volume"));
    Path data = Files.createDirectory(volume.resolve("..2026_11_19_10_00_00.000000001"));
    Path payload = Files.writeString(data.resolve(KEY_ID),
        Base64.getEncoder().encodeToString(key) + "\n", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(payload, PosixFilePermissions.fromString("rw-r--r--"));
    Files.createSymbolicLink(volume.resolve("..data"), data.getFileName());
    Files.createSymbolicLink(volume.resolve(KEY_ID), Path.of("..data", KEY_ID));
    return volume;
  }
}
