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
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link FilePepperService}: one Base64 file per key id, read under the owner, permission and
 * symbolic-link rules of JS-SEC-130 / JS-SEC-136. Keys are generated per test into a
 * temporary directory; no key material is committed.
 */
@DisplayName("FilePepperService - key files under owner, permission and link checks")
class FilePepperServiceTest {

  @TempDir
  Path dir;

  private static final SecureRandom RANDOM = new SecureRandom();

  @BeforeEach
  void posixOnly() {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner and permission checks need POSIX attributes");
  }

  private static byte[] key(int length) {
    byte[] key = new byte[length];
    RANDOM.nextBytes(key);
    return key;
  }

  /** Writes a key file the way an operator provisions it: Base64, newline, 0600. */
  private Path keyFile(String keyId, byte[] key, String permissions) throws IOException {
    Path file = dir.resolve(keyId);
    Files.writeString(file, Base64.getEncoder().encodeToString(key) + "\n",
        StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions));
    return file;
  }

  @Test
  @DisplayName("loads the named keys; the active one peppers, a retired one resolves, copies only")
  void loadsActiveAndRetiredKeys() throws IOException {
    byte[] active = key(32);
    byte[] retired = key(48);
    keyFile("pepper-2026", active, "rw-------");
    keyFile("pepper-2025", retired, "r--------");

    FilePepperService service = FilePepperService.fromDirectory(dir)
        .activeKeyId("pepper-2026")
        .retiredKeyId("pepper-2025")
        .load();

    assertEquals(Optional.of("pepper-2026"), service.activeKeyId());
    assertArrayEquals(active, service.resolve("pepper-2026").orElseThrow());
    assertArrayEquals(retired, service.resolve("pepper-2025").orElseThrow());
    assertEquals(List.of("pepper-2026", "pepper-2025"), List.copyOf(service.keyIds()));

    byte[] handedOut = service.resolve("pepper-2026").orElseThrow();
    handedOut[0] ^= 0x7f;
    assertArrayEquals(active, service.resolve("pepper-2026").orElseThrow(),
        "resolve hands out a copy; changing it does not change the held key");
    assertEquals(Optional.empty(), service.resolve("pepper-2024"),
        "an unknown key id is empty, not an exception");
    String text = service.toString();
    assertTrue(text.contains("pepper-2026"), text);
    assertFalse(text.contains(Base64.getEncoder().encodeToString(active)),
        "toString never shows key material");

    service.wipe();
    assertEquals(Optional.empty(), service.resolve("pepper-2026"));
  }

  @Test
  @DisplayName("white space and wrapped lines in the Base64 content are ignored")
  void wrappedBase64() throws IOException {
    byte[] key = key(64);
    String base64 = Base64.getEncoder().encodeToString(key);
    Path file = dir.resolve("wrapped");
    Files.writeString(file, "  " + base64.substring(0, 40) + "\r\n" + base64.substring(40)
        + "\n\n", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));

    FilePepperService service = FilePepperService.fromDirectory(dir).activeKeyId("wrapped").load();

    assertArrayEquals(key, service.resolve("wrapped").orElseThrow());
  }

  @Test
  @DisplayName("only the named files are opened: other secrets in the directory are not touched")
  void otherFilesAreIgnored() throws IOException {
    keyFile("pepper-2026", key(32), "rw-------");
    Path foreign = dir.resolve("db-password");
    Files.writeString(foreign, "short and world-readable");
    Files.setPosixFilePermissions(foreign, PosixFilePermissions.fromString("rw-r--r--"));

    FilePepperService service =
        FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load();

    assertEquals(List.of("pepper-2026"), List.copyOf(service.keyIds()));
  }

  @Test
  @DisplayName("a key file readable by group or others is refused at load")
  void tooWidePermissionsAreRefused() throws IOException {
    byte[] key = key(32);
    keyFile("pepper-2026", key, "rw-r-----");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());

    assertTrue(refused.getMessage().startsWith("pepper/key-file-rejected: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("accessible beyond its owner"), refused.getMessage());
    assertFalse(refused.getMessage().contains(Base64.getEncoder().encodeToString(key)),
        "the message never carries the key");

    keyFile("pepper-2026", key, "rw----r--");
    assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load(),
        "read access for others is refused as well");
  }

  @Test
  @DisplayName("a retired key file with wide permissions fails the whole load (no partial key set)")
  void oneRefusedFileFailsTheLoad() throws IOException {
    keyFile("pepper-2026", key(32), "rw-------");
    keyFile("pepper-2025", key(32), "rw-rw-rw-");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir)
            .activeKeyId("pepper-2026").retiredKeyId("pepper-2025").load());

    assertTrue(refused.getMessage().contains("pepper-2025"), refused.getMessage());
  }

  @Test
  @DisplayName("a refused retired key file zeroes the keys the load had already copied")
  void failedLoadWipesTheCopiedKeys() throws IOException {
    keyFile("pepper-2026", key(32), "rw-------");
    keyFile("pepper-2025", key(32), "rw-rw-rw-");
    InMemoryPepperService.Builder keys = InMemoryPepperService.builder();
    // a key already in the builder stands for every copy the load makes before it fails
    byte[] earlier = key(32);
    keys.addKey("earlier", earlier);
    List<byte[]> copies = keys.heldCopies();

    assertThrows(IllegalStateException.class, () -> FilePepperService.fromDirectory(dir)
        .activeKeyId("pepper-2026").retiredKeyId("pepper-2025").load(keys));

    assertEquals(List.of(), keys.heldCopies(), "the builder forgot its copies");
    for (byte[] copy : copies) {
      assertArrayEquals(new byte[copy.length], copy, "every copy is zeroed");
    }
    assertNotZero(earlier, "the caller's own array is not the builder's copy");
  }

  @Test
  @DisplayName("a successful load leaves the keys intact - the builder is wiped on failure only")
  void successfulLoadKeepsTheKeys() throws IOException {
    byte[] active = key(32);
    keyFile("pepper-2026", active, "rw-------");
    InMemoryPepperService.Builder keys = InMemoryPepperService.builder();

    FilePepperService service =
        FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load(keys);

    assertArrayEquals(active, service.resolve("pepper-2026").orElseThrow());
  }

  @Test
  @DisplayName("a key directory that group or others can write is refused; with the sticky bit it is accepted")
  void writableKeyDirectoryIsRefused() throws IOException {
    keyFile("pepper-2026", key(32), "rw-------");
    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxrwx---"));

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());
    assertTrue(refused.getMessage().startsWith("pepper/key-file-rejected: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("can be written by group or others (mode 770)"),
        refused.getMessage());

    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx---rwx"));
    assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load(),
        "write access for others is refused as well");

    assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("unix"),
        "the sticky bit needs the unix attribute view");
    Files.setAttribute(dir, "unix:mode", 01777);
    assertEquals(Optional.of("pepper-2026"), FilePepperService.fromDirectory(dir)
            .activeKeyId("pepper-2026").load().activeKeyId(),
        "with the sticky bit nobody else can rename or delete the key files");
    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
  }

  @Test
  @DisplayName("a key file with a second name (hard link) is refused")
  void hardLinkedKeyFileIsRefused() throws IOException {
    assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("unix"),
        "the link count needs the unix attribute view");
    Path file = keyFile("pepper-2026", key(32), "rw-------");
    Path elsewhere = Files.createDirectory(dir.resolve("elsewhere"));
    Path secondName = Files.createLink(elsewhere.resolve("copy"), file);

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());
    assertTrue(refused.getMessage().contains("has 2 names (hard links)"), refused.getMessage());

    Files.delete(secondName);
    assertEquals(Optional.of("pepper-2026"), FilePepperService.fromDirectory(dir)
        .activeKeyId("pepper-2026").load().activeKeyId(), "a single name is read again");
  }

  private static void assertNotZero(byte[] array, String message) {
    assertFalse(java.util.Arrays.equals(new byte[array.length], array), message);
  }

  @Test
  @DisplayName("a key file that is a symbolic link is refused, even to an owner-only file")
  void symbolicLinkIsRefused() throws IOException {
    Path target = keyFile("real-key", key(32), "rw-------");
    Files.createSymbolicLink(dir.resolve("pepper-2026"), target);

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());

    assertTrue(refused.getMessage().contains("symbolic link"), refused.getMessage());
  }

  @Test
  @DisplayName("a key directory that is a symbolic link is refused")
  void symbolicLinkDirectoryIsRefused() throws IOException {
    Path real = Files.createDirectory(dir.resolve("real"));
    Path file = real.resolve("pepper-2026");
    Files.writeString(file, Base64.getEncoder().encodeToString(key(32)));
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    Path link = Files.createSymbolicLink(dir.resolve("secrets"), real);

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(link).activeKeyId("pepper-2026").load());

    assertTrue(refused.getMessage().contains("key directory"), refused.getMessage());
    assertTrue(refused.getMessage().contains("symbolic link"), refused.getMessage());
  }

  @Test
  @DisplayName("a key shorter than 32 bytes is refused at load")
  void shortKeyIsRefused() throws IOException {
    keyFile("pepper-2026", key(16), "rw-------");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());

    assertTrue(refused.getMessage().contains("16 bytes"), refused.getMessage());
    assertTrue(refused.getMessage().contains(String.valueOf(PepperReference.MIN_KEY_BYTES)),
        refused.getMessage());
  }

  @Test
  @DisplayName("content that is not Base64 is refused without echoing it")
  void notBase64IsRefused() throws IOException {
    Path file = dir.resolve("pepper-2026");
    String content = "this-is-no-base64-but-a-secret-passphrase!";
    Files.writeString(file, content);
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());

    assertTrue(refused.getMessage().contains("Base64"), refused.getMessage());
    assertFalse(refused.getMessage().contains(content), refused.getMessage());
    assertNull(refused.getCause(),
        "the decoder's own message names the offending character; it is not attached");
  }

  @Test
  @DisplayName("missing, empty and oversized key files are refused")
  void missingEmptyAndOversizedFiles() throws IOException {
    IllegalStateException missing = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("pepper-2026").load());
    assertTrue(missing.getMessage().contains("does not exist"), missing.getMessage());

    Path empty = dir.resolve("empty");
    Files.writeString(empty, "\n");
    Files.setPosixFilePermissions(empty, PosixFilePermissions.fromString("rw-------"));
    IllegalStateException emptyRefused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("empty").load());
    assertTrue(emptyRefused.getMessage().contains("is empty"), emptyRefused.getMessage());

    Path large = dir.resolve("large");
    Files.writeString(large, Base64.getEncoder().encodeToString(
        key(FilePepperService.MAX_KEY_FILE_BYTES)));
    Files.setPosixFilePermissions(large, PosixFilePermissions.fromString("rw-------"));
    IllegalStateException largeRefused = assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).activeKeyId("large").load());
    assertTrue(largeRefused.getMessage().contains("larger than"), largeRefused.getMessage());
  }

  @Test
  @DisplayName("key ids that could leave the directory or hide a file are rejected")
  void keyIdShape() {
    FilePepperService.Builder builder = FilePepperService.fromDirectory(dir);
    for (String bad : List.of("", "../pepper", "a/b", ".hidden", "..", "with space", "a$b",
        "a,b", "x".repeat(65))) {
      assertThrows(IllegalArgumentException.class, () -> builder.activeKeyId(bad), bad);
      assertThrows(IllegalArgumentException.class, () -> builder.retiredKeyId(bad), bad);
    }
    builder.activeKeyId("x".repeat(64));
    builder.retiredKeyId("Pepper_2025-v1.b64");
  }

  @Test
  @DisplayName("a load without an active key id or with a key id named twice fails")
  void configurationErrors() throws IOException {
    keyFile("pepper-2026", key(32), "rw-------");

    assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir).retiredKeyId("pepper-2026").load());
    assertThrows(IllegalStateException.class,
        () -> FilePepperService.fromDirectory(dir)
            .activeKeyId("pepper-2026").retiredKeyId("pepper-2026").load());
  }
}
