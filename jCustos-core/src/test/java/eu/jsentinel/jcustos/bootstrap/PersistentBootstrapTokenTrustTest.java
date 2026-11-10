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

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * JS-SEC-130 (CWE-345, CWE-732, CWE-613): in {@code PERSISTENT_FILE} mode a
 * token file found on disk is only adopted when this installation can have
 * written it. Real files in a temporary directory, the real store, start-up
 * and bootstrap service.
 */
@DisplayName("JS-SEC-130 — a planted bootstrap token file is not adopted")
class PersistentBootstrapTokenTrustTest {

  /** A value in the generator's format, as an attacker who read the source would plant it. */
  private static final String PLANTED = "PLAN-TEDB-YLXC-ALUS-ER22";
  private static final String NOT_GENERATOR_SHAPED = "planted-by-local-user";

  @TempDir
  Path dir;

  private static final class Administrators implements AdministratorAccountStore {
    final List<NewAdministrator> created = new ArrayList<>();

    @Override
    public boolean hasAnyAdministrator() {
      return !created.isEmpty();
    }

    @Override
    public void createAdministrator(NewAdministrator administrator) {
      created.add(administrator);
    }
  }

  private static void assumePosix() {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner and permission checks exist on POSIX filesystems only (JS-SEC-016)");
  }

  private Path plant(String token, Instant createdAt, String permissions) throws IOException {
    Path file = dir.resolve("bootstrap-token");
    Files.writeString(file, "token=" + token + "\ncreatedAt=" + createdAt + "\n");
    if (permissions != null) {
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions));
    }
    return file;
  }

  /** Runs start-up against {@code file} and returns the token it announced. */
  private static BootstrapToken startUp(Path file, Administrators admins) {
    AtomicReference<BootstrapToken> announced = new AtomicReference<>();
    BootstrapStartup.initializeIfRequired(
        new BootstrapStateService(admins, BootstrapMode.PERSISTENT_FILE),
        new FileBootstrapTokenStore(file), new BootstrapTokenGenerator(),
        (token, configuration) -> announced.set(token),
        BootstrapConfiguration.persistent(file));
    return announced.get();
  }

  private static InitialAdminCreationResult createAdmin(
      Path file, Administrators admins, String token) {
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        new BootstrapStateService(admins, BootstrapMode.PERSISTENT_FILE),
        new FileBootstrapTokenStore(file), admins,
        new CredentialTestKit().hashing, new MinimumLengthPasswordPolicy(12));
    return service.createInitialAdmin(new CreateInitialAdminCommand(
        token, "intruder", "a-long-password-123".toCharArray(), "Intruder", null));
  }

  private void assertPlantedTokenIsDead(Path file, String planted) throws IOException {
    Administrators admins = new Administrators();

    BootstrapToken announced = startUp(file, admins);

    assertFalse(announced.matches(planted), "start-up must not announce the planted token");
    assertTrue(BootstrapTokenGenerator.isWellFormed(announced.value()));
    assertEquals(announced.value(),
        new FileBootstrapTokenStore(file).load().orElseThrow().value(),
        "the file is replaced by the fresh token");
    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
          Files.getPosixFilePermissions(file));
    }
    assertInstanceOf(InitialAdminCreationResult.InvalidBootstrapToken.class,
        createAdmin(file, admins, planted));
    assertTrue(admins.created.isEmpty());
    assertInstanceOf(InitialAdminCreationResult.Created.class,
        createAdmin(file, admins, announced.value()),
        "the fresh token still works for the operator");
  }

  @Test
  @DisplayName("a file readable beyond its owner (0644) is rejected; start-up issues another token")
  void worldReadableFileIsReplaced() throws IOException {
    assumePosix();
    Path file = plant(PLANTED, Instant.now(), "rw-r--r--");

    assertTrue(new FileBootstrapTokenStore(file).load().isEmpty());
    assertPlantedTokenIsDead(file, PLANTED);
  }

  @Test
  @DisplayName("a file writable by the group (0660) is rejected")
  void groupWritableFileIsRejected() throws IOException {
    assumePosix();
    Path file = plant(PLANTED, Instant.now(), "rw-rw----");

    assertTrue(new FileBootstrapTokenStore(file).load().isEmpty());
  }

  @Test
  @DisplayName("a creation instant in the future never expired before; now start-up issues another token")
  void futureCreatedAtIsReplaced() throws IOException {
    Path file = plant(PLANTED, Instant.parse("2099-01-01T00:00:00Z"),
        FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
            ? "rw-------" : null);

    assertPlantedTokenIsDead(file, PLANTED);
  }

  @Test
  @DisplayName("a token from the future is refused by the bootstrap service even without a restart")
  void futureCreatedAtIsRefusedByTheService() throws IOException {
    Path file = plant(PLANTED, Instant.now().plus(Duration.ofDays(365)),
        FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
            ? "rw-------" : null);
    Administrators admins = new Administrators();

    assertInstanceOf(InitialAdminCreationResult.InvalidBootstrapToken.class,
        createAdmin(file, admins, PLANTED));
    assertTrue(admins.created.isEmpty());
  }

  @Test
  @DisplayName("a value the generator cannot have produced is rejected, whatever the permissions")
  void foreignFormatIsReplaced() throws IOException {
    Path file = plant(NOT_GENERATOR_SHAPED, Instant.now(),
        FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
            ? "rw-------" : null);

    assertTrue(new FileBootstrapTokenStore(file).load().isEmpty());
    assertPlantedTokenIsDead(file, NOT_GENERATOR_SHAPED);
  }

  @Test
  @DisplayName("a file of another owner is rejected")
  void foreignOwnerIsRejected() throws IOException {
    assumePosix();
    Path file = plant(PLANTED, Instant.now(), "rw-------");
    UserPrincipal owner = Files.getOwner(file);
    assumeFalse(owner.getName().equals("root"), "the test needs a non-root user");
    // The store compares the file's owner with the user the process runs as.
    // Changing a file's owner needs privileges the test does not have, so the
    // process is told it runs as another existing user for the duration of load().
    String original = System.getProperty("user.name");
    System.setProperty("user.name", "root");
    try {
      assumeTrue(resolves("root"), "no user 'root' on this system");
      assertTrue(new FileBootstrapTokenStore(file).load().isEmpty());
    } finally {
      System.setProperty("user.name", original);
    }
    assertTrue(new FileBootstrapTokenStore(file).load().isPresent(),
        "the same file is accepted for its real owner");
  }

  @Test
  @DisplayName("a symbolic link at the token path is rejected even when its target looks right")
  void symbolicLinkIsRejected() throws IOException {
    assumePosix();
    Path target = dir.resolve("elsewhere");
    Files.writeString(target, "token=" + PLANTED + "\ncreatedAt=" + Instant.now() + "\n");
    Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
    Path link = dir.resolve("bootstrap-token");
    Files.createSymbolicLink(link, target);

    assertTrue(new FileBootstrapTokenStore(link).load().isEmpty());
  }

  @Test
  @DisplayName("the store's own file is still adopted after a restart")
  void ownFileIsReused() {
    Path file = dir.resolve("bootstrap-token");
    Administrators admins = new Administrators();

    BootstrapToken first = startUp(file, admins);
    BootstrapToken second = startUp(file, admins);

    assertEquals(first.value(), second.value(),
        "PERSISTENT_FILE keeps the token across restarts when the file is its own");
  }

  @Test
  @DisplayName("without a user-database entry for the process the owner is taken from a probe file")
  void ownerProbeWhenTheUserNameDoesNotResolve() {
    assumePosix();
    Path file = dir.resolve("bootstrap-token");
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(file);
    store.save(new BootstrapTokenGenerator().generate());
    String original = System.getProperty("user.name");
    System.setProperty("user.name", "no-such-user-jcustos-" + System.nanoTime());
    try {
      assertTrue(store.load().isPresent(),
          "a container uid without a passwd entry must not lose its own token file");
    } finally {
      System.setProperty("user.name", original);
    }
    try (var entries = Files.list(dir)) {
      assertEquals(List.of(file), entries.toList(), "the probe file is removed again");
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  @DisplayName("isExpired: beyond the tolerance a future creation instant is expired, within it it is not")
  void futureTolerance() {
    Instant now = Instant.parse("2026-11-10T10:00:00Z");
    Duration validity = Duration.ofHours(24);

    assertTrue(new BootstrapToken(PLANTED, now.plus(BootstrapToken.FUTURE_TOLERANCE).plusSeconds(1))
        .isExpired(now, validity));
    assertFalse(new BootstrapToken(PLANTED, now.plus(BootstrapToken.FUTURE_TOLERANCE))
        .isExpired(now, validity), "a clock set back by a few minutes must not kill a fresh token");
    assertFalse(new BootstrapToken(PLANTED, now).isExpired(now, validity));
    assertTrue(new BootstrapToken(PLANTED, now.minus(validity).minusSeconds(1))
        .isExpired(now, validity));
  }

  @Test
  @DisplayName("isWellFormed accepts what the generator produces and nothing else")
  void wellFormedness() {
    BootstrapTokenGenerator generator = new BootstrapTokenGenerator();
    for (int i = 0; i < 200; i++) {
      assertTrue(BootstrapTokenGenerator.isWellFormed(generator.generate().value()));
    }
    assertTrue(BootstrapTokenGenerator.isWellFormed(PLANTED));
    for (String bad : new String[] {
        null, "", NOT_GENERATOR_SHAPED,
        "ABCD-EFGH-JKLM-NPQR",            // too short
        "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ",  // too long
        "ABCDEFGHJKLMNPQRSTUVWXYZ",       // no separators
        "ABCD_EFGH_JKLM_NPQR_STUV",       // wrong separator
        "ABCD-EFGH-JKLM-NPQR-STU0",       // 0 is not in the alphabet
        "ABCD-EFGH-JKLM-NPQR-STUO",       // neither is O
        "abcd-efgh-jklm-npqr-stuv",       // lower case
        "ABCD-EFGH-JKLM-NPQR-STUV\n"}) {
      assertFalse(BootstrapTokenGenerator.isWellFormed(bad), String.valueOf(bad));
    }
    assertNotEquals(generator.generate().value(), generator.generate().value());
  }

  private static boolean resolves(String userName) {
    try {
      FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(userName);
      return true;
    } catch (IOException | RuntimeException notFound) {
      return false;
    }
  }
}
