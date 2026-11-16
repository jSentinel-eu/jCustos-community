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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * File-backed token store for {@link BootstrapMode#PERSISTENT_FILE}.
 * <p>
 * The token survives restarts as long as the file exists. POSIX systems
 * receive {@code rw-------} (0600) permissions on save; on a non-POSIX
 * filesystem owner-only permissions cannot be enforced and a WARN is logged
 * (JS-SEC-016) — place the file in an owner-only directory or prefer
 * {@code TRANSIENT_CONSOLE}.
 * <p>
 * A file found on disk is only adopted when it can have been written by this
 * store (JS-SEC-130, CWE-345, CWE-732): on POSIX it must be a regular file
 * that belongs to the user the process runs as and grants nothing to group
 * or others, and on every platform the token must have the shape
 * {@link BootstrapTokenGenerator} produces. Anything else is reported with a
 * WARN and treated as absent, so start-up generates a fresh token and
 * replaces the file. On a non-POSIX filesystem owner and permissions cannot
 * be checked; the behaviour there is unchanged (JS-SEC-016).
 * <p>
 * The file that was checked is the file that is read: it is opened without
 * following a symbolic link at the configured path, its identity is compared
 * with the one the check saw, and at most {@value #MAX_TOKEN_FILE_BYTES} bytes
 * are read from it (JS-SEC-130, CWE-367, CWE-59). Until 00.84.00 the check
 * looked at the entry itself but the read followed a link that could have
 * been put in its place in between, and the whole file was read whatever its
 * size.
 * <p>
 * Format (intentionally simple, no JSON dependency):
 * <pre>
 * token=XXXX-XXXX-XXXX-XXXX-XXXX
 * createdAt=2026-05-06T09:30:00Z
 * </pre>
 */
public final class FileBootstrapTokenStore implements BootstrapTokenStore, HasLogger {

  private static final EnumSet<PosixFilePermission> OWNER_RW =
      EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  /** Everything beyond the owner's bits — "wider than 0600" in the sense of JS-SEC-130. */
  private static final EnumSet<PosixFilePermission> GROUP_OR_OTHERS = EnumSet.of(
      PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
      PosixFilePermission.GROUP_EXECUTE,
      PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE,
      PosixFilePermission.OTHERS_EXECUTE);

  /**
   * Largest token file that is read: {@value} bytes. The two lines the store
   * writes need well under a hundred; a larger file was not written by it.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final int MAX_TOKEN_FILE_BYTES = 4_096;

  private final Path path;
  /** Test seam: runs between the trust check and the read. */
  Runnable afterTrustCheck = () -> { };

  public FileBootstrapTokenStore(Path path) {
    this.path = path;
  }

  @Override
  public Optional<BootstrapToken> load() {
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
    try {
      // JS-SEC-130 (CWE-345, CWE-732): the file content becomes the credential
      // for creating the first administrator. Adopt it only when nobody but
      // this process's user can have written or read it.
      BasicFileAttributes checked = trustedOnPosix();
      if (checked == null) {
        return Optional.empty();
      }
      afterTrustCheck.run();
      Optional<String> content = readChecked(checked);
      if (content.isEmpty()) {
        return Optional.empty();
      }
      List<String> lines = content.get().lines().toList();
      String tokenValue = null;
      Instant createdAt = null;
      for (String line : lines) {
        String trimmed = line.trim();
        if (trimmed.startsWith("token=")) {
          tokenValue = trimmed.substring("token=".length()).trim();
        } else if (trimmed.startsWith("createdAt=")) {
          try {
            createdAt = Instant.parse(trimmed.substring("createdAt=".length()).trim());
          } catch (DateTimeParseException ignored) {
            // fall through — corrupt file
          }
        }
      }
      if (tokenValue == null || tokenValue.isBlank() || createdAt == null) {
        return Optional.empty();
      }
      // JS-SEC-130 (CWE-345): a value the generator cannot have produced was
      // not written by save(). The value itself is never logged.
      if (!BootstrapTokenGenerator.isWellFormed(tokenValue)) {
        logger().warn("bootstrap/token-file-rejected: {} does not contain a token in the "
            + "generator's format; the file is ignored and a fresh token is required", path);
        return Optional.empty();
      }
      return Optional.of(new BootstrapToken(tokenValue, createdAt));
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  /**
   * JS-SEC-130 (CWE-367, CWE-59): reads the file the trust check judged. The
   * channel is opened without following a symbolic link, and the identity of
   * the entry is compared before and after the open, so a file swapped in after
   * the check is not read; a file larger than {@link #MAX_TOKEN_FILE_BYTES} is
   * not read either.
   *
   * @return the content, or empty when the file is not the one that was checked
   */
  private Optional<String> readChecked(BasicFileAttributes checked) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(MAX_TOKEN_FILE_BYTES + 1);
    try (SeekableByteChannel channel = Files.newByteChannel(path,
        Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
      BasicFileAttributes opened =
          Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!opened.isRegularFile()
          || (checked.fileKey() != null && !checked.fileKey().equals(opened.fileKey()))) {
        logger().warn("bootstrap/token-file-rejected: {} was replaced while it was being checked;"
            + " the file is ignored and a fresh token is required", path);
        return Optional.empty();
      }
      // read up to one byte beyond the limit, so that an oversized file is noticed
      int read;
      do {
        read = channel.read(buffer);
      } while (read >= 0 && buffer.hasRemaining());
    } catch (FileSystemException linkOrRace) {
      // ELOOP: a symbolic link took the place of the checked file
      logger().warn("bootstrap/token-file-rejected: {} could not be opened as the file that was"
          + " checked ({}); the file is ignored and a fresh token is required", path,
          linkOrRace.getClass().getSimpleName());
      return Optional.empty();
    }
    if (buffer.position() > MAX_TOKEN_FILE_BYTES) {
      logger().warn("bootstrap/token-file-rejected: {} is larger than {} bytes; the file is"
          + " ignored and a fresh token is required", path, MAX_TOKEN_FILE_BYTES);
      return Optional.empty();
    }
    buffer.flip();
    return Optional.of(StandardCharsets.UTF_8.decode(buffer).toString());
  }

  /**
   * JS-SEC-130: owner and permission check for a token file found on disk.
   *
   * @return the attributes the check judged when the file may be read — it
   *     passed the check, or the filesystem has no POSIX attributes (JS-SEC-016:
   *     nothing to check); {@code null} when it may not
   */
  private BasicFileAttributes trustedOnPosix() throws IOException {
    if (!path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }
    // NOFOLLOW_LINKS: judge the entry at the configured path itself. A symbolic
    // link there is not a file this store wrote, wherever it points.
    PosixFileAttributes attributes =
        Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!attributes.isRegularFile()) {
      logger().warn("bootstrap/token-file-rejected: {} is not a regular file; the file "
          + "is ignored and a fresh token is required", path);
      return null;
    }
    EnumSet<PosixFilePermission> excess = EnumSet.copyOf(GROUP_OR_OTHERS);
    excess.retainAll(attributes.permissions());
    if (!excess.isEmpty()) {
      logger().warn("bootstrap/token-file-rejected: {} is accessible beyond its owner "
          + "(permissions {}); the file is ignored and a fresh token is required",
          path, PosixFilePermissions.toString(attributes.permissions()));
      return null;
    }
    Optional<UserPrincipal> self = processUser();
    if (self.isEmpty() || !self.get().equals(attributes.owner())) {
      logger().warn("bootstrap/token-file-rejected: {} belongs to '{}', not to the user "
          + "this process runs as; the file is ignored and a fresh token is required",
          path, attributes.owner().getName());
      return null;
    }
    return attributes;
  }

  /**
   * The principal files created by this process belong to. Resolved from
   * {@code user.name}; where that name has no entry in the user database (a
   * container running under an arbitrary uid), the owner of a probe file
   * created next to the token file is used instead.
   *
   * @return the principal, or empty when it cannot be determined — the caller
   *     then rejects the token file
   */
  private Optional<UserPrincipal> processUser() {
    try {
      return Optional.of(path.getFileSystem().getUserPrincipalLookupService()
          .lookupPrincipalByName(System.getProperty("user.name")));
    } catch (IOException | RuntimeException lookupFailed) {
      // fall through to the probe
    }
    Path parent = path.toAbsolutePath().getParent();
    if (parent == null) {
      return Optional.empty();
    }
    Path probe = null;
    try {
      probe = Files.createTempFile(parent, ".bootstrap-owner-", ".probe",
          PosixFilePermissions.asFileAttribute(OWNER_RW));
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

  @Override
  public void save(BootstrapToken token) {
    try {
      Path parent = path.toAbsolutePath().getParent();
      if (parent != null) Files.createDirectories(parent);
      // Create the file atomically with restrictive permissions so it never
      // exists with default umask permissions, even briefly.
      Files.deleteIfExists(path);
      boolean posix = path.getFileSystem().supportedFileAttributeViews().contains("posix");
      FileAttribute<?>[] attrs = posix
          ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(OWNER_RW)}
          : new FileAttribute<?>[0];
      String content =
          "token=" + token.value() + System.lineSeparator()
              + "createdAt=" + token.createdAt() + System.lineSeparator();
      try (var channel = Files.newByteChannel(path,
          EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
          attrs)) {
        channel.write(StandardCharsets.UTF_8.encode(content));
      }
      if (!posix) {
        // JS-SEC-016 (CWE-256): owner-only permissions could not be enforced on
        // this non-POSIX filesystem. The bootstrap token is a plaintext
        // credential — place the file in an owner-only directory, or prefer
        // TRANSIENT_CONSOLE.
        logger().warn("bootstrap/token-file-permissions: owner-only permissions could "
            + "not be enforced for {} on a non-POSIX filesystem; ensure the containing "
            + "directory restricts access, or use TRANSIENT_CONSOLE", path);
      }
    } catch (IOException e) {
      throw new IllegalStateException("Could not write bootstrap token file", e);
    }
  }

  @Override
  public void invalidate() {
    try {
      Files.deleteIfExists(path);
    } catch (IOException e) {
      throw new IllegalStateException("Could not delete bootstrap token file", e);
    }
  }

  public Path path() {
    return path;
  }
}
