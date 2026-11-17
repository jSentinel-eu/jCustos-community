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

import com.svenruppert.dependencies.core.logger.HasLogger;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Reads the files the pepper sources load their keys from, and checks the key ids they
 * accept.
 *
 * <p>A key file is read only when nobody but the user the process runs as can have written
 * or read it (CWE-276, CWE-732), and the file that was checked is the file that is read
 * (CWE-367, CWE-59): the entry at the configured path is judged without following a
 * symbolic link, it must be a regular file, on POSIX it must belong to the process user and
 * grant nothing to group or others, it is opened without following a link, its identity is
 * compared with the one the check saw, and only a bounded number of bytes is read. These are
 * the rules {@code FileBootstrapTokenStore} (JS-SEC-130) applies to the bootstrap token file
 * and {@code StorageTreeHardening} (JS-SEC-136) to storage directories; neither is reachable
 * from here, so the rules are repeated, not shared. On a filesystem without POSIX attributes
 * owner and permissions cannot be checked (JS-SEC-016): that is logged, and the symbolic-link
 * and identity checks still apply.</p>
 *
 * <p>Nothing read from a file appears in a message or a log line: the messages name the
 * path, never the content.</p>
 */
final class PepperSourceFiles {

  /**
   * A key id: 1 to {@value #MAX_KEY_ID_LENGTH} characters from {@code [A-Za-z0-9._-]}, not
   * starting with a dot. It is written into every peppered envelope and, for
   * {@link FilePepperService}, used as a file name, so it can contain neither a path
   * separator nor an envelope separator, and it cannot name {@code .}, {@code ..} or a
   * hidden file.
   */
  static final int MAX_KEY_ID_LENGTH = 64;

  private static final Pattern KEY_ID =
      Pattern.compile("[A-Za-z0-9_-][A-Za-z0-9._-]{0," + (MAX_KEY_ID_LENGTH - 1) + "}");

  private PepperSourceFiles() {
    // utility class — never instantiated
  }

  /**
   * @param keyId the key id to check
   * @param what  what the id names, for the message ("key id", "alias")
   * @return {@code keyId}
   * @throws IllegalArgumentException when the id does not have the documented shape; the
   *                                  message does not repeat the value, which may be key
   *                                  material passed in the wrong place
   */
  static String requireKeyId(String keyId, String what) {
    Objects.requireNonNull(keyId, what);
    if (!KEY_ID.matcher(keyId).matches()) {
      throw new IllegalArgumentException("the " + what + " must be 1 to " + MAX_KEY_ID_LENGTH
          + " characters from [A-Za-z0-9._-] and must not start with a dot (got "
          + keyId.length() + " characters)");
    }
    return keyId;
  }

  /**
   * Checks that {@code directory} is a directory and not itself a symbolic link (CWE-59): a
   * link there could be pointed elsewhere between two loads.
   *
   * @throws IllegalStateException with a message that starts with {@code code}
   */
  static void requireDirectory(Path directory, String code) {
    BasicFileAttributes attributes;
    try {
      attributes = Files.readAttributes(directory, BasicFileAttributes.class,
          LinkOption.NOFOLLOW_LINKS);
    } catch (IOException | RuntimeException unreadable) {
      throw new IllegalStateException(code + ": the key directory " + directory
          + " cannot be read (" + unreadable.getClass().getSimpleName() + ")");
    }
    if (attributes.isSymbolicLink()) {
      throw new IllegalStateException(code + ": the key directory " + directory
          + " is a symbolic link; configure the directory it points to");
    }
    if (!attributes.isDirectory()) {
      throw new IllegalStateException(code + ": " + directory + " is not a directory");
    }
  }

  /**
   * Reads a key-bearing file under the rules of the class comment.
   *
   * @param file     the file
   * @param maxBytes the largest file that is read
   * @param code     the stable code that starts every message
   * @return the content; the caller owns the array and zeroes it
   * @throws IllegalStateException when the file is refused or cannot be read
   */
  static byte[] readTrusted(Path file, int maxBytes, String code) {
    return readTrusted(file, maxBytes, code, PepperSourceFiles::processUser);
  }

  /** Test seam: {@code whoAmI} names the principal the file has to belong to. */
  static byte[] readTrusted(Path file, int maxBytes, String code,
                            Function<Path, Optional<UserPrincipal>> whoAmI) {
    BasicFileAttributes checked = check(file, code, whoAmI);
    ByteBuffer buffer = ByteBuffer.allocate(maxBytes + 1);
    try {
      try (SeekableByteChannel channel = Files.newByteChannel(file,
          Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
        BasicFileAttributes opened =
            Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!opened.isRegularFile()
            || (checked.fileKey() != null && !checked.fileKey().equals(opened.fileKey()))) {
          throw new IllegalStateException(code + ": " + file
              + " was replaced while it was being checked");
        }
        // read up to one byte beyond the limit, so that an oversized file is noticed
        int read;
        do {
          read = channel.read(buffer);
        } while (read >= 0 && buffer.hasRemaining());
      } catch (FileSystemException linkOrRace) {
        // ELOOP: a symbolic link took the place of the checked file
        throw new IllegalStateException(code + ": " + file
            + " could not be opened as the file that was checked ("
            + linkOrRace.getClass().getSimpleName() + ")");
      } catch (IOException unreadable) {
        throw new IllegalStateException(code + ": " + file + " cannot be read ("
            + unreadable.getClass().getSimpleName() + ")");
      }
      if (buffer.position() > maxBytes) {
        throw new IllegalStateException(code + ": " + file + " is larger than " + maxBytes
            + " bytes");
      }
      return Arrays.copyOf(buffer.array(), buffer.position());
    } finally {
      Arrays.fill(buffer.array(), (byte) 0);
    }
  }

  /**
   * @return the attributes the check judged
   * @throws IllegalStateException when the file may not be read
   */
  private static BasicFileAttributes check(Path file, String code,
                                           Function<Path, Optional<UserPrincipal>> whoAmI) {
    boolean posix = file.getFileSystem().supportedFileAttributeViews().contains("posix");
    BasicFileAttributes attributes;
    try {
      // NOFOLLOW_LINKS: judge the entry at the configured path itself. A symbolic link there
      // is refused, wherever it points.
      attributes = posix
          ? Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
          : Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    } catch (NoSuchFileException missing) {
      throw new IllegalStateException(code + ": " + file + " does not exist");
    } catch (IOException | RuntimeException unreadable) {
      throw new IllegalStateException(code + ": " + file + " cannot be read ("
          + unreadable.getClass().getSimpleName() + ")");
    }
    if (attributes.isSymbolicLink()) {
      throw new IllegalStateException(code + ": " + file + " is a symbolic link; configure the"
          + " file it points to, or copy the key into a regular file");
    }
    if (!attributes.isRegularFile()) {
      throw new IllegalStateException(code + ": " + file + " is not a regular file");
    }
    if (!posix) {
      HasLogger.staticLogger().warn("{}: owner and permissions of {} cannot be checked on a"
          + " filesystem without POSIX attributes; make sure only the process user can read"
          + " the file (JS-SEC-016)", code, file);
      return attributes;
    }
    PosixFileAttributes posixAttributes = (PosixFileAttributes) attributes;
    if (posixAttributes.permissions().stream().anyMatch(PepperSourceFiles::beyondOwner)) {
      throw new IllegalStateException(code + ": " + file + " is accessible beyond its owner"
          + " (permissions " + PosixFilePermissions.toString(posixAttributes.permissions())
          + "); restrict it to 0400 or 0600");
    }
    Optional<UserPrincipal> self = whoAmI.apply(file);
    if (self.isEmpty() || !self.get().equals(posixAttributes.owner())) {
      throw new IllegalStateException(code + ": " + file + " belongs to '"
          + posixAttributes.owner().getName() + "', not to the user this process runs as");
    }
    return attributes;
  }

  /** Whether {@code permission} grants anything to group or others. */
  private static boolean beyondOwner(PosixFilePermission permission) {
    return switch (permission) {
      case OWNER_READ, OWNER_WRITE, OWNER_EXECUTE -> false;
      default -> true;
    };
  }

  /**
   * The principal files created by this process belong to — the approach of
   * {@code FileBootstrapTokenStore} (JS-SEC-130): resolved from {@code user.name}; where that
   * name has no entry in the user database (a container running under an arbitrary uid), the
   * owner of a probe file in the temporary directory is used instead, because a key directory
   * such as {@code /run/secrets} is usually read-only.
   *
   * @return the principal, or empty when it cannot be determined — the caller then refuses
   */
  private static Optional<UserPrincipal> processUser(Path file) {
    try {
      return Optional.of(file.getFileSystem().getUserPrincipalLookupService()
          .lookupPrincipalByName(System.getProperty("user.name")));
    } catch (IOException | RuntimeException lookupFailed) {
      // fall through to the probe
    }
    Path probe = null;
    try {
      probe = Files.createTempFile(".pepper-owner-", ".probe",
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
