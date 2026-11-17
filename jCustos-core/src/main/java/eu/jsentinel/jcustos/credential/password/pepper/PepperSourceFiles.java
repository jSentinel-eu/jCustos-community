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
import com.svenruppert.functional.result.Result;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
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
 * symbolic link, it must be a regular file with a single name (a hard link is refused where
 * the filesystem reports the link count), on POSIX it must belong to the process user and
 * grant nothing to group or others, it is opened without following a link, its identity and
 * size are compared with the ones the check saw, and only a bounded number of bytes is read.
 * These are the rules {@code FileBootstrapTokenStore} (JS-SEC-130) applies to the bootstrap
 * token file and {@code StorageTreeHardening} (JS-SEC-136) to storage directories; neither is
 * reachable from here, so the rules are repeated, not shared. On a filesystem without POSIX
 * attributes owner and permissions cannot be checked (JS-SEC-016): that is logged, and the
 * symbolic-link and identity checks still apply.</p>
 *
 * <p><strong>The key directory</strong> ({@link #openDirectory}, since 00.84.00) must not
 * be a symbolic link, must not be writable by group or others unless its sticky bit is set,
 * and must belong to the process user or to the superuser: whoever can write the directory
 * can put a file of their own in place of the checked one between the check and the read.
 * Where the JDK offers a {@link SecureDirectoryStream} (Linux, macOS) the directory is opened
 * once; its owner and mode are those of the directory that is open, and every key file is
 * judged and opened relative to it, so the directory cannot be swapped underneath the load.
 * {@link #readTrusted} pins the directory of a single file the same way, without the
 * directory rules.</p>
 *
 * <p><strong>What remains.</strong> The JDK reads neither the owner nor the permissions of an
 * opened file, only its size. A key file is therefore judged by its entry in the opened
 * directory before and after it is opened, and that entry can be replaced only by someone
 * who can write the directory - the process user or the superuser, once the directory has
 * passed its check. The link count is read through the path and bound to the checked file
 * by its identity; a mismatch refuses the file. The directories above the key directory are
 * not checked: someone who can rename entries in one of them can move the key directory
 * aside before it is opened. Without a {@link SecureDirectoryStream} - Windows, a directory
 * the process may traverse but not list - every check runs against the path, and such a swap
 * between the check of the directory and the read of a file is possible as well.</p>
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

  /** Write permission for group or others in a Unix mode. */
  private static final int GROUP_OR_OTHERS_WRITE = 0022;
  /** The sticky bit: only an entry's owner may rename or delete it. */
  private static final int STICKY_BIT = 01000;
  /** The permission and special bits of a Unix mode. */
  private static final int MODE_BITS = 07777;
  /** The superuser, who can replace anything anyway. */
  private static final int SUPERUSER_UID = 0;
  /** Ends the refusal of a key directory that belongs to someone else. */
  private static final String DIRECTORY_OWNER_RULE = " or to the superuser; its owner can"
      + " replace the key files in it";

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
   * Opens and checks a key directory under the rules of the class comment; the key files are
   * then read relative to the directory that was checked.
   *
   * @param directory the directory that holds one file per key id
   * @param code      the stable code that starts every message
   * @return the opened directory; the caller closes it
   * @throws IllegalStateException when the directory is refused or cannot be read
   */
  static KeyDirectory openDirectory(Path directory, String code) {
    return openDirectory(directory, code, PepperSourceFiles::processUser);
  }

  /** Test seam: {@code whoAmI} names the principal directory and files have to belong to. */
  static KeyDirectory openDirectory(Path directory, String code,
                                    Function<Path, Result<UserPrincipal, String>> whoAmI) {
    BasicFileAttributes byPath;
    try {
      byPath = Files.readAttributes(directory, BasicFileAttributes.class,
          LinkOption.NOFOLLOW_LINKS);
    } catch (IOException | RuntimeException unreadable) {
      throw new IllegalStateException(code + ": the key directory " + directory
          + " cannot be read (" + unreadable.getClass().getSimpleName() + ")");
    }
    if (byPath.isSymbolicLink()) {
      throw new IllegalStateException(code + ": the key directory " + directory
          + " is a symbolic link; configure the directory it points to");
    }
    if (!byPath.isDirectory()) {
      throw new IllegalStateException(code + ": " + directory + " is not a directory");
    }
    SecureDirectoryStream<Path> pinned = pin(directory, code);
    try {
      Object checkedKey = byPath.fileKey();
      if (pinned != null) {
        Object openedKey = pinned.getFileAttributeView(BasicFileAttributeView.class)
            .readAttributes().fileKey();
        if (checkedKey != null && !checkedKey.equals(openedKey)) {
          throw new IllegalStateException(code + ": the key directory " + directory
              + " was replaced while it was being opened");
        }
        checkedKey = openedKey;
      }
      requireDirectoryRules(directory, checkedKey, code, whoAmI);
      return new KeyDirectory(directory, pinned, code, whoAmI);
    } catch (IOException unreadable) {
      close(pinned);
      throw new IllegalStateException(code + ": the key directory " + directory
          + " cannot be read (" + unreadable.getClass().getSimpleName() + ")");
    } catch (RuntimeException | Error refused) {
      close(pinned);
      throw refused;
    }
  }

  /**
   * The owner and mode rules for a key directory, read from the directory whose identity is
   * {@code expectedKey} - the one that is open.
   */
  private static void requireDirectoryRules(Path directory, Object expectedKey, String code,
                                            Function<Path, Result<UserPrincipal, String>> whoAmI)
      throws IOException {
    Set<String> views = directory.getFileSystem().supportedFileAttributeViews();
    if (!views.contains("posix")) {
      HasLogger.staticLogger().warn("{}: owner and permissions of the key directory {} cannot be"
          + " checked on a filesystem without POSIX attributes; make sure only the process user"
          + " can write it (JS-SEC-016)", code, directory);
      return;
    }
    if (views.contains("unix")) {
      Map<String, Object> unix = Files.readAttributes(directory, "unix:mode,uid,owner,fileKey",
          LinkOption.NOFOLLOW_LINKS);
      requireSame(expectedKey, unix.get("fileKey"), directory, code);
      int mode = (Integer) unix.get("mode");
      if ((mode & GROUP_OR_OTHERS_WRITE) != 0 && (mode & STICKY_BIT) == 0) {
        throw new IllegalStateException(code + ": the key directory " + directory
            + " can be written by group or others (mode " + Integer.toOctalString(mode & MODE_BITS)
            + "), who can put a key file of their own in place of the checked one; restrict it"
            + " to 0700 or 0755");
      }
      if ((Integer) unix.get("uid") == SUPERUSER_UID) {
        return;
      }
      requireProcessUser(directory, (UserPrincipal) unix.get("owner"), code, whoAmI,
          "the key directory " + directory, DIRECTORY_OWNER_RULE);
      return;
    }
    // POSIX without the unix view: neither the sticky bit nor the uid can be read - fail closed
    PosixFileAttributes posix = Files.readAttributes(directory, PosixFileAttributes.class,
        LinkOption.NOFOLLOW_LINKS);
    requireSame(expectedKey, posix.fileKey(), directory, code);
    if (posix.permissions().contains(PosixFilePermission.GROUP_WRITE)
        || posix.permissions().contains(PosixFilePermission.OTHERS_WRITE)) {
      throw new IllegalStateException(code + ": the key directory " + directory
          + " can be written by group or others (permissions "
          + PosixFilePermissions.toString(posix.permissions()) + "); restrict it to 0700 or 0755");
    }
    requireProcessUser(directory, posix.owner(), code, whoAmI,
        "the key directory " + directory, DIRECTORY_OWNER_RULE);
  }

  /**
   * Reads a key-bearing file under the rules of the class comment. Its directory is pinned
   * where the JDK allows it; the directory rules of {@link #openDirectory} do not apply.
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
                            Function<Path, Result<UserPrincipal, String>> whoAmI) {
    Path parent = file.toAbsolutePath().getParent();
    SecureDirectoryStream<Path> pinned = parent == null ? null : pin(parent, code);
    try {
      Location location = pinned == null
          ? new ByPath(file)
          : new Pinned(pinned, file.toAbsolutePath().getFileName(), file);
      return read(location, maxBytes, code, whoAmI);
    } finally {
      close(pinned);
    }
  }

  /**
   * An opened key directory whose checks passed. Its key files are judged and opened relative
   * to it where the JDK offers a {@link SecureDirectoryStream}, through their path otherwise.
   */
  static final class KeyDirectory implements AutoCloseable {

    private final Path directory;
    /** {@code null} where the JDK offers no secure directory stream. */
    private final SecureDirectoryStream<Path> pinned;
    private final String code;
    private final Function<Path, Result<UserPrincipal, String>> whoAmI;

    private KeyDirectory(Path directory, SecureDirectoryStream<Path> pinned, String code,
                         Function<Path, Result<UserPrincipal, String>> whoAmI) {
      this.directory = directory;
      this.pinned = pinned;
      this.code = code;
      this.whoAmI = whoAmI;
    }

    /**
     * Reads the key file {@code fileName} of this directory.
     *
     * @param fileName a checked key id
     * @param maxBytes the largest file that is read
     * @return the content; the caller owns the array and zeroes it
     * @throws IllegalStateException when the file is refused or cannot be read
     */
    byte[] read(String fileName, int maxBytes) {
      Path file = directory.resolve(fileName);
      Location location = pinned == null
          ? new ByPath(file)
          : new Pinned(pinned, file.getFileName(), file);
      return PepperSourceFiles.read(location, maxBytes, code, whoAmI);
    }

    /** @return {@code true} when the key files are read relative to the opened directory */
    boolean pinned() {
      return pinned != null;
    }

    @Override
    public void close() {
      PepperSourceFiles.close(pinned);
    }
  }

  /** Where a key file is judged and opened: relative to an opened directory, or by its path. */
  private interface Location {

    /** @return the file as configured, for messages and for the link count */
    Path file();

    /** @return the attributes of the entry itself, without following a symbolic link */
    <A extends BasicFileAttributes> A attributes(Class<A> type) throws IOException;

    /** @return the entry opened for reading, without following a symbolic link */
    SeekableByteChannel open() throws IOException;
  }

  private record ByPath(Path file) implements Location {

    @Override
    public <A extends BasicFileAttributes> A attributes(Class<A> type) throws IOException {
      return Files.readAttributes(file, type, LinkOption.NOFOLLOW_LINKS);
    }

    @Override
    public SeekableByteChannel open() throws IOException {
      return Files.newByteChannel(file, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
    }
  }

  /** @param name the file name, relative to {@code directory} */
  private record Pinned(SecureDirectoryStream<Path> directory, Path name, Path file)
      implements Location {

    @Override
    public <A extends BasicFileAttributes> A attributes(Class<A> type) throws IOException {
      Class<? extends BasicFileAttributeView> view = type == PosixFileAttributes.class
          ? PosixFileAttributeView.class
          : BasicFileAttributeView.class;
      BasicFileAttributeView entry =
          directory.getFileAttributeView(name, view, LinkOption.NOFOLLOW_LINKS);
      if (entry == null) {
        throw new IOException("no " + view.getSimpleName() + " for the entry");
      }
      return type.cast(entry.readAttributes());
    }

    @Override
    public SeekableByteChannel open() throws IOException {
      return directory.newByteChannel(name,
          Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
    }
  }

  /** Checks and reads the file at {@code location}. */
  private static byte[] read(Location location, int maxBytes, String code,
                             Function<Path, Result<UserPrincipal, String>> whoAmI) {
    Path file = location.file();
    BasicFileAttributes checked = check(location, code, whoAmI);
    ByteBuffer buffer = ByteBuffer.allocate(maxBytes + 1);
    try {
      try (SeekableByteChannel channel = location.open()) {
        // the owner and permissions of an opened file cannot be read through the JDK; its size
        // can, and the entry it was opened from is judged once more
        BasicFileAttributes opened = location.attributes(BasicFileAttributes.class);
        if (!opened.isRegularFile()
            || (checked.fileKey() != null && !checked.fileKey().equals(opened.fileKey()))
            || channel.size() != checked.size()) {
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
  private static BasicFileAttributes check(Location location, String code,
                                           Function<Path, Result<UserPrincipal, String>> whoAmI) {
    Path file = location.file();
    boolean posix = file.getFileSystem().supportedFileAttributeViews().contains("posix");
    BasicFileAttributes attributes;
    try {
      // NOFOLLOW_LINKS: judge the entry at the configured path itself. A symbolic link there
      // is refused, wherever it points.
      attributes = posix
          ? location.attributes(PosixFileAttributes.class)
          : location.attributes(BasicFileAttributes.class);
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
    requireSingleName(file, attributes, code);
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
    requireProcessUser(file, posixAttributes.owner(), code, whoAmI, file.toString(), "");
    return attributes;
  }

  /**
   * Refuses a key file with more than one name where the filesystem reports the link count:
   * whoever holds the other name - in a directory the checks never saw - can change the key
   * (CWE-59). The count is read through the path and bound to the checked file by its identity.
   */
  private static void requireSingleName(Path file, BasicFileAttributes checked, String code) {
    if (!file.getFileSystem().supportedFileAttributeViews().contains("unix")) {
      return;
    }
    Map<String, Object> unix;
    try {
      unix = Files.readAttributes(file, "unix:nlink,fileKey", LinkOption.NOFOLLOW_LINKS);
    } catch (IOException | RuntimeException unreadable) {
      throw new IllegalStateException(code + ": " + file + " cannot be read ("
          + unreadable.getClass().getSimpleName() + ")");
    }
    if (checked.fileKey() != null && !checked.fileKey().equals(unix.get("fileKey"))) {
      throw new IllegalStateException(code + ": " + file
          + " was replaced while it was being checked");
    }
    int names = (Integer) unix.get("nlink");
    if (names > 1) {
      throw new IllegalStateException(code + ": " + file + " has " + names + " names (hard"
          + " links); whoever can reach another of them can change the key - copy the key into"
          + " a file of its own");
    }
  }

  /**
   * Refuses {@code path} unless {@code owner} is the user the process runs as.
   *
   * @param what  how the message names {@code path}
   * @param after what the message adds to "not to the user this process runs as"
   */
  private static void requireProcessUser(Path path, UserPrincipal owner, String code,
                                         Function<Path, Result<UserPrincipal, String>> whoAmI,
                                         String what, String after) {
    Result<UserPrincipal, String> self = whoAmI.apply(path);
    if (self.isFailure()) {
      // SP05: "cannot tell who I am" is no "belongs to someone else"
      throw new IllegalStateException(code + ": the user this process runs as cannot be"
          + " determined (" + self.fold(principal -> "", reason -> reason) + "), so the owner"
          + " of " + what + " cannot be checked; it is refused");
    }
    if (!self.getOrThrow().equals(owner)) {
      throw new IllegalStateException(code + ": " + what + " belongs to '" + owner.getName()
          + "', not to the user this process runs as" + after);
    }
  }

  /** Refuses a directory whose identity is not the one that was checked or opened. */
  private static void requireSame(Object expectedKey, Object actualKey, Path directory,
                                  String code) {
    if (expectedKey != null && !expectedKey.equals(actualKey)) {
      throw new IllegalStateException(code + ": the key directory " + directory
          + " was replaced while it was being opened");
    }
  }

  /** Whether {@code permission} grants anything to group or others. */
  private static boolean beyondOwner(PosixFilePermission permission) {
    return switch (permission) {
      case OWNER_READ, OWNER_WRITE, OWNER_EXECUTE -> false;
      default -> true;
    };
  }

  /**
   * Opens {@code directory} as a {@link SecureDirectoryStream}.
   *
   * @return the stream, or {@code null} where the JDK offers none or the directory cannot be
   *         listed - the checks then run against the path
   */
  private static SecureDirectoryStream<Path> pin(Path directory, String code) {
    DirectoryStream<Path> stream;
    try {
      stream = Files.newDirectoryStream(directory);
    } catch (IOException | RuntimeException unavailable) {
      HasLogger.staticLogger().debug("{}: {} cannot be opened as a directory stream ({}); the"
          + " key files are checked through their path", code, directory,
          unavailable.getClass().getSimpleName());
      return null;
    }
    if (stream instanceof SecureDirectoryStream<Path> secure) {
      return secure;
    }
    close(stream);
    return null;
  }

  private static void close(DirectoryStream<Path> stream) {
    if (stream == null) {
      return;
    }
    try {
      stream.close();
    } catch (IOException ignored) {
      // nothing was read through it that could be lost
    }
  }

  /**
   * The principal files created by this process belong to — the approach of
   * {@code FileBootstrapTokenStore} (JS-SEC-130): resolved from {@code user.name}; where that
   * name has no entry in the user database (a container running under an arbitrary uid), the
   * owner of a probe file in the temporary directory is used instead, because a key directory
   * such as {@code /run/secrets} is usually read-only.
   *
   * @return the principal, or why it cannot be determined - the caller then refuses; the
   *         reason names the failures by their class, not by their message
   */
  private static Result<UserPrincipal, String> processUser(Path file) {
    String lookupFailure;
    try {
      return Result.success(file.getFileSystem().getUserPrincipalLookupService()
          .lookupPrincipalByName(System.getProperty("user.name")));
    } catch (IOException | RuntimeException lookupFailed) {
      // SP05: kept for the message instead of being swallowed; the probe comes next
      lookupFailure = lookupFailed.getClass().getSimpleName();
    }
    Path probe = null;
    try {
      probe = Files.createTempFile(".pepper-owner-", ".probe",
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      return Result.success(Files.getOwner(probe, LinkOption.NOFOLLOW_LINKS));
    } catch (IOException | RuntimeException probeFailed) {
      return Result.failure("the lookup of user.name failed with " + lookupFailure
          + ", the probe file in the temporary directory with "
          + probeFailed.getClass().getSimpleName());
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
