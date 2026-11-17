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
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Pepper keys from files: one file per key id, named like the key id, holding the key in
 * Base64 — the shape of container secrets such as {@code /run/secrets/pepper-2026}.
 *
 * <pre>{@code
 * PepperService pepper = FilePepperService.fromDirectory(Path.of("/run/secrets"))
 *     .activeKeyId("pepper-2026")      // new hashes are peppered with this key
 *     .retiredKeyId("pepper-2025")     // still verifies; needsRehash reports PEPPER_KEY_ROTATED
 *     .load();
 * }</pre>
 *
 * <p>Only the key ids that are named are loaded; other files in the directory — the other
 * secrets of a container, for instance — are never opened. {@link Builder#load()} reads every
 * named file once and fails closed: it throws when one of them is missing, refused or holds
 * less than {@link PepperReference#MIN_KEY_BYTES} bytes, so an application never starts with
 * part of its keys. A file is refused when it is a symbolic link, is not a regular file, is
 * larger than {@value #MAX_KEY_FILE_BYTES} bytes, or — on POSIX — belongs to another user than
 * the one the process runs as or grants any access to group or others (provision it with
 * {@code 0400} or {@code 0600}), or - where the filesystem reports it - has a second name
 * (a hard link). The directory must not be a symbolic link either, must not be writable by
 * group or others unless its sticky bit is set, and must belong to the process user or the
 * superuser ({@code /run/secrets} with {@code 0755}, owned by root, passes). Where the JDK
 * offers a {@link java.nio.file.SecureDirectoryStream} the directory is opened once and the
 * key files are checked and read relative to it. These are the rules jCustos applies to the
 * bootstrap token file (JS-SEC-130) and to storage directories (JS-SEC-136). On a filesystem
 * without POSIX attributes owner and permissions cannot be checked (JS-SEC-016); that is
 * logged as a warning.</p>
 *
 * <p>The content is standard Base64 ({@code A-Z a-z 0-9 + /}, padded); white space and line
 * breaks anywhere in the file are ignored, so {@code openssl rand -base64 32 > pepper-2026}
 * produces a valid file. The keys are held on the heap after loading, as copies that
 * {@link #wipe()} zeroes; {@link #resolve(String)} hands out a fresh copy and never touches
 * the filesystem. To rotate, add the new file, make it active, name the previous key as
 * retired and restart; remove a retired key id once no stored hash names it.</p>
 *
 * <p>Key ids are 1 to 64 characters from {@code [A-Za-z0-9._-]} and do not start with a
 * dot. Neither the key material nor the content of a key file appears in a message, a log
 * line or {@link #toString()}.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class FilePepperService implements PepperService {

  /**
   * Largest key file that is read: {@value} bytes, room for a key of about 3 000 bytes in
   * Base64. A 32-byte key takes 44 characters.
   */
  public static final int MAX_KEY_FILE_BYTES = 4_096;

  /** Stable code that starts every load failure and log line of this source. */
  static final String CODE = "pepper/key-file-rejected";

  private final Path directory;
  private final List<String> keyIds;
  private final InMemoryPepperService keys;

  private FilePepperService(Path directory, List<String> keyIds, InMemoryPepperService keys) {
    this.directory = directory;
    this.keyIds = List.copyOf(keyIds);
    this.keys = keys;
  }

  /**
   * Starts the configuration of a source that reads its key files from {@code directory}.
   *
   * @param directory the directory that holds one file per key id
   * @return a builder; nothing is read before {@link Builder#load()}
   */
  public static Builder fromDirectory(Path directory) {
    return new Builder(Objects.requireNonNull(directory, "directory"));
  }

  @Override
  public Optional<String> activeKeyId() {
    return keys.activeKeyId();
  }

  @Override
  public Optional<byte[]> resolve(String keyId) {
    return keys.resolve(keyId);
  }

  /**
   * @return the loaded key ids, the active one first
   */
  public Set<String> keyIds() {
    return new LinkedHashSet<>(keyIds);
  }

  /**
   * Zeroes every held key. Afterwards the service resolves no key id, and hashing through a
   * pipeline that uses it fails.
   */
  public void wipe() {
    keys.wipe();
  }

  @Override
  public String toString() {
    return "FilePepperService[directory=" + directory + ", activeKeyId="
        + keys.activeKeyId().orElse("<none>") + ", keyIds=" + keyIds + "]";
  }

  /**
   * Decodes the content of a key file. White space is dropped first, so a trailing newline
   * or wrapped lines do not matter. Neither the content nor the decoder's message — which
   * names the offending character — goes into the exception.
   */
  private static byte[] decode(byte[] content, Path file) {
    byte[] compact = new byte[content.length];
    int length = 0;
    for (byte b : content) {
      if (b != ' ' && b != '\t' && b != '\r' && b != '\n') {
        compact[length++] = b;
      }
    }
    byte[] base64 = Arrays.copyOf(compact, length);
    try {
      if (base64.length == 0) {
        throw new IllegalStateException(CODE + ": " + file + " is empty");
      }
      try {
        return Base64.getDecoder().decode(base64);
      } catch (IllegalArgumentException notBase64) {
        throw new IllegalStateException(CODE + ": " + file + " does not hold a key in standard"
            + " Base64");
      }
    } finally {
      Arrays.fill(compact, (byte) 0);
      Arrays.fill(base64, (byte) 0);
    }
  }

  /**
   * Names the key ids of a {@link FilePepperService} and loads their files.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final class Builder {

    private final Path directory;
    private String activeKeyId;
    private final List<String> retiredKeyIds = new ArrayList<>();

    private Builder(Path directory) {
      this.directory = directory;
    }

    /**
     * The key new hashes are peppered with; its file is {@code <directory>/<keyId>}.
     * Required.
     *
     * @throws IllegalArgumentException when the key id does not have the documented shape
     */
    public Builder activeKeyId(String keyId) {
      this.activeKeyId = PepperSourceFiles.requireKeyId(keyId, "key id");
      return this;
    }

    /**
     * A key that only verifies: hashes peppered with it keep verifying, and
     * {@code needsRehash} reports {@code PEPPER_KEY_ROTATED} for them. May be called more
     * than once.
     *
     * @throws IllegalArgumentException when the key id does not have the documented shape
     */
    public Builder retiredKeyId(String keyId) {
      retiredKeyIds.add(PepperSourceFiles.requireKeyId(keyId, "key id"));
      return this;
    }

    /**
     * Reads and checks every named key file.
     *
     * @return the loaded service
     * @throws IllegalStateException when no active key id is set, a key id is named twice,
     *                               the directory is refused, or a key file is missing,
     *                               refused, not Base64 or shorter than
     *                               {@link PepperReference#MIN_KEY_BYTES} bytes once decoded;
     *                               the message names the file, never its content. The keys
     *                               read before the failure are zeroed.
     */
    public FilePepperService load() {
      return load(InMemoryPepperService.builder());
    }

    /** Test seam: loads into {@code keys}, which is wiped when the load fails. */
    FilePepperService load(InMemoryPepperService.Builder keys) {
      boolean built = false;
      try {
        FilePepperService service = loadInto(keys);
        built = true;
        return service;
      } finally {
        if (!built) {
          // the keys copied in before the failure must not stay on the heap
          keys.wipe();
        }
      }
    }

    private FilePepperService loadInto(InMemoryPepperService.Builder keys) {
      if (activeKeyId == null) {
        throw new IllegalStateException(CODE + ": no active key id was set");
      }
      List<String> ids = new ArrayList<>();
      ids.add(activeKeyId);
      for (String retired : retiredKeyIds) {
        if (ids.contains(retired)) {
          throw new IllegalStateException(CODE + ": key id '" + retired + "' is named twice");
        }
        ids.add(retired);
      }
      try (PepperSourceFiles.KeyDirectory keyDirectory =
               PepperSourceFiles.openDirectory(directory, CODE)) {
        for (String keyId : ids) {
          Path file = directory.resolve(keyId);
          byte[] content = keyDirectory.read(keyId, MAX_KEY_FILE_BYTES);
          byte[] key = null;
          try {
            key = decode(content, file);
            if (key.length < PepperReference.MIN_KEY_BYTES) {
              throw new IllegalStateException(CODE + ": " + file + " holds a key of "
                  + key.length + " bytes; a pepper key needs at least "
                  + PepperReference.MIN_KEY_BYTES);
            }
            keys.addKey(keyId, key);
          } finally {
            Arrays.fill(content, (byte) 0);
            if (key != null) {
              Arrays.fill(key, (byte) 0);
            }
          }
        }
      }
      FilePepperService service =
          new FilePepperService(directory, ids, keys.activeKeyId(activeKeyId).build());
      HasLogger.staticLogger().info("pepper/keys-loaded: {} key(s) from {}, active key id {}",
          ids.size(), directory, activeKeyId);
      return service;
    }
  }
}
