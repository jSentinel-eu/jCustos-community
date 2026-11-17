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

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Pepper keys from the secret-key entries of a JDK {@link KeyStore}: a PKCS12 file, or a
 * PKCS#11 token through the JDK's {@code SunPKCS11} provider. The key id is the alias.
 *
 * <pre>{@code
 * // PKCS12 file, for example generated with
 * //   keytool -genseckey -storetype PKCS12 -keystore pepper.p12 \
 * //           -alias pepper-2026 -keyalg HmacSHA256 -keysize 256
 * //   chmod 600 pepper.p12
 * PepperService pepper = KeyStorePepperService.fromPkcs12(Path.of("/etc/app/pepper.p12"), password)
 *     .activeAlias("pepper-2026")      // new hashes are peppered with this key
 *     .retiredAlias("pepper-2025")     // still verifies; needsRehash reports PEPPER_KEY_ROTATED
 *     .load();
 *
 * // PKCS#11 token: a key store the application has loaded (and logged into) itself
 * PepperService pepper = KeyStorePepperService.fromKeyStore(pkcs11KeyStore, null)
 *     .activeAlias("pepper-2026")
 *     .load();
 * }</pre>
 *
 * <p>Only the aliases that are named are loaded; other entries of the store are never read.
 * {@link Builder#load()} fails closed: it throws when a named alias is not in the store with
 * exactly this spelling, is not a secret-key entry, cannot be recovered with the password, is
 * not extractable or holds less than {@link PepperReference#MIN_KEY_BYTES} bytes — so an
 * application never starts with part of its keys. Aliases are compared character for
 * character with what {@link KeyStore#aliases()} lists, never through the store's
 * case-insensitive lookup (CWE-178, as {@code JdkKeyStoreKeyManagement} since JS-SEC-101);
 * PKCS12 stores its aliases in lower case, so use lower-case aliases.</p>
 *
 * <p>A PKCS12 file is read under the rules jCustos applies to the bootstrap token file
 * (JS-SEC-130) and storage directories (JS-SEC-136): it must be a regular file, not a symbolic
 * link, at most {@value #MAX_KEYSTORE_FILE_BYTES} bytes, and on POSIX it must belong to the
 * process user and grant nothing to group or others ({@code keytool} creates it with the
 * umask — restrict it to {@code 0600}).</p>
 *
 * <p>The key material is copied out of the store when it is loaded and held on the heap, as
 * copies that {@link #wipe()} zeroes; {@link #resolve(String)} hands out a fresh copy and
 * never touches the store. jCustos applies the pepper with HMAC-SHA-256 inside the JVM, so a
 * PKCS#11 key must be extractable ({@code CKA_SENSITIVE=false}, {@code CKA_EXTRACTABLE=true}):
 * the token then protects the key at rest, not in use. A key that does not leave the token
 * cannot be used through this class and is refused at load. Neither the key material nor a
 * password appears in a message, a log line or {@link #toString()}.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class KeyStorePepperService implements PepperService {

  /**
   * Largest PKCS12 file that is read: {@value} bytes. A store with a handful of secret keys
   * takes about half a kilobyte each.
   */
  public static final int MAX_KEYSTORE_FILE_BYTES = 1_048_576;

  /** Stable code that starts every load failure and log line of this source. */
  static final String CODE = "pepper/keystore-rejected";

  private static final String PKCS12 = "PKCS12";
  private static final String RAW_FORMAT = "RAW";

  private final String source;
  private final List<String> aliases;
  private final InMemoryPepperService keys;

  private KeyStorePepperService(String source, List<String> aliases, InMemoryPepperService keys) {
    this.source = source;
    this.aliases = List.copyOf(aliases);
    this.keys = keys;
  }

  /**
   * Starts the configuration of a source that loads the PKCS12 file at {@code file}. The
   * password opens the store and its secret-key entries, as {@code keytool} writes them.
   *
   * @param file     the PKCS12 file
   * @param password the store password; copied, and the copy is zeroed by
   *                 {@link Builder#load()}
   * @return a builder; nothing is read before {@link Builder#load()}
   */
  public static Builder fromPkcs12(Path file, char[] password) {
    Objects.requireNonNull(file, "file");
    Objects.requireNonNull(password, "password");
    return new Builder(file, null, password.clone());
  }

  /**
   * Starts the configuration of a source over a key store the application has loaded —
   * a PKCS#11 token, or a store of another type.
   *
   * @param keyStore      a loaded key store
   * @param entryPassword the password of the secret-key entries, or {@code null} when the
   *                      entries have none (a PKCS#11 token after its login); copied, and
   *                      the copy is zeroed by {@link Builder#load()}
   * @return a builder; no entry is read before {@link Builder#load()}
   */
  public static Builder fromKeyStore(KeyStore keyStore, char[] entryPassword) {
    Objects.requireNonNull(keyStore, "keyStore");
    return new Builder(null, keyStore, entryPassword == null ? null : entryPassword.clone());
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
   * @return the loaded aliases, the active one first
   */
  public Set<String> keyIds() {
    return new LinkedHashSet<>(aliases);
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
    return "KeyStorePepperService[source=" + source + ", activeKeyId="
        + keys.activeKeyId().orElse("<none>") + ", keyIds=" + aliases + "]";
  }

  /**
   * Names the aliases of a {@link KeyStorePepperService} and loads their keys.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final class Builder {

    private final Path file;
    private final KeyStore keyStore;
    private final char[] password;
    private String activeAlias;
    private final List<String> retiredAliases = new ArrayList<>();
    private boolean loaded;

    private Builder(Path file, KeyStore keyStore, char[] password) {
      this.file = file;
      this.keyStore = keyStore;
      this.password = password;
    }

    /**
     * The key new hashes are peppered with. Required.
     *
     * @throws IllegalArgumentException when the alias is not 1 to 64 characters from
     *                                  {@code [A-Za-z0-9._-]} or starts with a dot
     */
    public Builder activeAlias(String alias) {
      this.activeAlias = PepperSourceFiles.requireKeyId(alias, "alias");
      return this;
    }

    /**
     * A key that only verifies: hashes peppered with it keep verifying, and
     * {@code needsRehash} reports {@code PEPPER_KEY_ROTATED} for them. May be called more
     * than once.
     *
     * @throws IllegalArgumentException when the alias does not have the shape of
     *                                  {@link #activeAlias(String)}
     */
    public Builder retiredAlias(String alias) {
      retiredAliases.add(PepperSourceFiles.requireKeyId(alias, "alias"));
      return this;
    }

    /**
     * Opens the store (for a PKCS12 file) and copies the named keys out of it. The password
     * copy is zeroed afterwards, whatever the outcome; a builder loads once.
     *
     * @return the loaded service
     * @throws IllegalStateException when no active alias is set, an alias is named twice,
     *                               the file is refused or cannot be opened with the
     *                               password, or a named entry is missing, of another kind,
     *                               not extractable or too short; the message names the
     *                               alias, never key material or the password
     */
    public KeyStorePepperService load() {
      if (loaded) {
        throw new IllegalStateException(CODE + ": this builder has already loaded its keys");
      }
      loaded = true;
      KeyStore.PasswordProtection protection = null;
      try {
        if (activeAlias == null) {
          throw new IllegalStateException(CODE + ": no active alias was set");
        }
        List<String> ids = new ArrayList<>();
        ids.add(activeAlias);
        for (String retired : retiredAliases) {
          if (ids.contains(retired)) {
            throw new IllegalStateException(CODE + ": alias '" + retired + "' is named twice");
          }
          ids.add(retired);
        }
        String source = file != null ? file.toString() : keyStore.getType() + " key store";
        KeyStore store = file != null ? openPkcs12() : keyStore;
        protection = password == null ? null : new KeyStore.PasswordProtection(password);
        Set<String> listed = listedAliases(store, source);
        InMemoryPepperService.Builder keys = InMemoryPepperService.builder();
        for (String alias : ids) {
          byte[] key = secretKey(store, protection, alias, listed, source);
          try {
            keys.addKey(alias, key);
          } finally {
            Arrays.fill(key, (byte) 0);
          }
        }
        KeyStorePepperService service =
            new KeyStorePepperService(source, ids, keys.activeKeyId(activeAlias).build());
        HasLogger.staticLogger().info("pepper/keys-loaded: {} key(s) from {}, active key id {}",
            ids.size(), source, activeAlias);
        return service;
      } finally {
        if (password != null) {
          Arrays.fill(password, '\0');
        }
        destroy(protection);
      }
    }

    /** Clears the copy of the password that {@link KeyStore.PasswordProtection} keeps. */
    private static void destroy(KeyStore.PasswordProtection protection) {
      if (protection == null) {
        return;
      }
      try {
        protection.destroy();
      } catch (DestroyFailedException ignored) {
        // the JDK implementation does not fail; nothing else is left to clear
      }
    }

    private KeyStore openPkcs12() {
      byte[] content = PepperSourceFiles.readTrusted(file, MAX_KEYSTORE_FILE_BYTES, CODE);
      try {
        KeyStore store = KeyStore.getInstance(PKCS12);
        store.load(new ByteArrayInputStream(content), password);
        return store;
      } catch (IOException | GeneralSecurityException unreadable) {
        // the JDK's messages name the failed check ("integrity check failed"), not key data
        throw new IllegalStateException(CODE + ": " + file + " cannot be opened as a PKCS12"
            + " key store with the given password (" + unreadable.getMessage() + ")",
            unreadable);
      } finally {
        Arrays.fill(content, (byte) 0);
      }
    }

    // JS-SEC-101 (CWE-178): KeyStore's own lookups ignore case; only an alias the store lists
    // with exactly this spelling counts.
    private static Set<String> listedAliases(KeyStore store, String source) {
      try {
        Set<String> listed = new LinkedHashSet<>();
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
          listed.add(aliases.nextElement());
        }
        return listed;
      } catch (KeyStoreException notLoaded) {
        throw new IllegalStateException(CODE + ": the aliases of " + source
            + " cannot be listed; is the key store loaded?", notLoaded);
      }
    }

    /** @return a copy of the key material under {@code alias}; the caller zeroes it */
    private static byte[] secretKey(KeyStore store, KeyStore.ProtectionParameter protection,
                                    String alias, Set<String> listed, String source) {
      if (!listed.contains(alias)) {
        throw new IllegalStateException(CODE + ": alias '" + alias + "' is not in " + source
            + " with exactly this spelling (PKCS12 stores aliases in lower case)");
      }
      KeyStore.Entry entry;
      try {
        if (!store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
          throw new IllegalStateException(CODE + ": alias '" + alias + "' in " + source
              + " is not a secret-key entry");
        }
        entry = store.getEntry(alias, protection);
      } catch (GeneralSecurityException unrecoverable) {
        throw new IllegalStateException(CODE + ": the entry '" + alias + "' in " + source
            + " cannot be read (" + unrecoverable.getClass().getSimpleName()
            + "); check the entry password", unrecoverable);
      }
      if (!(entry instanceof KeyStore.SecretKeyEntry secretEntry)) {
        throw new IllegalStateException(CODE + ": alias '" + alias + "' in " + source
            + " is not a secret-key entry");
      }
      SecretKey secretKey = secretEntry.getSecretKey();
      byte[] encoded = RAW_FORMAT.equalsIgnoreCase(secretKey.getFormat())
          ? secretKey.getEncoded()
          : null;
      if (encoded == null) {
        throw new IllegalStateException(CODE + ": the key '" + alias + "' in " + source
            + " is not extractable; jCustos applies the pepper with HMAC-SHA-256 in the JVM"
            + " and needs the key material");
      }
      if (encoded.length < PepperReference.MIN_KEY_BYTES) {
        int length = encoded.length;
        Arrays.fill(encoded, (byte) 0);
        throw new IllegalStateException(CODE + ": the key '" + alias + "' in " + source
            + " has " + length + " bytes; a pepper key needs at least "
            + PepperReference.MIN_KEY_BYTES);
      }
      return encoded;
    }
  }
}
