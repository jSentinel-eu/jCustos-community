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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link KeyStorePepperService}: secret-key entries of a JDK key store, alias = key id. The
 * PKCS12 stores are generated per test in a temporary directory from {@link SecureRandom}
 * keys; no key material is committed. The non-extractable token key is a hand-written
 * {@link KeyStoreSpi}, standing in for a PKCS#11 token.
 */
@DisplayName("KeyStorePepperService - PKCS12 and token key stores")
class KeyStorePepperServiceTest {

  private static final SecureRandom RANDOM = new SecureRandom();
  /** Synthetic password of the generated test stores. */
  private static final String STORE_PASSWORD = "synthetic-store-password-1";

  @TempDir
  Path dir;

  private static byte[] key(int length) {
    byte[] key = new byte[length];
    RANDOM.nextBytes(key);
    return key;
  }

  private static KeyStore pkcs12(Map<String, byte[]> keysByAlias) throws GeneralSecurityException,
      IOException {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    for (Map.Entry<String, byte[]> entry : keysByAlias.entrySet()) {
      store.setEntry(entry.getKey(),
          new KeyStore.SecretKeyEntry(new SecretKeySpec(entry.getValue(), "HmacSHA256")),
          new KeyStore.PasswordProtection(STORE_PASSWORD.toCharArray()));
    }
    return store;
  }

  /** Writes a PKCS12 file the way an operator provisions it: keytool output, chmod 600. */
  private Path pkcs12File(String name, Map<String, byte[]> keysByAlias, String permissions)
      throws GeneralSecurityException, IOException {
    Path file = dir.resolve(name);
    try (OutputStream out = Files.newOutputStream(file)) {
      pkcs12(keysByAlias).store(out, STORE_PASSWORD.toCharArray());
    }
    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions));
    }
    return file;
  }

  private static Map<String, byte[]> keys(Object... aliasAndKey) {
    Map<String, byte[]> map = new LinkedHashMap<>();
    for (int i = 0; i < aliasAndKey.length; i += 2) {
      map.put((String) aliasAndKey[i], (byte[]) aliasAndKey[i + 1]);
    }
    return map;
  }

  @Test
  @DisplayName("PKCS12: loads the named aliases; the active one peppers, a retired one resolves")
  void pkcs12ActiveAndRetired() throws Exception {
    byte[] active = key(32);
    byte[] retired = key(32);
    byte[] unrelated = key(16);
    Path file = pkcs12File("pepper.p12",
        keys("pepper-2026", active, "pepper-2025", retired, "unrelated-aes", unrelated),
        "rw-------");

    KeyStorePepperService service =
        KeyStorePepperService.fromPkcs12(file, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2026")
            .retiredAlias("pepper-2025")
            .load();

    assertEquals(Optional.of("pepper-2026"), service.activeKeyId());
    assertArrayEquals(active, service.resolve("pepper-2026").orElseThrow());
    assertArrayEquals(retired, service.resolve("pepper-2025").orElseThrow());
    assertEquals(Optional.empty(), service.resolve("unrelated-aes"),
        "an entry that is not named is never loaded, not even a short one");
    assertEquals(List.of("pepper-2026", "pepper-2025"), List.copyOf(service.keyIds()));
    byte[] handedOut = service.resolve("pepper-2026").orElseThrow();
    handedOut[0] ^= 0x55;
    assertArrayEquals(active, service.resolve("pepper-2026").orElseThrow(),
        "resolve hands out a copy");
    assertFalse(service.toString().contains(STORE_PASSWORD), service.toString());

    service.wipe();
    assertEquals(Optional.empty(), service.resolve("pepper-2026"));
  }

  @Test
  @DisplayName("an already loaded key store (the PKCS#11 path) is read the same way")
  void loadedKeyStore() throws Exception {
    byte[] active = key(40);
    KeyStore store = pkcs12(keys("pepper-2026", active));

    KeyStorePepperService service =
        KeyStorePepperService.fromKeyStore(store, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2026")
            .load();

    assertArrayEquals(active, service.resolve("pepper-2026").orElseThrow());
  }

  @Test
  @DisplayName("a short secret key is refused at load")
  void shortKeyIsRefused() throws Exception {
    Path file = pkcs12File("pepper.p12", keys("pepper-2026", key(16)), "rw-------");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(file, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2026").load());

    assertTrue(refused.getMessage().startsWith("pepper/keystore-rejected: "), refused.getMessage());
    assertTrue(refused.getMessage().contains("16 bytes"), refused.getMessage());
  }

  @Test
  @DisplayName("an alias is matched exactly; PKCS12's lower-cased alias does not answer to another spelling")
  void aliasIsMatchedExactly() throws Exception {
    Path file = pkcs12File("pepper.p12", keys("Pepper-2026", key(32)), "rw-------");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(file, STORE_PASSWORD.toCharArray())
            .activeAlias("Pepper-2026").load());
    assertTrue(refused.getMessage().contains("exactly this spelling"), refused.getMessage());

    KeyStorePepperService lowerCase = KeyStorePepperService.fromPkcs12(file,
        STORE_PASSWORD.toCharArray()).activeAlias("pepper-2026").load();
    assertTrue(lowerCase.resolve("pepper-2026").isPresent());
  }

  @Test
  @DisplayName("a missing alias, a missing retired alias and a wrong password are refused")
  void missingAliasAndWrongPassword() throws Exception {
    Path file = pkcs12File("pepper.p12", keys("pepper-2026", key(32)), "rw-------");

    assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(file, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2027").load());
    IllegalStateException retiredMissing = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(file, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2026").retiredAlias("pepper-2025").load());
    assertTrue(retiredMissing.getMessage().contains("pepper-2025"), retiredMissing.getMessage());

    String wrong = "not-the-store-password";
    IllegalStateException wrongPassword = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(file, wrong.toCharArray())
            .activeAlias("pepper-2026").load());
    assertTrue(wrongPassword.getMessage().contains("cannot be opened"), wrongPassword.getMessage());
    assertFalse(wrongPassword.getMessage().contains(wrong), "the password never appears");
    assertFalse(wrongPassword.getMessage().contains(STORE_PASSWORD));
  }

  @Test
  @DisplayName("a PKCS12 file readable by group or others, or a symbolic link to one, is refused")
  void pkcs12FileChecks() throws Exception {
    assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "owner and permission checks need POSIX attributes");
    Path open = pkcs12File("open.p12", keys("pepper-2026", key(32)), "rw-r--r--");
    IllegalStateException wide = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(open, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2026").load());
    assertTrue(wide.getMessage().contains("accessible beyond its owner"), wide.getMessage());

    Path real = pkcs12File("real.p12", keys("pepper-2026", key(32)), "rw-------");
    Path link = Files.createSymbolicLink(dir.resolve("pepper.p12"), real);
    IllegalStateException linked = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromPkcs12(link, STORE_PASSWORD.toCharArray())
            .activeAlias("pepper-2026").load());
    assertTrue(linked.getMessage().contains("symbolic link"), linked.getMessage());
  }

  @Test
  @DisplayName("a token key that does not leave the token is refused, naming why")
  void nonExtractableKeyIsRefused() throws Exception {
    KeyStore token = new KeyStore(new SealedTokenSpi("pepper-2026"),
        new Provider("SyntheticToken", "1.0", "test token") { }, "SYNTHETIC-TOKEN") { };
    token.load(null, null);

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> KeyStorePepperService.fromKeyStore(token, null).activeAlias("pepper-2026").load());

    assertTrue(refused.getMessage().contains("not extractable"), refused.getMessage());
  }

  @Test
  @DisplayName("aliases with an unusable shape, a missing active alias and a second load are refused")
  void configurationErrors() throws Exception {
    Path file = pkcs12File("pepper.p12", keys("pepper-2026", key(32)), "rw-------");
    KeyStorePepperService.Builder builder =
        KeyStorePepperService.fromPkcs12(file, STORE_PASSWORD.toCharArray());
    for (String bad : List.of("", "a b", "a$b", ".x", "../x")) {
      assertThrows(IllegalArgumentException.class, () -> builder.activeAlias(bad), bad);
    }
    assertThrows(IllegalStateException.class, builder::load, "no active alias");
    assertThrows(IllegalStateException.class, builder::load, "a builder loads once");

    KeyStorePepperService.Builder twice = KeyStorePepperService.fromPkcs12(file,
        STORE_PASSWORD.toCharArray()).activeAlias("pepper-2026").retiredAlias("pepper-2026");
    assertThrows(IllegalStateException.class, twice::load);
  }

  /** One secret-key entry whose key material stays in the "token": getEncoded() is null. */
  private static final class SealedTokenSpi extends KeyStoreSpi {

    private final String alias;

    SealedTokenSpi(String alias) {
      this.alias = alias;
    }

    private static final class SealedKey implements SecretKey {
      @Override public String getAlgorithm() {
        return "HmacSHA256";
      }

      @Override public String getFormat() {
        return null;
      }

      @Override public byte[] getEncoded() {
        return null;
      }
    }

    @Override public Key engineGetKey(String a, char[] password) {
      return alias.equals(a) ? new SealedKey() : null;
    }

    @Override public KeyStore.Entry engineGetEntry(String a, KeyStore.ProtectionParameter p) {
      return alias.equals(a) ? new KeyStore.SecretKeyEntry(new SealedKey()) : null;
    }

    @Override public boolean engineEntryInstanceOf(String a,
                                                   Class<? extends KeyStore.Entry> type) {
      return alias.equals(a) && type == KeyStore.SecretKeyEntry.class;
    }

    @Override public Certificate[] engineGetCertificateChain(String a) {
      return null;
    }

    @Override public Certificate engineGetCertificate(String a) {
      return null;
    }

    @Override public Date engineGetCreationDate(String a) {
      return null;
    }

    @Override public void engineSetKeyEntry(String a, Key key, char[] password,
                                            Certificate[] chain) {
      throw new UnsupportedOperationException();
    }

    @Override public void engineSetKeyEntry(String a, byte[] key, Certificate[] chain) {
      throw new UnsupportedOperationException();
    }

    @Override public void engineSetCertificateEntry(String a, Certificate cert) {
      throw new UnsupportedOperationException();
    }

    @Override public void engineDeleteEntry(String a) {
      throw new UnsupportedOperationException();
    }

    @Override public Enumeration<String> engineAliases() {
      return Collections.enumeration(List.of(alias));
    }

    @Override public boolean engineContainsAlias(String a) {
      return alias.equals(a);
    }

    @Override public int engineSize() {
      return 1;
    }

    @Override public boolean engineIsKeyEntry(String a) {
      return alias.equals(a);
    }

    @Override public boolean engineIsCertificateEntry(String a) {
      return false;
    }

    @Override public String engineGetCertificateAlias(Certificate cert) {
      return null;
    }

    @Override public void engineStore(OutputStream stream, char[] password) {
      throw new UnsupportedOperationException();
    }

    @Override public void engineLoad(InputStream stream, char[] password) {
      // nothing to load: the entry is fixed
    }
  }
}
