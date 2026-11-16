package eu.jsentinel.jcustos.events.keys;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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

import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the real PKCS12 reference implementation against a keytool-built
 * Ed25519 key store committed under {@code src/test/resources}. No mocks.
 */
@DisplayName("JdkKeyStoreKeyManagement (real PKCS12)")
class JdkKeyStoreKeyManagementTest {

  private static final KeyId ALIAS = KeyId.of("eventbus-2026");
  private final SignatureAlgorithm algorithm = new Ed25519SignatureAlgorithm();

  private JdkKeyStoreKeyManagement load() throws Exception {
    Path p12 = Path.of(getClass().getResource("/test-eventbus.p12").toURI());
    return JdkKeyStoreKeyManagement.loadPkcs12(
        p12, "changeit".toCharArray(), "changeit".toCharArray(), ALIAS, algorithm);
  }

  @Test
  @DisplayName("the current alias signs and verifies end-to-end")
  void signAndVerifyEndToEnd() throws Exception {
    JdkKeyStoreKeyManagement km = load();
    assertEquals(ALIAS, km.currentKeyId());
    byte[] data = "envelope base".getBytes(StandardCharsets.UTF_8);
    byte[] sig = km.currentAlgorithm().sign(data, km.currentSigningKey());
    assertTrue(km.currentAlgorithm().verify(data, sig,
        km.resolveVerificationKey(ALIAS).orElseThrow()));
  }

  @Test
  @DisplayName("the current alias is ACTIVE; an unknown alias is UNKNOWN")
  void keyStatuses() throws Exception {
    JdkKeyStoreKeyManagement km = load();
    assertEquals(KeyStatus.ACTIVE, km.keyStatus(ALIAS));
    assertEquals(KeyStatus.UNKNOWN, km.keyStatus(KeyId.of("does-not-exist")));
    assertTrue(km.resolveVerificationKey(KeyId.of("does-not-exist")).isEmpty());
  }

  @Test
  @DisplayName("an alias spelled in another case is unknown and cannot sign")
  void aliasesMatchExactly() throws Exception {
    KeyId shouted = KeyId.of("EVENTBUS-2026");
    JdkKeyStoreKeyManagement km = load();

    assertEquals(KeyStatus.UNKNOWN, km.keyStatus(shouted),
        "PKCS12 itself finds eventbus-2026 under EVENTBUS-2026");
    assertTrue(km.resolveVerificationKey(shouted).isEmpty());

    Path p12 = Path.of(getClass().getResource("/test-eventbus.p12").toURI());
    JdkKeyStoreKeyManagement respelled = JdkKeyStoreKeyManagement.loadPkcs12(
        p12, "changeit".toCharArray(), "changeit".toCharArray(), shouted, algorithm);
    assertThrows(KeyAccessException.class, respelled::currentSigningKey,
        "a producer must not sign under a key id no verifier can resolve");
  }

  @Test
  @DisplayName("a wrong store password fails fast with KeyAccessException")
  void wrongPasswordFails() {
    Path p12;
    try {
      p12 = Path.of(getClass().getResource("/test-eventbus.p12").toURI());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    assertThrows(KeyAccessException.class, () -> JdkKeyStoreKeyManagement.loadPkcs12(
        p12, "wrong".toCharArray(), "wrong".toCharArray(), ALIAS, algorithm));
  }
}
