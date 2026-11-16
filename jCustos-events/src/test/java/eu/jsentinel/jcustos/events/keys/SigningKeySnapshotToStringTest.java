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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SA27 follow-up (JS-SEC-127, CWE-532): the string form of a signing-key snapshot has no key material. */
@DisplayName("JS-SEC-127 — SigningKeySnapshot masks the private key")
class SigningKeySnapshotToStringTest {

  @Test
  @DisplayName("neither the key's own description nor its encoding appears, key id and algorithm do")
  void privateKeyIsMasked() throws Exception {
    PrivateKey key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPrivate();
    String text = new SigningKeySnapshot(KeyId.of("k-1"), new Ed25519SignatureAlgorithm(), key).toString();

    assertFalse(text.contains(key.toString()), text);
    assertFalse(text.contains(Base64.getEncoder().encodeToString(key.getEncoded())), text);
    assertTrue(text.contains("k-1"), text);
    assertTrue(text.contains("privateKey=***"), text);
  }
}
