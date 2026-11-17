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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SA27 follow-up (JS-SEC-127, CWE-532): the string forms of the mTLS configuration and of an endpoint answer carry no secret. */
@DisplayName("JS-SEC-127 — MutualTlsClientConfig and OAuth2FormPost.Outcome mask their secrets")
class SecretRecordToStringTest {

  @Test
  @DisplayName("the key-store password is masked, the alias stays readable")
  void mutualTlsClientConfig() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);
    String text = new MutualTlsClientConfig(keyStore, "store-pass-9".toCharArray(), "client").toString();
    assertFalse(text.contains("store-pass-9"), text);
    assertTrue(text.contains("alias=client"), text);
  }

  @Test
  @DisplayName("an endpoint answer shows status and length, not the body with the tokens")
  void outcome() {
    String body = "{\"access_token\":\"at-123\",\"refresh_token\":\"rt-456\"}";
    String text = new OAuth2FormPost.Outcome(200, body).toString();
    assertFalse(text.contains("at-123"), text);
    assertFalse(text.contains("rt-456"), text);
    assertTrue(text.contains("status=200"), text);
    assertTrue(text.contains("<" + body.length() + " chars>"), text);
  }
}
