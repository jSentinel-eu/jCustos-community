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
package eu.jsentinel.jcustos.dpop;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SA27 follow-up (JS-SEC-127, CWE-532): the string form of a DPoP validation request carries neither proof nor token. */
@DisplayName("JS-SEC-127 — DpopValidationRequest masks proof and access token")
class SecretRecordToStringTest {

  @Test
  @DisplayName("proof and access token are masked; method, URI and thumbprint stay readable")
  void dpopValidationRequest() {
    String text = DpopValidationRequest.boundTo("eyJhbGciOi.proof.sig", "POST",
        URI.create("https://rs.example.org/orders"), "at-secret-1",
        new JwkThumbprint("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")).toString();
    assertFalse(text.contains("eyJhbGciOi.proof.sig"), text);
    assertFalse(text.contains("at-secret-1"), text);
    assertTrue(text.contains("httpMethod=POST"), text);
    assertTrue(text.contains("https://rs.example.org/orders"), text);
    assertTrue(text.contains("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"), text);
  }
}
