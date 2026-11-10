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
package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
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

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.jwt.api.JoseLimits;
import eu.jsentinel.jcustos.jwt.api.JweAlgorithmAllowList;
import eu.jsentinel.jcustos.jwt.api.JweDecoder;
import eu.jsentinel.jcustos.jwt.api.JweDecodingError;

import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Objects;

/**
 * Nimbus-backed {@link JweDecoder} (V00.79, RFC 7516). {@code final}, composition. It
 * parses the five-segment JWE, enforces the {@link JweAlgorithmAllowList} on the
 * {@code alg}/{@code enc} header <em>before</em> decryption (so {@code RSA1_5} / {@code dir}
 * downgrades are rejected without touching the ciphertext), then decrypts with an
 * {@link RSADecrypter} and returns the inner compact JWS. Authentication-tag failures
 * (wrong key, tampered ciphertext) surface as {@link JweDecodingError.DecryptionFailed}.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public final class NimbusJweDecoder implements JweDecoder {

  private final JweAlgorithmAllowList allowList;

  public NimbusJweDecoder(JweAlgorithmAllowList allowList) {
    this.allowList = Objects.requireNonNull(allowList, "allowList");
  }

  @Override
  public Result<String, JweDecodingError> decode(String jweCompact, PrivateKey decryptionKey) {
    Objects.requireNonNull(decryptionKey, "decryptionKey");
    if (jweCompact == null || jweCompact.isBlank()) {
      return Result.failure(new JweDecodingError.NotJwe("compact JWE is blank"));
    }
    // JS-SEC-053: shared JOSE compact-form ceiling (was a private MAX_JWE_BYTES).
    if (jweCompact.length() > JoseLimits.MAX_COMPACT_BYTES) {
      return Result.failure(new JweDecodingError.Malformed("compact JWE exceeds the size cap"));
    }
    if (countSegments(jweCompact) != 5) {
      return Result.failure(new JweDecodingError.NotJwe("compact form is not a five-segment JWE"));
    }

    JWEObject jwe;
    try {
      jwe = JWEObject.parse(jweCompact);
    } catch (ParseException e) {
      return Result.failure(new JweDecodingError.Malformed("JWE could not be parsed"));
    }

    JWEHeader header = jwe.getHeader();
    // Reject any compression: Nimbus honours a header zip=DEF on decrypt and inflates the
    // plaintext, so an attacker holding the recipient's public key could mint a valid
    // RSA-OAEP-256 + GCM JWE whose deflated payload inflates to a memory bomb.
    if (header.getCompressionAlgorithm() != null) {
      return Result.failure(new JweDecodingError.UnsupportedAlgorithm("compression (zip) is not permitted"));
    }
    String alg = header.getAlgorithm() == null ? "" : header.getAlgorithm().getName();
    if (!allowList.allowsKeyManagement(alg)) {
      return Result.failure(new JweDecodingError.UnsupportedAlgorithm("alg not on the allow-list"));
    }
    String enc = header.getEncryptionMethod() == null ? "" : header.getEncryptionMethod().getName();
    if (!allowList.allowsContentEncryption(enc)) {
      return Result.failure(new JweDecodingError.UnsupportedEncryption("enc not on the allow-list"));
    }

    try {
      jwe.decrypt(new RSADecrypter(decryptionKey));
    } catch (Exception e) {
      return Result.failure(new JweDecodingError.DecryptionFailed("decryption or tag verification failed"));
    }
    return Result.success(jwe.getPayload().toString());
  }

  private static int countSegments(String compact) {
    int dots = 0;
    for (int i = 0; i < compact.length(); i++) {
      if (compact.charAt(i) == '.') {
        dots++;
      }
    }
    return dots + 1;
  }
}
