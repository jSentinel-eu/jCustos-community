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

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.jwt.api.JoseLimits;
import eu.jsentinel.jcustos.jwt.api.JweDecoder;
import eu.jsentinel.jcustos.jwt.api.JweDecodingError;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * A {@link JwtValidator} decorator that transparently unwraps encrypted JWTs (V00.79,
 * RFC 7516). A five-segment JWE is decrypted via the composed {@link JweDecoder} and the
 * resulting inner compact JWS is handed to the wrapped validator; a three-segment JWS is
 * passed straight through. Composition, not inheritance — the wrapped
 * {@code NimbusJwtValidator} is untouched and keeps doing the full signature/claims work.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public final class JweUnwrappingJwtValidator implements JwtValidator {

  private final JwtValidator delegate;
  private final JweDecoder jweDecoder;
  private final PrivateKey decryptionKey;

  public JweUnwrappingJwtValidator(JwtValidator delegate, JweDecoder jweDecoder, PrivateKey decryptionKey) {
    this.delegate = Objects.requireNonNull(delegate, "delegate");
    this.jweDecoder = Objects.requireNonNull(jweDecoder, "jweDecoder");
    this.decryptionKey = Objects.requireNonNull(decryptionKey, "decryptionKey");
  }

  @Override
  public Result<ValidatedJwt, JwtValidationError> validate(String compactJwt) {
    if (compactJwt == null || compactJwt.isBlank()) {
      return Result.failure(new JwtValidationError.MalformedJwt("compact JWT is blank"));
    }
    // JS-SEC-053 (CWE-770): bound the input here too so the pre-JWE branch (delegate.validate) and
    // the JWE decode below are both capped at the shared ceiling before any base64/parse work.
    if (compactJwt.length() > JoseLimits.MAX_COMPACT_BYTES) {
      return Result.failure(new JwtValidationError.MalformedJwt("compact JWT exceeds the size cap"));
    }
    if (countSegments(compactJwt) != 5) {
      return delegate.validate(compactJwt);
    }
    Result<String, JweDecodingError> decrypted = jweDecoder.decode(compactJwt, decryptionKey);
    return decrypted.fold(
        inner -> delegate.validate(inner),
        error -> Result.failure(toJwtError(error)));
  }

  private static JwtValidationError toJwtError(JweDecodingError error) {
    return switch (error) {
      case JweDecodingError.UnsupportedAlgorithm a ->
          new JwtValidationError.UnsupportedAlgorithm(a.code(), a.message());
      case JweDecodingError.UnsupportedEncryption e ->
          new JwtValidationError.UnsupportedAlgorithm(e.code(), e.message());
      default -> new JwtValidationError.MalformedJwt(error.code() + ": " + error.message());
    };
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
