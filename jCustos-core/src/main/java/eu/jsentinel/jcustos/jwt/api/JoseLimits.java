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
package eu.jsentinel.jcustos.jwt.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * The single home of the size and key-strength bounds every JOSE parser and verifier of
 * jCustos applies (CWE-770, CWE-326).
 *
 * <p>JS-SEC-053 introduced the compact-size ceiling inside {@code jCustos-jwt}; the DPoP proof
 * parser of {@code jCustos-dpop} lived in another module and therefore never saw it (JS-SEC-148).
 * JS-SEC-029 introduced the RSA modulus floor for DPoP proof keys only; keys loaded from a JWKS
 * were never checked (JS-SEC-149). The constants live here, in the core API, so that every module
 * shares one value instead of a copy that drifts.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class JoseLimits {

  /**
   * Maximum accepted length of a JOSE compact serialisation (JWS, JWE or DPoP proof). A signed
   * or encrypted JWT is at most a few tens of kilobytes; 100 kB sits far above any legitimate
   * token.
   */
  public static final int MAX_COMPACT_BYTES = 100_000;

  /** Smallest RSA modulus, in bits, accepted for signature verification (NIST SP 800-131A). */
  public static final int MIN_RSA_MODULUS_BITS = 2048;

  /**
   * Largest RSA modulus, in bits, accepted from an unauthenticated party (a DPoP proof key). A
   * larger modulus only amplifies the verification cost.
   */
  public static final int MAX_RSA_MODULUS_BITS = 8192;

  /** Maximum accepted length of a {@code jti} that is recorded for replay protection. */
  public static final int MAX_JTI_CHARS = 128;

  private JoseLimits() {
  }

  /**
   * Counts the dot-separated segments of a JOSE compact serialisation without splitting it: three
   * for a JWS, five for a JWE (RFC 7515 §7.1, RFC 7516 §7.1). The parsers check the count before
   * they hand the value to the JOSE library, so a value of the wrong shape is refused without
   * being parsed (JS-SEC-098, CWE-1041: the single copy of what three parsers counted for
   * themselves).
   *
   * <p>Call it after the {@link #MAX_COMPACT_BYTES} check; it reads the whole value.
   *
   * @param compact the compact serialisation, non-null
   * @return the number of segments, at least one
   * @since 00.84.00
   */
  public static int countSegments(String compact) {
    int dots = 0;
    for (int i = 0; i < compact.length(); i++) {
      if (compact.charAt(i) == '.') {
        dots++;
      }
    }
    return dots + 1;
  }
}
