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
package eu.jsentinel.jcustos.propagation.oidc.http;

import eu.jsentinel.jcustos.util.json.BoundedJson;

import java.util.Map;
import java.util.Optional;

/**
 * Reads the top-level fields of a token-endpoint response.
 * <p>
 * Until 00.84.00 this class carried its own top-level JSON scanner, one of three readers in the
 * identity modules (ER31, JS-SEC-098, CWE-1041). It now delegates to {@link BoundedJson}, the
 * one bounded reader in jCustos-core: a body that is no well-formed JSON object - trailing
 * content, a repeated key, deeper than 64 levels, larger than 1 MiB - yields no field at all,
 * and escaped characters arrive decoded. The propagation strategies no longer use this class.
 *
 * @since 00.74.00
 * @deprecated since 00.84.00, for removal in 00.85.00; parse the body once with
 *     {@link BoundedJson#parseObject(String)} and read the fields with
 *     {@link BoundedJson#string(Map, String)} and {@link BoundedJson#integer(Map, String)}.
 */
@Deprecated(since = "00.84.00", forRemoval = true)
public final class JsonResponse {

  private JsonResponse() {
    throw new AssertionError("no instances");
  }

  /**
   * @return the top-level {@code access_token} value, or empty if absent or the body is
   *     malformed
   */
  public static Optional<String> accessToken(String body) {
    return BoundedJson.string(fieldsOf(body), "access_token");
  }

  /**
   * @return the top-level {@code expires_in} value in seconds, or empty if absent, not an
   *     integer within {@code long}, or the body is malformed
   */
  public static Optional<Long> expiresIn(String body) {
    return BoundedJson.integer(fieldsOf(body), "expires_in");
  }

  /**
   * @return the top-level {@code token_type} value (typically {@code "Bearer"}), or empty if
   *     absent or the body is malformed
   */
  public static Optional<String> tokenType(String body) {
    return BoundedJson.string(fieldsOf(body), "token_type");
  }

  private static Map<String, Object> fieldsOf(String body) {
    return BoundedJson.parseObject(body).getOrElse(Map.of());
  }
}
