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
package eu.jsentinel.jcustos.oauth2.internal;

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

import eu.jsentinel.jcustos.util.json.BoundedJson;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Field access for OAuth2 token, PAR, introspection and device responses (V00.77) — no
 * third-party JSON library. Only members of the top-level object are read, so a nested or
 * value-embedded key can never be picked (R09).
 *
 * <p>Since 00.84.00 (JS-SEC-098, CWE-1041) this class is a facade over
 * {@link BoundedJson}, the one JSON reader of jCustos, and no longer a scanner of its own. The
 * signatures are unchanged; what changes is what a response has to be: a well-formed JSON
 * object of at most {@link BoundedJson#MAX_INPUT_CHARS} characters, nested at most
 * {@link BoundedJson#MAX_DEPTH} levels, without a repeated key. A body that is not yields empty
 * for every field. String values are fully decoded, <code>&#92;uXXXX</code> escapes included — the
 * scanner kept those raw. A response is read once with {@link #object(String)}; the
 * {@code String}-taking methods parse the body on every call and remain for compatibility.
 */
public final class OAuth2Json {

  private OAuth2Json() {
    throw new AssertionError("no instances");
  }

  /**
   * Reads a response body as a JSON object.
   *
   * @param body the response body, may be {@code null}
   * @return the top-level object, or empty when the body is not a well-formed JSON object
   *     within the bounds of {@link BoundedJson}
   * @since 00.84.00
   */
  public static Optional<Map<String, Object>> object(String body) {
    return BoundedJson.parseObject(body).toOptional();
  }

  /** @return the top-level string field {@code key}, or empty. */
  public static Optional<String> string(String body, String key) {
    return object(body).flatMap(json -> string(json, key));
  }

  /**
   * @param json a parsed response
   * @param key  the top-level key
   * @return the string field {@code key}, or empty
   * @since 00.84.00
   */
  public static Optional<String> string(Map<String, ?> json, String key) {
    return BoundedJson.string(json, key);
  }

  /** @return the top-level numeric field {@code key} as a long, or empty (overflow-safe). */
  public static Optional<Long> longValue(String body, String key) {
    return object(body).flatMap(json -> longValue(json, key));
  }

  /**
   * @param json a parsed response
   * @param key  the top-level key
   * @return the integer field {@code key}, or empty when it is absent or not an integer
   * @since 00.84.00
   */
  public static Optional<Long> longValue(Map<String, ?> json, String key) {
    return BoundedJson.integer(json, key);
  }

  /** @return the top-level boolean field {@code key}, or empty. */
  public static Optional<Boolean> bool(String body, String key) {
    return object(body).flatMap(json -> bool(json, key));
  }

  /**
   * @param json a parsed response
   * @param key  the top-level key
   * @return the boolean field {@code key}, or empty
   * @since 00.84.00
   */
  public static Optional<Boolean> bool(Map<String, ?> json, String key) {
    return BoundedJson.bool(json, key);
  }

  /**
   * JS-SEC-034 (CWE-248): parse an RFC 6749 scope string into a set without
   * {@code Set.of}'s duplicate-hostility. Splits on whitespace, drops blanks and
   * de-duplicates into an insertion-ordered {@link LinkedHashSet}. {@code Set.of}
   * throws {@link IllegalArgumentException} on a duplicate scope (or an empty token
   * from consecutive spaces), which escaped the module's {@code Result} never-throw
   * contract on a non-conformant authorization-server response.
   *
   * @param scope the raw {@code scope} value (may be {@code null} / blank)
   * @return the de-duplicated scopes, never {@code null}
   */
  public static Set<String> parseScopes(String scope) {
    if (scope == null || scope.isBlank()) {
      return Set.of();
    }
    return Arrays.stream(scope.trim().split("\\s+"))
        .filter(token -> !token.isEmpty())
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  /**
   * JS-SEC-043 (CWE-20): reads a top-level claim that RFC 7662 / RFC 7519 permit as EITHER a JSON
   * string OR an array of strings (notably {@code aud}). A scalar string yields a single-element
   * set; an array yields all of its string elements (non-string elements skipped); an absent or
   * otherwise-shaped value yields an empty set. Mirrors the String-or-array tolerance the JWT
   * {@code aud} path already has, so the opaque-token introspection path no longer silently drops
   * an array-form audience.
   *
   * @param body the JSON body
   * @param key  the top-level key
   * @return the audience values, never {@code null}
   */
  public static Set<String> stringOrArray(String body, String key) {
    return object(body).map(json -> stringOrArray(json, key)).orElse(Set.of());
  }

  /**
   * @param json a parsed response
   * @param key  the top-level key
   * @return the values of a string-or-array field, never {@code null}
   * @since 00.84.00
   */
  public static Set<String> stringOrArray(Map<String, ?> json, String key) {
    Object value = json.get(key);
    if (value instanceof String scalar) {
      return Set.of(scalar);
    }
    if (value instanceof List<?> list) {
      Set<String> out = new LinkedHashSet<>();
      for (Object element : list) {
        if (element instanceof String text) {
          out.add(text);
        }
      }
      return Set.copyOf(out);
    }
    return Set.of();
  }
}
