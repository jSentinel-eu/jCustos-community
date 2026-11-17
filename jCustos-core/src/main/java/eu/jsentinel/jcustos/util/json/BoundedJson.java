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
package eu.jsentinel.jcustos.util.json;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The one JSON reader of jCustos for documents an HTTP endpoint sends back: token, PAR,
 * introspection and device responses, discovery documents, UserInfo responses and the token
 * responses of the propagation strategies (JS-SEC-098, CWE-1041, CWE-770). It replaces three
 * readers that had drifted apart — two top-level scanners that decoded no <code>&#92;uXXXX</code> escape
 * and a full parser — and keeps the stricter of their rules. The event wire codec has its own,
 * canonical codec and is not served by this class.
 *
 * <p>The reader is strict and bounded:
 *
 * <ul>
 *   <li>an input longer than {@link #MAX_INPUT_CHARS} characters is refused before it is
 *       read;</li>
 *   <li>containers nest at most {@link #MAX_DEPTH} levels deep, so no input exhausts the
 *       stack;</li>
 *   <li>an object that names a key twice is refused: two components that pick different
 *       duplicates is how a parser differential is exploited (RFC 8259 §4 leaves the choice
 *       open);</li>
 *   <li>the grammar is RFC 8259: one value, nothing after it but white space, no unescaped
 *       control character in a string, numbers without a leading {@code +} or leading zeros.
 *       All escapes are decoded, <code>&#92;uXXXX</code> included;</li>
 *   <li>an integer that does not fit a {@code long}, or a fraction that is not finite as a
 *       {@code double}, is refused (RFC 8259 §6 permits the limit).</li>
 * </ul>
 *
 * <p>Values map to {@link Map} (insertion-ordered, unmodifiable), {@link List} (unmodifiable),
 * {@link String}, {@link Long}, {@link Double}, {@link Boolean} and {@code null}. A refusal is a
 * {@link Result#failure(Object) failure} with a short reason that names a position, never a
 * piece of the input.
 *
 * <p>Internal to jCustos: the class is public so that the identity, OAuth2 and propagation
 * modules share it, not for application code.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi("Internal to jCustos; shared by the identity, OAuth2 and propagation modules.")
public final class BoundedJson {

  /**
   * Largest accepted input, in characters (1 MiB). Every HTTP client of jCustos caps a response
   * body at 1 MiB of bytes, which never decodes to more characters.
   */
  public static final int MAX_INPUT_CHARS = 1 << 20;

  /** Deepest accepted nesting of objects and arrays below the top-level value. */
  public static final int MAX_DEPTH = 64;

  /** Unwinds a refused parse; never leaves this class. */
  private static final class Refusal extends RuntimeException {
    Refusal(String reason) {
      super(reason, null, false, false);
    }
  }

  private final String s;
  private int i;

  private BoundedJson(String s) {
    this.s = s;
  }

  /**
   * Parses one complete JSON document whose top-level value is an object.
   *
   * @param json the JSON text, may be {@code null} (refused)
   * @return the object, or the reason for the refusal
   */
  @SuppressWarnings("unchecked")
  public static Result<Map<String, Object>, String> parseObject(String json) {
    if (json == null) {
      return Result.failure("no input");
    }
    if (json.length() > MAX_INPUT_CHARS) {
      return Result.failure("input exceeds " + MAX_INPUT_CHARS + " characters");
    }
    BoundedJson parser = new BoundedJson(json);
    Object value;
    try {
      parser.skipWs();
      value = parser.value(0);
      parser.skipWs();
    } catch (Refusal refusal) {
      return Result.failure(refusal.getMessage());
    }
    if (parser.i != json.length()) {
      return Result.failure("trailing content after the JSON value at " + parser.i);
    }
    return value instanceof Map<?, ?> map
        ? Result.success((Map<String, Object>) map)
        : Result.failure("expected a JSON object");
  }

  /**
   * The string member {@code key} of {@code object}.
   *
   * @param object a parsed object, non-null
   * @param key    the member name
   * @return the value, or empty when the member is absent or not a string
   */
  public static Optional<String> string(Map<String, ?> object, String key) {
    return object.get(key) instanceof String value ? Optional.of(value) : Optional.empty();
  }

  /**
   * The integer member {@code key} of {@code object}.
   *
   * @param object a parsed object, non-null
   * @param key    the member name
   * @return the value, or empty when the member is absent or not an integer
   */
  public static Optional<Long> integer(Map<String, ?> object, String key) {
    return object.get(key) instanceof Long value ? Optional.of(value) : Optional.empty();
  }

  /**
   * The boolean member {@code key} of {@code object}.
   *
   * @param object a parsed object, non-null
   * @param key    the member name
   * @return the value, or empty when the member is absent or not a boolean
   */
  public static Optional<Boolean> bool(Map<String, ?> object, String key) {
    return object.get(key) instanceof Boolean value ? Optional.of(value) : Optional.empty();
  }

  private Object value(int depth) {
    if (depth > MAX_DEPTH) {
      throw new Refusal("nesting deeper than " + MAX_DEPTH + " levels");
    }
    if (i >= s.length()) {
      throw new Refusal("unexpected end of input");
    }
    char c = s.charAt(i);
    return switch (c) {
      case '{' -> object(depth);
      case '[' -> array(depth);
      case '"' -> string();
      case 't' -> literal("true", Boolean.TRUE);
      case 'f' -> literal("false", Boolean.FALSE);
      case 'n' -> literal("null", null);
      default -> number();
    };
  }

  private Map<String, Object> object(int depth) {
    expect('{');
    Map<String, Object> map = new LinkedHashMap<>();
    skipWs();
    if (peek() == '}') {
      i++;
      return Collections.unmodifiableMap(map);
    }
    while (true) {
      skipWs();
      if (peek() != '"') {
        throw new Refusal("expected a string key at " + i);
      }
      int keyAt = i;
      String key = string();
      if (map.containsKey(key)) {
        throw new Refusal("duplicate key at " + keyAt);
      }
      skipWs();
      expect(':');
      skipWs();
      map.put(key, value(depth + 1));
      skipWs();
      char c = next();
      if (c == '}') {
        return Collections.unmodifiableMap(map);
      }
      if (c != ',') {
        throw new Refusal("expected ',' or '}' at " + (i - 1));
      }
    }
  }

  private List<Object> array(int depth) {
    expect('[');
    List<Object> list = new ArrayList<>();
    skipWs();
    if (peek() == ']') {
      i++;
      return Collections.unmodifiableList(list);
    }
    while (true) {
      skipWs();
      list.add(value(depth + 1));
      skipWs();
      char c = next();
      if (c == ']') {
        return Collections.unmodifiableList(list);
      }
      if (c != ',') {
        throw new Refusal("expected ',' or ']' at " + (i - 1));
      }
    }
  }

  private String string() {
    expect('"');
    StringBuilder sb = new StringBuilder();
    while (true) {
      if (i >= s.length()) {
        throw new Refusal("unterminated string");
      }
      char c = s.charAt(i++);
      if (c == '"') {
        return sb.toString();
      }
      if (c == '\\') {
        char e = next();
        switch (e) {
          case '"' -> sb.append('"');
          case '\\' -> sb.append('\\');
          case '/' -> sb.append('/');
          case 'b' -> sb.append('\b');
          case 'f' -> sb.append('\f');
          case 'n' -> sb.append('\n');
          case 'r' -> sb.append('\r');
          case 't' -> sb.append('\t');
          case 'u' -> sb.append(unicodeEscape());
          default -> throw new Refusal("invalid escape at " + (i - 1));
        }
      } else if (c < 0x20) {
        throw new Refusal("unescaped control character in a string at " + (i - 1));
      } else {
        sb.append(c);
      }
    }
  }

  private char unicodeEscape() {
    if (i + 4 > s.length()) {
      throw new Refusal("truncated unicode escape");
    }
    int code = 0;
    for (int h = 0; h < 4; h++) {
      int digit = Character.digit(s.charAt(i + h), 16);
      if (digit < 0) {
        throw new Refusal("invalid unicode escape at " + (i - 2));
      }
      code = (code << 4) | digit;
    }
    i += 4;
    return (char) code;
  }

  private Object number() {
    int start = i;
    if (peek() == '-') {
      i++;
    }
    if (peek() == '0') {
      i++;
    } else if (isDigit(peek())) {
      digits();
    } else {
      throw new Refusal("invalid value at " + start);
    }
    boolean integral = true;
    if (peek() == '.') {
      integral = false;
      i++;
      if (!isDigit(peek())) {
        throw new Refusal("invalid number at " + start);
      }
      digits();
    }
    if (peek() == 'e' || peek() == 'E') {
      integral = false;
      i++;
      if (peek() == '+' || peek() == '-') {
        i++;
      }
      if (!isDigit(peek())) {
        throw new Refusal("invalid number at " + start);
      }
      digits();
    }
    String text = s.substring(start, i);
    if (integral) {
      try {
        return Long.parseLong(text);
      } catch (NumberFormatException outOfRange) {
        throw new Refusal("integer out of range at " + start);
      }
    }
    double value = Double.parseDouble(text);
    if (Double.isInfinite(value)) {
      throw new Refusal("number out of range at " + start);
    }
    return value;
  }

  private void digits() {
    while (isDigit(peek())) {
      i++;
    }
  }

  private static boolean isDigit(char c) {
    return c >= '0' && c <= '9';
  }

  private Object literal(String text, Object value) {
    if (!s.startsWith(text, i)) {
      throw new Refusal("invalid literal at " + i);
    }
    i += text.length();
    return value;
  }

  private void expect(char c) {
    if (next() != c) {
      throw new Refusal("expected '" + c + "' at " + (i - 1));
    }
  }

  private char next() {
    if (i >= s.length()) {
      throw new Refusal("unexpected end of input");
    }
    return s.charAt(i++);
  }

  private char peek() {
    return i < s.length() ? s.charAt(i) : '\0';
  }

  private void skipWs() {
    while (i < s.length()) {
      char c = s.charAt(i);
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        i++;
      } else {
        break;
      }
    }
  }
}
