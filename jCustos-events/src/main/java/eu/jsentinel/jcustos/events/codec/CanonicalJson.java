package eu.jsentinel.jcustos.events.codec;

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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal in-tree canonical JSON engine (Konzept §454-§466). No Jackson, Gson
 * or org.json — those are Maven-Enforcer-banned on this module.
 *
 * <p>Canonical rules: UTF-8, no insignificant whitespace, object keys sorted
 * lexicographically, strings escaped deterministically, integers without a
 * fractional part. The engine handles exactly the value shapes the canonical
 * payload needs: objects, strings and non-negative integers.
 *
 * <p>Public since 00.80.00 (V00.80 P010): the audit-integrity export codec
 * reuses this hardened engine (depth cap, deterministic escaping) instead of
 * duplicating a JSON writer.
 *
 * @since 00.75.00
 */
@eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi
public final class CanonicalJson {

  private CanonicalJson() {
  }

  /**
   * Writes a value in canonical form. Supported types: {@link Map} (rendered
   * as an object with sorted keys), {@link String}, {@link Integer} /
   * {@link Long}.
   */
  public static void write(StringBuilder out, Object value) {
    switch (value) {
      case null -> throw new PayloadCodecException("canonical JSON does not encode null");
      case Map<?, ?> map -> writeObject(out, map);
      case String s -> writeString(out, s);
      case Integer i -> out.append(i.intValue());
      case Long l -> out.append(l.longValue());
      default -> throw new PayloadCodecException(
          "unsupported canonical JSON value type: " + value.getClass().getName());
    }
  }

  private static void writeObject(StringBuilder out, Map<?, ?> map) {
    TreeMap<String, Object> sorted = new TreeMap<>();
    for (Map.Entry<?, ?> e : map.entrySet()) {
      sorted.put(String.valueOf(e.getKey()), e.getValue());
    }
    out.append('{');
    boolean first = true;
    for (Map.Entry<String, Object> e : sorted.entrySet()) {
      if (!first) {
        out.append(',');
      }
      first = false;
      writeString(out, e.getKey());
      out.append(':');
      write(out, e.getValue());
    }
    out.append('}');
  }

  private static void writeString(StringBuilder out, String s) {
    out.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }

  /**
   * Parses a canonical JSON document into {@link Map} / {@link String} /
   * {@link Long} values. An object that names a key twice is rejected
   * (since 00.84.00): canonical output never contains one, and parsers
   * disagree on which of the two values counts.
   *
   * @throws PayloadCodecException if the document is malformed, too deeply
   *     nested or names a key twice
   */
  public static Object parse(String json) {
    Parser parser = new Parser(json);
    parser.skipWhitespace();
    Object value = parser.parseValue();
    parser.skipWhitespace();
    if (!parser.atEnd()) {
      throw new PayloadCodecException("trailing content in canonical JSON at index " + parser.pos);
    }
    return value;
  }

  /**
   * Hard bound on object nesting on the parse path. Canonical event payloads are
   * shallow; this only exists to turn a hostile deeply-nested document into a
   * clean {@link PayloadCodecException} instead of a {@link StackOverflowError}
   * (R015 / CWE-674).
   */
  static final int MAX_DEPTH = 64;

  private static final class Parser {
    private final String s;
    private int pos;
    private int depth;

    Parser(String s) {
      this.s = s;
    }

    boolean atEnd() {
      return pos >= s.length();
    }

    void skipWhitespace() {
      while (pos < s.length()) {
        char c = s.charAt(pos);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
          pos++;
        } else {
          break;
        }
      }
    }

    Object parseValue() {
      if (atEnd()) {
        throw new PayloadCodecException("unexpected end of canonical JSON");
      }
      char c = s.charAt(pos);
      return switch (c) {
        case '{' -> parseObject();
        case '"' -> parseString();
        default -> parseNumber();
      };
    }

    Map<String, Object> parseObject() {
      // R015: bound recursion depth so a hostile {"a":{"a":{… document raises a
      // PayloadCodecException rather than a StackOverflowError on the consume path.
      if (++depth > MAX_DEPTH) {
        throw new PayloadCodecException(
            "canonical JSON nesting too deep (> " + MAX_DEPTH + ")");
      }
      try {
        expect('{');
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
          pos++;
          return map;
        }
        while (true) {
          skipWhitespace();
          String key = parseString();
          // A canonical document names every key once. A duplicate is read
          // differently by different parsers (last wins here, first wins in
          // others), so it is malformed rather than silently resolved.
          if (map.containsKey(key)) {
            throw new PayloadCodecException("duplicate key in canonical JSON object at index "
                + pos);
          }
          skipWhitespace();
          expect(':');
          skipWhitespace();
          map.put(key, parseValue());
          skipWhitespace();
          char c = next();
          if (c == ',') {
            continue;
          }
          if (c == '}') {
            return map;
          }
          throw new PayloadCodecException("expected ',' or '}' at index " + (pos - 1));
        }
      } finally {
        depth--;
      }
    }

    String parseString() {
      expect('"');
      StringBuilder sb = new StringBuilder();
      while (true) {
        if (atEnd()) {
          throw new PayloadCodecException("unterminated string in canonical JSON");
        }
        char c = s.charAt(pos++);
        if (c == '"') {
          return sb.toString();
        }
        if (c == '\\') {
          // R015: an escape with no following character is malformed input, not
          // a reason to throw a raw StringIndexOutOfBoundsException.
          if (atEnd()) {
            throw new PayloadCodecException("dangling escape at end of canonical JSON string");
          }
          char esc = s.charAt(pos++);
          switch (esc) {
            case '"' -> sb.append('"');
            case '\\' -> sb.append('\\');
            case '/' -> sb.append('/');
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'n' -> sb.append('\n');
            case 'r' -> sb.append('\r');
            case 't' -> sb.append('\t');
            case 'u' -> {
              // R015: bounds-check before substring and wrap a bad hex group so a
              // truncated/invalid \\u yields PayloadCodecException, not a raw
              // StringIndexOutOfBounds / NumberFormatException.
              if (pos + 4 > s.length()) {
                throw new PayloadCodecException(
                    "truncated \\u escape in canonical JSON at index " + (pos - 2));
              }
              String hex = s.substring(pos, pos + 4);
              pos += 4;
              try {
                sb.append((char) Integer.parseInt(hex, 16));
              } catch (NumberFormatException e) {
                throw new PayloadCodecException(
                    "invalid \\u escape '" + hex + "' in canonical JSON", e);
              }
            }
            default -> throw new PayloadCodecException("invalid escape \\" + esc);
          }
        } else {
          sb.append(c);
        }
      }
    }

    Long parseNumber() {
      int start = pos;
      if (peek() == '-') {
        pos++;
      }
      while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
        pos++;
      }
      if (pos == start) {
        throw new PayloadCodecException("expected value at index " + start);
      }
      try {
        return Long.parseLong(s.substring(start, pos));
      } catch (NumberFormatException e) {
        throw new PayloadCodecException("invalid number at index " + start, e);
      }
    }

    char peek() {
      if (atEnd()) {
        throw new PayloadCodecException("unexpected end of canonical JSON");
      }
      return s.charAt(pos);
    }

    char next() {
      // R015: never index past the end with a raw charAt — report malformed input.
      if (atEnd()) {
        throw new PayloadCodecException("unexpected end of canonical JSON");
      }
      return s.charAt(pos++);
    }

    void expect(char c) {
      if (atEnd() || s.charAt(pos) != c) {
        throw new PayloadCodecException("expected '" + c + "' at index " + pos);
      }
      pos++;
    }
  }
}
