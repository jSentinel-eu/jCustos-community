package eu.jsentinel.jcustos.events.wire;

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

import eu.jsentinel.jcustos.events.api.WellFormedText;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal flat-object JSON engine for the wire codec (no Jackson). Handles a
 * single JSON object whose values are strings or non-negative integers — all
 * the envelope's wire fields are strings (byte arrays base64-encoded) plus the
 * numeric sequence.
 */
final class WireJson {

  private WireJson() {
  }

  static String writeObject(Map<String, Object> fields) {
    StringBuilder out = new StringBuilder();
    out.append('{');
    boolean first = true;
    for (Map.Entry<String, Object> e : fields.entrySet()) {
      if (!first) {
        out.append(',');
      }
      first = false;
      writeString(out, e.getKey());
      out.append(':');
      Object value = e.getValue();
      if (value instanceof Number n) {
        out.append(n.longValue());
      } else {
        writeString(out, String.valueOf(value));
      }
    }
    out.append('}');
    return out.toString();
  }

  private static void writeString(StringBuilder out, String s) {
    out.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (mustEscape(c)) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }

  // JS-SEC-110 (CWE-93): besides the C0 controls JSON requires to be escaped,
  // DEL, the C1 controls (U+0085 NEXT LINE among them) and the Unicode line and
  // paragraph separators are written as six-character Unicode escapes. JSON
  // allows them raw, but a line-oriented consumer that splits on Unicode line
  // terminators would cut one record into several. The escape is plain JSON —
  // every decoder, including earlier versions of this one, reads the same
  // value.
  private static boolean mustEscape(char c) {
    return c < 0x20 || (c >= 0x7f && c <= 0x9f) || c == 0x2028 || c == 0x2029;
  }

  static Map<String, Object> parseObject(String json) {
    Parser p = new Parser(json);
    p.ws();
    Map<String, Object> map = p.object();
    p.ws();
    if (!p.end()) {
      throw new EventWireException("trailing content in JSON at " + p.pos);
    }
    return map;
  }

  private static final class Parser {
    private final String s;
    private int pos;

    Parser(String s) {
      this.s = s;
    }

    boolean end() {
      return pos >= s.length();
    }

    void ws() {
      while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
        pos++;
      }
    }

    Map<String, Object> object() {
      expect('{');
      Map<String, Object> map = new LinkedHashMap<>();
      ws();
      if (peek() == '}') {
        pos++;
        return map;
      }
      while (true) {
        ws();
        String key = string();
        ws();
        expect(':');
        ws();
        map.put(key, value());
        ws();
        if (end()) {
          throw new EventWireException("expected ',' or '}' but reached end of JSON");
        }
        char c = s.charAt(pos++);
        if (c == ',') {
          continue;
        }
        if (c == '}') {
          return map;
        }
        throw new EventWireException("expected ',' or '}' at " + (pos - 1));
      }
    }

    Object value() {
      char c = peek();
      if (c == '"') {
        return string();
      }
      return number();
    }

    String string() {
      expect('"');
      StringBuilder sb = new StringBuilder();
      while (true) {
        if (end()) {
          throw new EventWireException("unterminated string");
        }
        char c = s.charAt(pos++);
        if (c == '"') {
          return wellFormed(sb);
        }
        if (c == '\\') {
          if (end()) {
            throw new EventWireException("unterminated escape sequence");
          }
          char esc = s.charAt(pos++);
          switch (esc) {
            case '"' -> sb.append('"');
            case '\\' -> sb.append('\\');
            case '/' -> sb.append('/');
            case 'n' -> sb.append('\n');
            case 'r' -> sb.append('\r');
            case 't' -> sb.append('\t');
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'u' -> {
              if (pos + 4 > s.length()) {
                throw new EventWireException("truncated \\u escape");
              }
              String hex = s.substring(pos, pos + 4);
              try {
                sb.append((char) Integer.parseInt(hex, 16));
              } catch (NumberFormatException e) {
                throw new EventWireException("invalid \\u escape '" + hex + "'", e);
              }
              pos += 4;
            }
            default -> throw new EventWireException("invalid escape \\" + esc);
          }
        } else {
          sb.append(c);
        }
      }
    }

    // JS-SEC-111 (CWE-176): a lone surrogate — written raw or as a single
    // Unicode escape such as U+D800 — has no UTF-8 encoding and would enter
    // the signature base as '?'. Reject it here so the caller gets a decode
    // error.
    private static String wellFormed(StringBuilder sb) {
      if (!WellFormedText.isWellFormed(sb)) {
        throw new EventWireException("string contains an unpaired surrogate");
      }
      return sb.toString();
    }

    Long number() {
      int start = pos;
      if (peek() == '-') {
        pos++;
      }
      while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
        pos++;
      }
      if (pos == start) {
        throw new EventWireException("expected value at " + start);
      }
      String digits = s.substring(start, pos);
      try {
        return Long.parseLong(digits);
      } catch (NumberFormatException e) {
        throw new EventWireException("number out of range: " + digits, e);
      }
    }

    char peek() {
      if (end()) {
        throw new EventWireException("unexpected end of JSON");
      }
      return s.charAt(pos);
    }

    void expect(char c) {
      if (end() || s.charAt(pos) != c) {
        throw new EventWireException("expected '" + c + "' at " + pos);
      }
      pos++;
    }
  }
}
