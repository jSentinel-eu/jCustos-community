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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("CanonicalJson parser — malformed input hardening (R015)")
class CanonicalJsonTest {

  @Test
  @DisplayName("deeply nested input raises PayloadCodecException, not StackOverflowError")
  void deepNestingRaisesCodecExceptionNotStackOverflow() {
    int depth = CanonicalJson.MAX_DEPTH + 500;
    StringBuilder json = new StringBuilder();
    for (int i = 0; i < depth; i++) {
      json.append("{\"a\":");
    }
    json.append('1');
    for (int i = 0; i < depth; i++) {
      json.append('}');
    }
    // Must be the codec exception (a depth guard fired) — never a StackOverflowError.
    assertThrows(PayloadCodecException.class, () -> CanonicalJson.parse(json.toString()));
  }

  @Test
  @DisplayName("a truncated \\u escape raises PayloadCodecException, not StringIndexOutOfBounds")
  void truncatedUnicodeEscapeRaisesCodecException() {
    // "\\u12 then end of input — only two hex digits available before the close.
    assertThrows(PayloadCodecException.class, () -> CanonicalJson.parse("\"\\u12\""));
  }

  @Test
  @DisplayName("an invalid \\u hex group raises PayloadCodecException, not NumberFormatException")
  void invalidUnicodeEscapeHexRaisesCodecException() {
    assertThrows(PayloadCodecException.class, () -> CanonicalJson.parse("\"\\uZZZZ\""));
  }

  @Test
  @DisplayName("a dangling backslash at end of string raises PayloadCodecException")
  void danglingBackslashRaisesCodecException() {
    // Opening quote, content, then a trailing backslash with no following char.
    assertThrows(PayloadCodecException.class, () -> CanonicalJson.parse("\"abc\\"));
  }

  @Test
  @DisplayName("end of input where ',' or '}' is expected raises PayloadCodecException")
  void unexpectedEndAfterValueRaisesCodecException() {
    assertThrows(PayloadCodecException.class, () -> CanonicalJson.parse("{\"a\":1"));
  }

  @Test
  @DisplayName("an object that names a key twice raises PayloadCodecException, at any depth")
  void duplicateKeyRaisesCodecException() {
    for (String json : new String[]{
        "{\"a\":\"x\",\"a\":\"y\"}",
        "{\"a\":{\"b\":1,\"b\":2}}",
        "{\"a\":\"x\",\"\\u0061\":\"y\"}"}) {
      PayloadCodecException duplicate =
          assertThrows(PayloadCodecException.class, () -> CanonicalJson.parse(json), json);
      assertTrue(duplicate.getMessage().contains("duplicate key"), duplicate.getMessage());
    }
    Map<?, ?> distinct = assertInstanceOf(Map.class,
        CanonicalJson.parse("{\"a\":\"x\",\"b\":\"y\"}"));
    assertEquals(2, distinct.size());
  }

  @Test
  @DisplayName("a valid object nested within the depth bound parses and round-trips")
  void validNestedObjectWithinDepthParses() {
    Object parsed = CanonicalJson.parse("{\"a\":{\"b\":1}}");
    Map<?, ?> outer = assertInstanceOf(Map.class, parsed);
    Map<?, ?> inner = assertInstanceOf(Map.class, outer.get("a"));
    assertEquals(1L, inner.get("b"));
  }
}
