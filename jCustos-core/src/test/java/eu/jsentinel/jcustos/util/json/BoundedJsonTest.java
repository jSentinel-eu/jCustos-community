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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-098 (CWE-1041, CWE-770): the one JSON reader of the library modules. The first group
 * carries over the cases of the former {@code OidcJson} test of {@code jCustos-identity-oidc};
 * the second covers what is new: size limit, duplicate keys, the exact depth bound and the
 * RFC 8259 number grammar.
 */
@DisplayName("JS-SEC-098 — BoundedJson: strict, bounded, one reader for all modules")
class BoundedJsonTest {

  private static Map<String, Object> parsed(String json) {
    Result<Map<String, Object>, String> result = BoundedJson.parseObject(json);
    assertTrue(result.isSuccess(), () -> "expected to parse: " + result);
    return result.getOrThrow();
  }

  private static String refusal(String json) {
    Result<Map<String, Object>, String> result = BoundedJson.parseObject(json);
    assertTrue(result.isFailure(), () -> "expected a refusal for: " + json);
    return result.fold(ok -> "", reason -> reason);
  }

  private static String nestedArrays(int levels) {
    return "{\"a\":" + "[".repeat(levels) + "]".repeat(levels) + "}";
  }

  // ── carried over from OidcJsonTest ──

  @Test
  @DisplayName("parses objects, arrays, strings, numbers, booleans and null")
  void parsesAllShapes() {
    Map<String, Object> m = parsed(
        "{\"s\":\"hi\",\"n\":42,\"d\":1.5,\"b\":true,\"z\":null,\"a\":[\"x\",\"y\"],"
            + "\"o\":{\"k\":\"v\"}}");
    assertEquals("hi", m.get("s"));
    assertEquals(42L, m.get("n"));
    assertEquals(1.5, m.get("d"));
    assertEquals(Boolean.TRUE, m.get("b"));
    assertNull(m.get("z"));
    assertTrue(m.containsKey("z"));
    assertEquals(List.of("x", "y"), m.get("a"));
    assertEquals(Map.of("k", "v"), m.get("o"));
  }

  @Test
  @DisplayName("decodes string escapes including the unicode escape and surrogate pairs")
  void decodesEscapes() {
    assertEquals("a\nbA\"c", parsed("{\"k\":\"a\\nb\\u0041\\\"c\"}").get("k"));
    assertEquals("\b\f\r\t/\\", parsed("{\"k\":\"\\b\\f\\r\\t\\/\\\\\"}").get("k"));
    assertEquals("caf\u00e9 \uD83D\uDE00", parsed("{\"k\":\"caf\\u00E9 \\ud83d\\ude00\"}").get("k"));
    assertEquals("value", parsed("{\"\\u006b\":\"value\"}").get("k"), "keys are decoded as well");
  }

  @Test
  @DisplayName("refuses trailing content after the top-level value")
  void rejectsTrailingContent() {
    refusal("{}garbage");
    refusal("{} {}");
  }

  @Test
  @DisplayName("refuses malformed input (unterminated string / bad literal / missing colon)")
  void rejectsMalformed() {
    refusal("{\"k\":}");
    refusal("{\"k\" \"v\"}");
    refusal("{\"k\":\"unterminated");
    refusal("{\"k\":tru}");
    refusal("{\"k\":truex}");
    refusal("{\"k\":nul}");
    refusal("{\"k\":1,}");
    refusal("{,}");
    refusal("{\"k\":[1,]}");
    refusal("{k:1}");
    refusal("{\"k\":'v'}");
  }

  @Test
  @DisplayName("a non-hex unicode escape is a refusal, not an uncaught NumberFormatException")
  void invalidUnicodeEscape() {
    refusal("{\"k\":\"\\uZZZZ\"}");
    refusal("{\"k\":\"\\u00+1\"}");
    refusal("{\"k\":\"\\u00\"}");
    refusal("{\"k\":\"\\x41\"}");
  }

  @Test
  @DisplayName("refuses an unescaped control character inside a string")
  void rejectsControlCharacters() {
    refusal("{\"k\":\"a\nb\"}");
    refusal("{\"k\":\"a\u0000b\"}");
  }

  @Test
  @DisplayName("parseObject refuses a top-level value that is not an object")
  void parseObjectRejectsNonObject() {
    assertEquals("expected a JSON object", refusal("[1,2,3]"));
    refusal("\"string\"");
    refusal("42");
    refusal("null");
    refusal("true");
  }

  // ── new in 00.84.00 ──

  @Test
  @DisplayName("null, empty and blank input are refused")
  void noInput() {
    assertEquals("no input", refusal(null));
    refusal("");
    refusal("  \n\t ");
  }

  @Test
  @DisplayName("size: exactly MAX_INPUT_CHARS characters are read, one more is refused before reading")
  void sizeLimit() {
    String prefix = "{\"k\":\"";
    String suffix = "\"}";
    int fill = BoundedJson.MAX_INPUT_CHARS - prefix.length() - suffix.length();
    String atLimit = prefix + "a".repeat(fill) + suffix;
    assertEquals(BoundedJson.MAX_INPUT_CHARS, atLimit.length());
    assertEquals(fill, ((String) parsed(atLimit).get("k")).length());

    String overLimit = prefix + "a".repeat(fill + 1) + suffix;
    assertEquals("input exceeds " + BoundedJson.MAX_INPUT_CHARS + " characters", refusal(overLimit));
  }

  @Test
  @DisplayName("depth: 64 levels below the top-level object are read, 65 are refused")
  void depthLimit() {
    assertEquals(64, BoundedJson.MAX_DEPTH);
    assertTrue(parsed(nestedArrays(BoundedJson.MAX_DEPTH)).containsKey("a"));
    assertEquals("nesting deeper than 64 levels", refusal(nestedArrays(BoundedJson.MAX_DEPTH + 1)));
    // far beyond the bound: no StackOverflowError, a refusal
    refusal(nestedArrays(100_000));
    refusal("{\"a\":" + "{\"b\":".repeat(10_000) + "1" + "}".repeat(10_000) + "}");
  }

  @Test
  @DisplayName("duplicate keys are refused at the top level and in nested objects")
  void duplicateKeys() {
    assertEquals("duplicate key at 20",
        refusal("{\"access_token\":\"a\",\"access_token\":\"b\"}"));
    refusal("{\"o\":{\"k\":1,\"k\":1}}");
    refusal("{\"a\":[{\"k\":1,\"k\":2}]}");
    refusal("{\"k\":1,\"\\u006b\":2}");
    Map<String, Object> distinct = parsed("{\"a\":{\"k\":1},\"b\":{\"k\":2}}");
    assertEquals(Map.of("k", 2L), distinct.get("b"), "the same key in different objects is no duplicate");
  }

  @Test
  @DisplayName("numbers follow RFC 8259: integers as Long, fractions as Double")
  void numbers() {
    Map<String, Object> m = parsed("{\"a\":0,\"b\":-0,\"c\":9223372036854775807,\"d\":-9223372036854775808,"
        + "\"e\":1e5,\"f\":-1.5E-3,\"g\":2.0}");
    assertEquals(0L, m.get("a"));
    assertEquals(0L, m.get("b"));
    assertEquals(Long.MAX_VALUE, m.get("c"));
    assertEquals(Long.MIN_VALUE, m.get("d"));
    assertEquals(100000.0, m.get("e"));
    assertEquals(-0.0015, m.get("f"));
    assertEquals(2.0, m.get("g"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"01", "-01", "+1", "1.", ".5", "-", "1e", "1e+", "0x10", "1.2.3", "1-2",
      "9223372036854775808", "-9223372036854775809", "1e400", "-1e400", "NaN", "Infinity"})
  @DisplayName("malformed or out-of-range numbers are refused")
  void badNumbers(String number) {
    refusal("{\"n\":" + number + "}");
  }

  @Test
  @DisplayName("a refusal names a position, never a piece of the input")
  void refusalCarriesNoInput() {
    String reason = refusal("{\"client_secret\":\"s3cr3t-value\",\"client_secret\":\"other\"}");
    assertFalse(reason.contains("s3cr3t"), reason);
    assertFalse(reason.contains("client_secret"), reason);
    reason = refusal("{\"k\":\"s3cr3t-value\" garbage}");
    assertFalse(reason.contains("s3cr3t"), reason);
  }

  @Test
  @DisplayName("parsed objects and arrays are unmodifiable")
  void unmodifiable() {
    Map<String, Object> m = parsed("{\"a\":[1],\"o\":{}}");
    assertThrows(UnsupportedOperationException.class, () -> m.put("x", "y"));
    assertThrows(UnsupportedOperationException.class, () -> ((List<?>) m.get("a")).clear());
    assertThrows(UnsupportedOperationException.class, () -> ((Map<?, ?>) m.get("o")).clear());
  }

  @Test
  @DisplayName("typed getters return a value only for the matching type")
  void typedGetters() {
    Map<String, Object> m = parsed("{\"s\":\"text\",\"n\":7,\"d\":7.5,\"b\":false,\"z\":null}");
    assertEquals(Optional.of("text"), BoundedJson.string(m, "s"));
    assertEquals(Optional.empty(), BoundedJson.string(m, "n"));
    assertEquals(Optional.empty(), BoundedJson.string(m, "z"));
    assertEquals(Optional.empty(), BoundedJson.string(m, "missing"));
    assertEquals(Optional.of(7L), BoundedJson.integer(m, "n"));
    assertEquals(Optional.empty(), BoundedJson.integer(m, "d"), "a fraction is no integer");
    assertEquals(Optional.empty(), BoundedJson.integer(m, "s"));
    assertEquals(Optional.of(false), BoundedJson.bool(m, "b"));
    assertEquals(Optional.empty(), BoundedJson.bool(m, "s"));
  }

  @Test
  @DisplayName("white space around and between tokens is accepted")
  void whitespace() {
    Map<String, Object> m = parsed(" \r\n\t{ \"a\" : [ 1 , 2 ] , \"b\" : { } }\n ");
    assertEquals(List.of(1L, 2L), m.get("a"));
    assertEquals(Map.of(), m.get("b"));
  }
}
