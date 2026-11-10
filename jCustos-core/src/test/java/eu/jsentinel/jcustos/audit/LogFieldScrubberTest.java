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
package eu.jsentinel.jcustos.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-110: the scrub rule has to hold against processors that split on
 * Unicode line terminators and Unicode white space, not only on CR/LF and the
 * ASCII space. The assertions use exactly such processors —
 * {@link Scanner#nextLine()} and a {@code \s+} split under
 * {@link Pattern#UNICODE_CHARACTER_CLASS}.
 */
@DisplayName("LogFieldScrubber — Unicode separators (JS-SEC-110)")
class LogFieldScrubberTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");
  private static final Pattern UNICODE_WHITESPACE =
      Pattern.compile("\\s+", Pattern.UNICODE_CHARACTER_CLASS);

  /** Line terminators a Unicode-aware splitter honours: NEL, LS, PS, VT, FF and the C0 separators. */
  private static final int[] LINE_BREAKS =
      {0x0085, 0x2028, 0x2029, 0x000B, 0x000C, 0x001C, 0x001D, 0x001E, 0x000A, 0x000D};

  /** White space that is not U+0020: NBSP, Ogham space, the U+2000 block, NNBSP, MMSP, ideographic space. */
  private static final int[] SPACES =
      {0x00A0, 0x1680, 0x2000, 0x2003, 0x200A, 0x202F, 0x205F, 0x3000, 0x0009, 0x0020};

  /** Format characters: zero-width space/joiner, bidi overrides and isolates, BOM, a tag character. */
  private static final int[] FORMAT =
      {0x200B, 0x200D, 0x200E, 0x202A, 0x202E, 0x2066, 0x2069, 0xFEFF, 0x00AD, 0xE0001};

  private static String cp(int codePoint) {
    return new String(Character.toChars(codePoint));
  }

  private static List<String> lines(String text) {
    List<String> lines = new ArrayList<>();
    try (Scanner scanner = new Scanner(text)) {
      while (scanner.hasNextLine()) {
        lines.add(scanner.nextLine());
      }
    }
    return lines;
  }

  @Test
  @DisplayName("a value with any Unicode line terminator stays one line for java.util.Scanner")
  void lineTerminatorsCannotSplitALine() {
    for (int lineBreak : LINE_BREAKS) {
      String hostile = "alice" + cp(lineBreak) + "AUDIT LoginSucceeded user=admin";

      String line = "AUDIT LoginFailed user=" + LogFieldScrubber.scrub(hostile);

      assertEquals(1, lines(line).size(),
          "U+" + Integer.toHexString(lineBreak) + " split the record: " + lines(line));
      assertEquals("AUDIT LoginFailed user=alice?AUDIT?LoginSucceeded?user=admin", line);
    }
  }

  @Test
  @DisplayName("a value with any Unicode white space stays one field under a Unicode \\s+ split")
  void unicodeSpacesCannotForgeAField() {
    for (int space : SPACES) {
      String hostile = "alice" + cp(space) + "user=admin";

      String line = "AUDIT LoginFailed user=" + LogFieldScrubber.scrub(hostile) + " client=10.0.0.1";

      String[] fields = UNICODE_WHITESPACE.split(line);
      assertEquals(4, fields.length,
          "U+" + Integer.toHexString(space) + " forged a field: " + List.of(fields));
      assertEquals("user=alice?user=admin", fields[2]);
    }
  }

  @Test
  @DisplayName("format characters and unpaired surrogates are replaced")
  void formatCharactersAndLoneSurrogatesAreReplaced() {
    for (int format : FORMAT) {
      assertEquals("a?b", LogFieldScrubber.scrub("a" + cp(format) + "b"),
          "U+" + Integer.toHexString(format));
    }
    assertEquals("a?b", LogFieldScrubber.scrub("a" + (char) 0xD800 + "b"));
    assertEquals("a?b", LogFieldScrubber.scrub("a" + (char) 0xDC00 + "b"));
    assertEquals("a??b", LogFieldScrubber.scrub("a" + (char) 0xDC00 + (char) 0xD800 + "b"));
  }

  @Test
  @DisplayName("ordinary text, non-ASCII letters and supplementary characters pass unchanged")
  void harmlessValuesAreUntouched() {
    String emoji = cp(0x1F600);
    for (String value : List.of("alice", "user@example.org", "Zoë-Müller",
        "name=with=equals|pipe^caret", emoji + "x" + emoji, "")) {
      assertSame(value, LogFieldScrubber.scrub(value), "no allocation for a clean value");
      assertSame(value, LogFieldScrubber.scrubMessage(value));
    }
    assertNull(LogFieldScrubber.scrub(null));
    assertNull(LogFieldScrubber.scrubMessage(null));
  }

  @Test
  @DisplayName("scrubMessage keeps the plain space but nothing else that separates")
  void scrubMessageKeepsOnlyThePlainSpace() {
    assertEquals("field 'x' is too long", LogFieldScrubber.scrubMessage("field 'x' is too long"));
    for (int lineBreak : LINE_BREAKS) {
      String scrubbed = LogFieldScrubber.scrubMessage(
          "bad value" + cp(lineBreak) + "forged line");
      assertEquals("bad value?forged line", scrubbed, "U+" + Integer.toHexString(lineBreak));
      assertEquals(1, lines(scrubbed).size());
    }
    assertEquals("a?b", LogFieldScrubber.scrubMessage("a" + cp(0x00A0) + "b"));
    assertEquals("a?b", LogFieldScrubber.scrubMessage("a" + cp(0x202E) + "b"));
  }

  @Test
  @DisplayName("isLineUnsafe is the rule without the plain space")
  void lineUnsafePredicate() {
    assertFalse(LogFieldScrubber.isLineUnsafe(' '));
    assertFalse(LogFieldScrubber.isLineUnsafe('a'));
    assertFalse(LogFieldScrubber.isLineUnsafe(0x1F600));
    for (int unsafe : new int[]{0x000A, 0x0085, 0x2028, 0x2029, 0x00A0, 0x2003, 0x202E, 0xD800}) {
      assertTrue(LogFieldScrubber.isLineUnsafe(unsafe), "U+" + Integer.toHexString(unsafe));
    }
  }

  @Test
  @DisplayName("the AUDIT line of the logging sink cannot be split or extended through a user name")
  void auditLineHoldsAgainstUnicodeSeparators() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    String hostile = "x" + cp(0x2028) + "AUDIT LoginSucceeded user=admin" + cp(0x2003) + "user=root";

    new LoggingAuditSink(logger).accept(new LoginSucceeded(T0, hostile, "127.0.0.1", "S-1"));

    String line = logger.firstMessage();
    assertEquals(1, lines(line).size(), "the AUDIT record was split: " + lines(line));
    long userFields = UNICODE_WHITESPACE.splitAsStream(line)
        .filter(field -> field.startsWith("user=")).count();
    assertEquals(1, userFields, "exactly one user= field in: " + line);
    assertTrue(line.contains("user=x?AUDIT?LoginSucceeded?user=admin?user=root"), line);
  }
}
