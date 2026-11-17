/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.compromised;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The bounded loader of {@link LocalBlocklistCompromisedPasswordChecker}: an
 * operator-supplied list is read strictly, bounded while it is read, and folded
 * the same way as the candidate (NFKC + {@code Locale.ROOT} lower case).
 * Synthetic lists only; jCustos ships none.
 */
@DisplayName("Password blocklists — bounded loader and NFKC folding")
class LocalBlocklistLoaderTest {

  @TempDir
  Path dir;

  private static boolean listed(LocalBlocklistCompromisedPasswordChecker checker, String candidate) {
    return checker.check(SecretValue.ofString(candidate))
        instanceof CompromisedPasswordResult.Pwned;
  }

  @Test
  @DisplayName("a list file: comments, blank lines, CRLF, a byte order mark and surrounding whitespace")
  void loadsAFile() throws IOException {
    Path file = dir.resolve("common.txt");
    Files.writeString(file, "﻿# synthetic list for the test\r\n"
        + "password\r\n"
        + "\r\n"
        + "   letmein   \n"
        + "  # an indented comment\n"
        + "Sommer2026\r"
        + "trustno1", StandardCharsets.UTF_8);

    LocalBlocklistCompromisedPasswordChecker checker =
        LocalBlocklistCompromisedPasswordChecker.fromFile(file);

    assertEquals(4, checker.size(), "four entries: comments and blank lines are skipped");
    assertEquals(true, listed(checker, "password"), "first entry after the byte order mark");
    assertEquals(true, listed(checker, "LETMEIN"), "stripped and case-folded");
    assertEquals(true, listed(checker, "sommer2026"), "a lone CR ends a line");
    assertEquals(true, listed(checker, "trustno1"), "last line without a terminator");
    assertFalse(listed(checker, "# synthetic list for the test"), "a comment is no entry");
    assertFalse(listed(checker, "correct horse battery staple"));
  }

  @Test
  @DisplayName("the full-width spelling of a listed password is listed, on both sides of the comparison")
  void fullWidthVariantIsRecognised() {
    LocalBlocklistCompromisedPasswordChecker plainList =
        LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.of("password"));
    assertEquals(true, listed(plainList, "ＰＡＳＳＷＯＲＤ"),
        "full-width candidate against a plain entry");
    assertEquals(true, listed(plainList, "Ｐａｓｓｗｏｒｄ"));

    LocalBlocklistCompromisedPasswordChecker fullWidthList =
        LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.of("ｌｅｔｍｅｉｎ"));
    assertEquals(true, listed(fullWidthList, "LetMeIn"),
        "plain candidate against a full-width entry");

    LocalBlocklistCompromisedPasswordChecker constructed =
        new LocalBlocklistCompromisedPasswordChecker(List.of("ｑｗｅｒｔｙ"));
    assertEquals(true, listed(constructed, "QWERTY"),
        "the collection constructor folds the same way");
  }

  @Test
  @DisplayName("a file above MAX_FILE_BYTES is refused before it is read, with a fixed message")
  void fileAboveTheByteBoundIsRefused() throws IOException {
    Path file = dir.resolve("huge.txt");
    try (RandomAccessFile sparse = new RandomAccessFile(file.toFile(), "rw")) {
      sparse.setLength(LocalBlocklistCompromisedPasswordChecker.MAX_FILE_BYTES + 1L);
    }

    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromFile(file));

    assertEquals("blocklist/file-too-large: the blocklist file is larger than 67108864 bytes"
        + " (MAX_FILE_BYTES)", refused.getMessage());
  }

  @Test
  // A separate thread: the endless stream never checks for interrupts, so without the bound
  // the test must fail on time instead of hanging the build.
  @Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
  @DisplayName("a stream that delivers more than MAX_FILE_BYTES is refused while it is read")
  void streamAboveTheByteBoundIsRefused() {
    // Comment lines only, so nothing is kept: the byte bound trips, not the entry bound.
    byte[] commentLine = ("#" + "x".repeat(198) + "\n").getBytes(StandardCharsets.US_ASCII);
    InputStream endless = new InputStream() {
      private long position;

      @Override
      public int read() {
        return commentLine[(int) (position++ % commentLine.length)];
      }

      @Override
      public int read(byte[] b, int off, int len) {
        for (int i = 0; i < len; i++) {
          b[off + i] = commentLine[(int) (position++ % commentLine.length)];
        }
        return len;
      }
    };

    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromStream(endless));

    assertEquals("blocklist/file-too-large: the blocklist file is larger than 67108864 bytes"
        + " (MAX_FILE_BYTES)", refused.getMessage());
  }

  @Test
  @DisplayName("a line above MAX_LINE_LENGTH refuses the list; the message names the line, not its content")
  void lineAboveTheLengthBoundIsRefused() throws IOException {
    String tooLong = "s3cret-" + "y".repeat(LocalBlocklistCompromisedPasswordChecker.MAX_LINE_LENGTH);
    Path file = dir.resolve("long.txt");
    Files.writeString(file, "password\n" + "x".repeat(256) + "\n" + tooLong + "\n",
        StandardCharsets.UTF_8);

    IllegalArgumentException fromFile = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromFile(file));
    assertEquals("blocklist/line-too-long: line 3 of the blocklist is longer than 256 characters"
        + " (MAX_LINE_LENGTH)", fromFile.getMessage());
    assertFalse(fromFile.getMessage().contains("s3cret"), "the line itself is never repeated");

    IllegalArgumentException fromLines = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromLines(
            Stream.of("password", "x".repeat(256), tooLong)));
    assertEquals(fromFile.getMessage(), fromLines.getMessage());
  }

  @Test
  @DisplayName("more than MAX_ENTRIES entries refuse the list; duplicates count, comments and blanks do not")
  void entriesAboveTheBoundAreRefused() {
    int max = LocalBlocklistCompromisedPasswordChecker.MAX_ENTRIES;

    LocalBlocklistCompromisedPasswordChecker atTheBound = LocalBlocklistCompromisedPasswordChecker
        .fromLines(Stream.concat(Stream.of("# header", ""),
            IntStream.range(0, max).mapToObj(i -> "dragon")));
    assertEquals(1, atTheBound.size());

    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromLines(
            IntStream.rangeClosed(0, max).mapToObj(i -> "dragon")));
    assertEquals("blocklist/too-many-entries: the blocklist has more than 2000000 entries"
        + " (MAX_ENTRIES)", refused.getMessage());
  }

  @Test
  @DisplayName("a file that is not well-formed UTF-8 is refused as a whole")
  void malformedUtf8IsRefused() throws IOException {
    Path file = dir.resolve("latin1.txt");
    // "passwört" in ISO-8859-1: 0xF6 is no valid UTF-8 sequence here.
    Files.write(file, new byte[] {'p', 'a', 's', 's', 'w', (byte) 0xF6, 'r', 't', '\n'});

    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromFile(file));

    assertEquals("blocklist/not-utf-8: the blocklist file is not well-formed UTF-8",
        refused.getMessage());
  }

  @Test
  @DisplayName("an element with an unpaired surrogate refuses the lines")
  void unpairedSurrogateIsRefused() {
    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromLines(
            Stream.of("password", "abc\uD800def")));
    assertEquals("blocklist/malformed-line: line 2 of the blocklist contains an unpaired"
        + " surrogate", refused.getMessage());
  }

  @Test
  @DisplayName("a missing file is an IOException, not an empty list")
  void missingFileIsAnIoFailure() {
    assertThrows(IOException.class,
        () -> LocalBlocklistCompromisedPasswordChecker.fromFile(dir.resolve("absent.txt")));
  }

  @Test
  @DisplayName("an empty list lists nothing")
  void emptyListListsNothing() throws IOException {
    Path file = dir.resolve("empty.txt");
    Files.writeString(file, "# nothing yet\n\n", StandardCharsets.UTF_8);
    LocalBlocklistCompromisedPasswordChecker checker =
        LocalBlocklistCompromisedPasswordChecker.fromFile(file);
    assertEquals(0, checker.size());
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("password")));
    assertInstanceOf(CompromisedPasswordResult.Clean.class,
        LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.empty())
            .check(SecretValue.ofString("password")));
  }
}
