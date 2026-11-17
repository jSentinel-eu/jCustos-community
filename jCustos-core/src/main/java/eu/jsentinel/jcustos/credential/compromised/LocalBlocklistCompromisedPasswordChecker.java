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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.input.PasswordNormalizer;
import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Offline {@link CompromisedPasswordChecker} backed by an operator-
 * supplied blocklist.
 *
 * <p>Every entry is held in its comparison form
 * ({@link PasswordNormalizer#comparisonForm(CharSequence)}: Unicode NFKC, then
 * lower case under {@code Locale.ROOT}, surrounding whitespace stripped) in a
 * {@link Set} of strings, and the candidate is folded the same way before the
 * lookup. Case variants of a listed password are therefore listed too, as NIST
 * SP 800-63B advises, and so are compatibility spellings such as the full-width
 * {@code ｐａｓｓｗｏｒｄ} (since 00.84.00; up to 00.83.00 only the case was folded
 * and only the entries were trimmed). The blocklist exists only in memory —
 * never logged, never serialised.</p>
 *
 * <h2>Providing a list</h2>
 * <p>jCustos ships no list: the operator chooses one, checks its licence and
 * keeps it current. {@link #fromFile(Path)} loads a UTF-8 text file with one
 * password per line; blank lines and lines that start with {@code #} are
 * skipped. Suitable sources are lists of the most common passwords - for
 * example the "Pwned Passwords top 100 000" list published by the UK NCSC, or
 * the {@code Passwords/Common-Credentials} files of the SecLists collection -
 * extended by terms of the deployment itself: the product and company name,
 * the city, the service's domain. Breach corpora that are distributed as hashes
 * (the downloadable HaveIBeenPwned data) cannot be loaded here; the online
 * range query of {@code jCustos-credentials-hibp} covers them, and
 * {@link CompositeCompromisedPasswordChecker} asks the local list first and the
 * online service second.</p>
 *
 * <p>A loaded list is bounded (CWE-400, CWE-770): at most
 * {@value #MAX_FILE_BYTES} bytes ({@link #MAX_FILE_BYTES}), {@value #MAX_ENTRIES}
 * entries ({@link #MAX_ENTRIES}) and {@value #MAX_LINE_LENGTH} characters per
 * line ({@link #MAX_LINE_LENGTH}). A list that exceeds a bound, or a file that
 * is not well-formed UTF-8, is refused as a whole with an
 * {@link IllegalArgumentException} whose message names the bound and, where it
 * applies, the line number - never the content of a line. Nothing is loaded
 * partially.</p>
 *
 * <p>This implementation copies the candidate password into a temporary
 * folded {@link String} for the {@link Set#contains} call and
 * does not retain it. Callers that consider this trade-off
 * unacceptable can wrap with their own hash-only blocklist.</p>
 */
public final class LocalBlocklistCompromisedPasswordChecker
    implements CompromisedPasswordChecker {

  /**
   * Largest file, in bytes, that {@link #fromFile(Path)} reads: 64 MiB.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final long MAX_FILE_BYTES = 64L * 1024L * 1024L;

  /**
   * Most entries - lines that are neither blank nor comments, duplicates
   * included - that {@link #fromFile(Path)} and {@link #fromLines(Stream)}
   * accept: 2 000 000.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final int MAX_ENTRIES = 2_000_000;

  /**
   * Longest line, in UTF-16 characters and before whitespace is stripped, that
   * {@link #fromFile(Path)} and {@link #fromLines(Stream)} accept: 256.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static final int MAX_LINE_LENGTH = 256;

  /** Error code of a file above {@link #MAX_FILE_BYTES}; starts the exception message. */
  static final String ERROR_FILE_TOO_LARGE = "blocklist/file-too-large";
  /** Error code of a list with more than {@link #MAX_ENTRIES} entries. */
  static final String ERROR_TOO_MANY_ENTRIES = "blocklist/too-many-entries";
  /** Error code of a line longer than {@link #MAX_LINE_LENGTH}. */
  static final String ERROR_LINE_TOO_LONG = "blocklist/line-too-long";
  /** Error code of a file that is not well-formed UTF-8. */
  static final String ERROR_NOT_UTF8 = "blocklist/not-utf-8";
  /** Error code of a line with an unpaired surrogate. */
  static final String ERROR_MALFORMED_LINE = "blocklist/malformed-line";

  /** First character of a comment line. */
  private static final char COMMENT = '#';
  /** A byte order mark at the start of a file is not part of the first entry. */
  private static final char BYTE_ORDER_MARK = '﻿';
  private static final int READ_BUFFER_CHARS = 8192;

  private final Set<String> blocklist;

  /**
   * @param entries blocklist entries; each is stripped of surrounding
   *                whitespace and folded into its comparison form. Blank and
   *                {@code null} entries are skipped; no entry is read as a
   *                comment, and the bounds of a loaded list do not apply.
   */
  public LocalBlocklistCompromisedPasswordChecker(Collection<String> entries) {
    Objects.requireNonNull(entries, "entries");
    Set<String> folded = new HashSet<>();
    for (String entry : entries) {
      if (entry == null) {
        continue;
      }
      String stripped = entry.strip();
      if (!stripped.isEmpty()) {
        folded.add(PasswordNormalizer.comparisonForm(stripped));
      }
    }
    this.blocklist = Collections.unmodifiableSet(folded);
  }

  private LocalBlocklistCompromisedPasswordChecker(Set<String> folded) {
    this.blocklist = Collections.unmodifiableSet(folded);
  }

  /**
   * Loads a blocklist from a UTF-8 text file: one password per line, lines
   * separated by {@code \n}, {@code \r\n} or {@code \r}. Surrounding whitespace
   * of a line is stripped; blank lines and lines that then start with
   * {@code #} are skipped; a byte order mark at the start is ignored.
   *
   * <p>The file is decoded strictly: a malformed or truncated UTF-8 sequence
   * refuses the file. It must not be larger than {@link #MAX_FILE_BYTES}, hold
   * more than {@link #MAX_ENTRIES} entries or a line longer than
   * {@link #MAX_LINE_LENGTH} characters. The bounds are checked while the file
   * is read, so a file that grows while it is loaded, or a device that never
   * ends, is refused as well.</p>
   *
   * @param file the list; non-null
   * @return a checker over the folded entries
   * @throws IOException              if the file cannot be read
   * @throws IllegalArgumentException if the file exceeds a bound or is not
   *                                  well-formed UTF-8; the message starts with
   *                                  {@code blocklist/file-too-large},
   *                                  {@code blocklist/too-many-entries},
   *                                  {@code blocklist/line-too-long} or
   *                                  {@code blocklist/not-utf-8} and never
   *                                  contains a line of the list
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static LocalBlocklistCompromisedPasswordChecker fromFile(Path file) throws IOException {
    Objects.requireNonNull(file, "file");
    if (Files.size(file) > MAX_FILE_BYTES) {
      throw fileTooLarge();
    }
    return fromStream(Files.newInputStream(file));
  }

  /**
   * Reads, decodes and loads {@code raw} under the bounds of
   * {@link #fromFile(Path)}, the byte bound counted while reading; closes it.
   */
  static LocalBlocklistCompromisedPasswordChecker fromStream(InputStream raw) throws IOException {
    CharsetDecoder strictUtf8 = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT);
    Loader loader = new Loader();
    try (raw;
         Reader reader = new InputStreamReader(new BoundedInputStream(raw), strictUtf8)) {
      char[] buffer = new char[READ_BUFFER_CHARS];
      try {
        int read;
        while ((read = reader.read(buffer)) >= 0) {
          for (int i = 0; i < read; i++) {
            loader.accept(buffer[i]);
          }
        }
      } catch (CharacterCodingException malformed) {
        // No line number: the reader decodes ahead, so the line count lags behind
        // the bad sequence. Neither the bytes nor anything read before them are
        // repeated.
        throw new IllegalArgumentException(ERROR_NOT_UTF8
            + ": the blocklist file is not well-formed UTF-8");
      } finally {
        Arrays.fill(buffer, '\0');
      }
    }
    loader.finish();
    return new LocalBlocklistCompromisedPasswordChecker(loader.entries);
  }

  /**
   * Builds a blocklist from lines that the caller has already read - one
   * password per element. The rules of {@link #fromFile(Path)} apply to every
   * element, except the file-size bound and the UTF-8 decoding: surrounding
   * whitespace is stripped, blank elements and comments starting with
   * {@code #} are skipped, {@code null} elements are skipped, at most
   * {@link #MAX_ENTRIES} entries and {@link #MAX_LINE_LENGTH} characters per
   * element are accepted, and an element with an unpaired surrogate refuses
   * the list.
   *
   * <p>The stream is consumed but not closed; the caller closes it.</p>
   *
   * @param lines the lines; non-null
   * @return a checker over the folded entries
   * @throws IllegalArgumentException if the lines exceed a bound or one of them
   *                                  is malformed; the message starts with
   *                                  {@code blocklist/too-many-entries},
   *                                  {@code blocklist/line-too-long} or
   *                                  {@code blocklist/malformed-line} and never
   *                                  contains a line of the list
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static LocalBlocklistCompromisedPasswordChecker fromLines(Stream<String> lines) {
    Objects.requireNonNull(lines, "lines");
    Loader loader = new Loader();
    Iterator<String> iterator = lines.iterator();
    while (iterator.hasNext()) {
      String line = iterator.next();
      if (line != null) {
        loader.addLine(line);
      }
      loader.nextLine();
    }
    return new LocalBlocklistCompromisedPasswordChecker(loader.entries);
  }

  /** Number of distinct folded entries. */
  int size() {
    return blocklist.size();
  }

  @Override
  public CompromisedPasswordResult check(SecretValue password) {
    Objects.requireNonNull(password, "password");
    char[] chars = password.asChars();
    try {
      // The same folding as the entries (NFKC + Locale.ROOT lower case): the
      // full-width or upper-case spelling of a listed password is listed too.
      String candidate = PasswordNormalizer.comparisonForm(CharBuffer.wrap(chars));
      try {
        if (blocklist.contains(candidate)) {
          return new CompromisedPasswordResult.Pwned(1L);
        }
        return CompromisedPasswordResult.Clean.INSTANCE;
      } finally {
        // best-effort zeroing of the folded string's char[] is
        // impossible — String is immutable. The original char[] is
        // wiped below, which is the boundary we actually control.
        candidate = null;
      }
    } finally {
      Arrays.fill(chars, '\0');
    }
  }

  private static IllegalArgumentException fileTooLarge() {
    return new IllegalArgumentException(ERROR_FILE_TOO_LARGE
        + ": the blocklist file is larger than " + MAX_FILE_BYTES + " bytes (MAX_FILE_BYTES)");
  }

  /**
   * Splits decoded text into lines, enforces the bounds and folds the entries.
   * Holds at most one line of at most {@link #MAX_LINE_LENGTH} characters
   * besides the entries.
   */
  private static final class Loader {
    private final Set<String> entries = new HashSet<>();
    private final StringBuilder line = new StringBuilder(MAX_LINE_LENGTH);
    private long lineNumber = 1L;
    private int entryCount;
    private boolean afterCarriageReturn;

    /** One decoded character of a file. */
    void accept(char c) {
      if (c == '\n' && afterCarriageReturn) {
        // the second half of \r\n: the line ended at the \r
        afterCarriageReturn = false;
        return;
      }
      afterCarriageReturn = c == '\r';
      if (c == '\n' || c == '\r') {
        endFileLine();
        return;
      }
      if (line.length() >= MAX_LINE_LENGTH) {
        line.setLength(0);
        throw lineTooLong();
      }
      line.append(c);
    }

    /** The end of the file: a last line without a terminator still counts. */
    void finish() {
      if (!line.isEmpty()) {
        endFileLine();
      }
    }

    private void endFileLine() {
      String text = line.toString();
      line.setLength(0);
      addLine(text);
      nextLine();
    }

    void nextLine() {
      lineNumber++;
    }

    /** One complete line; checks the bounds, skips blanks and comments, folds the rest. */
    void addLine(String raw) {
      if (raw.length() > MAX_LINE_LENGTH) {
        throw lineTooLong();
      }
      if (hasUnpairedSurrogate(raw)) {
        throw new IllegalArgumentException(ERROR_MALFORMED_LINE + ": line " + lineNumber
            + " of the blocklist contains an unpaired surrogate");
      }
      String text = lineNumber == 1L && !raw.isEmpty() && raw.charAt(0) == BYTE_ORDER_MARK
          ? raw.substring(1) : raw;
      String stripped = text.strip();
      if (stripped.isEmpty() || stripped.charAt(0) == COMMENT) {
        return;
      }
      entryCount++;
      if (entryCount > MAX_ENTRIES) {
        throw new IllegalArgumentException(ERROR_TOO_MANY_ENTRIES
            + ": the blocklist has more than " + MAX_ENTRIES + " entries (MAX_ENTRIES)");
      }
      entries.add(PasswordNormalizer.comparisonForm(stripped));
    }

    private IllegalArgumentException lineTooLong() {
      return new IllegalArgumentException(ERROR_LINE_TOO_LONG + ": line " + lineNumber
          + " of the blocklist is longer than " + MAX_LINE_LENGTH
          + " characters (MAX_LINE_LENGTH)");
    }

    private static boolean hasUnpairedSurrogate(String text) {
      for (int i = 0; i < text.length(); i++) {
        char c = text.charAt(i);
        if (Character.isHighSurrogate(c)) {
          if (i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1))) {
            return true;
          }
          i++;
        } else if (Character.isLowSurrogate(c)) {
          return true;
        }
      }
      return false;
    }
  }

  /**
   * Refuses to deliver more than {@link #MAX_FILE_BYTES} bytes: the size check
   * before the read does not hold for a file that grows, or for a device.
   */
  private static final class BoundedInputStream extends FilterInputStream {
    private long remaining = MAX_FILE_BYTES;

    BoundedInputStream(InputStream in) {
      super(in);
    }

    @Override
    public int read() throws IOException {
      int b = super.read();
      if (b >= 0) {
        consume(1L);
      }
      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int n = in.read(b, off, len);
      if (n > 0) {
        consume(n);
      }
      return n;
    }

    private void consume(long n) {
      remaining -= n;
      if (remaining < 0L) {
        throw fileTooLarge();
      }
    }
  }
}
