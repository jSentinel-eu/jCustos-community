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

/**
 * Single home for neutralizing attacker-influenced values before they are written into a
 * space-separated {@code key=value} log/audit line (CWE-117 log injection).
 *
 * <p>JS-SEC-045 (exit-review of JS-SEC-031 / RF09): the scrub existed as three divergent private
 * copies ({@code LoggingAuditSink}, {@code RestAccessContextFactory}, and — missing entirely —
 * {@code LoggingNotificationSender}), which drift. This is the one canonical, RF09-hardened
 * variant: it replaces every ISO control char <em>and</em> the {@code 0x20} space field-delimiter
 * with {@code '?'}, so a value can forge neither a second log line (CR/LF) nor a second
 * {@code key=value} token (space) that a whitespace-splitting SIEM would attribute elsewhere.
 * Identifiers carried in these lines (user / client / session / route / tenant) have no semantic
 * need for embedded control chars or spaces.
 *
 * <p>JS-SEC-110 (CWE-117, CWE-93): the rule now covers Unicode as well. A downstream processor
 * that splits on Unicode line terminators ({@code java.util.Scanner.nextLine()}, the regex
 * {@code \R}, Python's {@code str.splitlines()}) or on Unicode white space saw U+0085, U+2028,
 * U+2029 and the non-ASCII spaces (U+00A0, U+1680, U+2000–U+200A, U+202F, U+205F, U+3000) as
 * separators although the former ISO-control-plus-space rule let them through. Format characters
 * (category {@code Cf}: bidirectional controls, zero-width characters, the byte-order mark) and
 * unpaired surrogates are replaced too — they reorder or hide text in a viewer, or turn into
 * another character once the line is encoded.
 */
public final class LogFieldScrubber {

  private static final char REPLACEMENT = '?';

  private LogFieldScrubber() {
  }

  /**
   * Replaces every character that can act as a line or field separator in {@code value} with
   * {@code '?'}: ISO control characters, every Unicode white-space and space character (the
   * {@code 0x20} delimiter included), line and paragraph separators, format characters and
   * unpaired surrogates. Only allocates when a disallowed character is actually present; a
   * {@code null} value is returned as-is.
   *
   * @param value the raw field value (may be {@code null})
   * @return the scrubbed value, safe to place into a space-separated {@code key=value} line
   */
  public static String scrub(String value) {
    return replace(value, true);
  }

  /**
   * Variant of {@link #scrub(String)} for free text such as an exception message: it keeps the
   * plain {@code 0x20} space, so the text stays readable, and replaces everything else
   * {@link #scrub(String)} replaces. The result is one line, but not one field — never use it
   * for a value inside a space-separated {@code key=value} line.
   *
   * @param value the raw text (may be {@code null})
   * @return the text as a single line without control, separator or format characters
   * @since 00.84.00
   */
  public static String scrubMessage(String value) {
    return replace(value, false);
  }

  /**
   * Tells whether a code point must never reach a line-oriented log or export record unescaped,
   * independently of the field delimiter in use: ISO control characters, every Unicode white-space
   * or space character other than the plain {@code 0x20} space, line and paragraph separators,
   * format characters and surrogate code points (which only occur unpaired when a string is
   * walked by code point). Formatters with their own escaping rules — where replacing the space
   * would be wrong — use this predicate to decide what to escape.
   *
   * @param codePoint the code point to test
   * @return {@code true} if the code point can split, reorder or hide a record
   * @since 00.84.00
   */
  public static boolean isLineUnsafe(int codePoint) {
    if (codePoint == ' ') {
      return false;
    }
    if (Character.isISOControl(codePoint) || Character.isWhitespace(codePoint)
        || Character.isSpaceChar(codePoint)) {
      return true;
    }
    int type = Character.getType(codePoint);
    return type == Character.FORMAT || type == Character.SURROGATE;
  }

  private static String replace(String value, boolean replaceSpace) {
    if (value == null) {
      return null;
    }
    StringBuilder out = null;
    int i = 0;
    while (i < value.length()) {
      int codePoint = value.codePointAt(i);
      int width = Character.charCount(codePoint);
      if (isLineUnsafe(codePoint) || (replaceSpace && codePoint == ' ')) {
        if (out == null) {
          out = new StringBuilder(value.length());
          out.append(value, 0, i);
        }
        out.append(REPLACEMENT);
      } else if (out != null) {
        out.appendCodePoint(codePoint);
      }
      i += width;
    }
    return out == null ? value : out.toString();
  }
}
