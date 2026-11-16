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
package eu.jsentinel.jcustos.util;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Turns a subject name as the client typed it into the one key every component uses for that
 * subject.
 *
 * <p>JS-SEC-123 (CWE-178): a throttle and the user store it protects must agree on which
 * spellings are the same account. When the login policy folds case but the credential store
 * compares exactly, {@code alice} and {@code ALICE} are two accounts that share one failure
 * counter - the owner of one resets the counter of the other. When the throttle keys the raw
 * spelling but the user store ignores case, every spelling gets a counter of its own. Both
 * shapes disappear once the same canonicaliser sits in front of the throttle <em>and</em> the
 * store.
 *
 * <p>The interface is deliberately a single function so an application whose user directory
 * follows other rules (case-sensitive names, e-mail addresses with a provider-specific local
 * part, a tenant prefix) supplies its own and hands the same instance to every component:
 * {@code InMemoryLoginAttemptPolicy}, {@code StoreBackedLoginAttemptPolicy} and
 * {@code InMemoryCredentialStore} accept one in their constructors.
 *
 * <p>Implementations must be pure, thread-safe and idempotent:
 * {@code canonicalize(canonicalize(x))} equals {@code canonicalize(x)}.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
@FunctionalInterface
public interface SubjectKeyCanonicalizer {

  /**
   * Longest name, in UTF-16 code units, that {@link #defaults()} normalises: {@value}. NFKC can
   * turn one character into eighteen (U+FDFA), so the canonical form of an unbounded name costs
   * time and memory far beyond its own length - and the throttle keeps up to 100 000 such keys.
   * A longer name is not normalised but mapped to a fixed-length key, see {@link #defaults()}.
   *
   * @since 00.84.00
   */
  int MAX_RAW_LENGTH = 256;

  /**
   * Prefix of the key {@link #defaults()} returns for a name longer than
   * {@link #MAX_RAW_LENGTH}: the prefix followed by the lower-case hexadecimal SHA-256 of the
   * name's UTF-8 bytes.
   *
   * @since 00.84.00
   */
  String OVERLONG_KEY_PREFIX = "overlong-sha256:";

  /**
   * Returns the canonical key for {@code raw}.
   *
   * @param raw the name as supplied; never {@code null}
   * @return the canonical key; never {@code null}
   */
  String canonicalize(String raw);

  /**
   * The default: Unicode NFKC, lower-case under {@link Locale#ROOT}, surrounding whitespace and
   * control characters removed. NFKC folds compatibility forms (full-width letters, ligatures,
   * the no-break space) onto their plain counterparts, so visually identical names share one
   * key; the second NFKC pass keeps the result stable for characters whose lower-case form
   * decomposes.
   *
   * <p>A name longer than {@link #MAX_RAW_LENGTH} is not normalised (JS-SEC-123, CWE-400,
   * CWE-770): its key is {@link #OVERLONG_KEY_PREFIX} followed by the SHA-256 of the name -
   * eighty characters, the same for the same name, different for different names, and a fixed
   * point of this canonicaliser. No registered name of normal length has such a key, so a
   * credential store answers "unknown user" and a throttle counts the name on a key of its own;
   * nothing throws.</p>
   *
   * @return the shared default canonicaliser
   */
  static SubjectKeyCanonicalizer defaults() {
    return SubjectKeyCanonicalizer::nfkcLowerTrim;
  }

  /**
   * Leaves the name untouched. For user directories that treat every spelling as a distinct
   * account - use it for the throttle and the store alike, never for one of the two.
   *
   * @return the identity canonicaliser
   */
  static SubjectKeyCanonicalizer exact() {
    return SubjectKeyCanonicalizer::unchanged;
  }

  private static String unchanged(String raw) {
    return raw;
  }

  private static String nfkcLowerTrim(String raw) {
    if (raw.length() > MAX_RAW_LENGTH) {
      return overlongKey(raw);
    }
    String folded = Normalizer.normalize(raw, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    String stable = Normalizer.normalize(folded, Normalizer.Form.NFKC);
    int from = 0;
    int to = stable.length();
    while (from < to && isPadding(stable.charAt(from))) {
      from++;
    }
    while (to > from && isPadding(stable.charAt(to - 1))) {
      to--;
    }
    return stable.substring(from, to);
  }

  /** JS-SEC-123 (CWE-400): a bounded key for a name too long to normalise. */
  private static String overlongKey(String raw) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(raw.getBytes(StandardCharsets.UTF_8));
      return OVERLONG_KEY_PREFIX + HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException missing) {
      // every Java platform must provide SHA-256
      throw new IllegalStateException("SHA-256 is not available", missing);
    }
  }

  /** What {@link String#trim()} removes plus Unicode whitespace it does not know. */
  private static boolean isPadding(char c) {
    return c <= ' ' || Character.isWhitespace(c) || Character.isSpaceChar(c);
  }
}
