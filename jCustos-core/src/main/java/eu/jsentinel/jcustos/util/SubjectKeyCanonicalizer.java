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

import java.text.Normalizer;
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

  /** What {@link String#trim()} removes plus Unicode whitespace it does not know. */
  private static boolean isPadding(char c) {
    return c <= ' ' || Character.isWhitespace(c) || Character.isSpaceChar(c);
  }
}
