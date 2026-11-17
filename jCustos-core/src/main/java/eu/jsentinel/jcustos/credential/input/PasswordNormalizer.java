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
package eu.jsentinel.jcustos.credential.input;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.nio.CharBuffer;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * Normalises password material under the active
 * {@link PasswordInputPolicy} so that two equivalent Unicode
 * representations of the same characters compare equal across
 * hash/verify (CWE-176).
 *
 * <h2>JVM memory honesty</h2>
 * <p>The JDK's {@link Normalizer#normalize(CharSequence, Normalizer.Form)}
 * returns a {@link String}. {@code String} instances are immutable and
 * may be retained by the JVM. The normalizer copies that String into a
 * fresh {@link SecretValue} and discards the reference, but a brief
 * window remains where the normalised material lives in a String
 * object. This is the same caveat documented on {@link SecretValue};
 * see CWE-226.</p>
 *
 * <p>Pre-hashing of overlong inputs is intentionally not performed
 * here. The Konzept §11 forbids silent pre-hashing without a real
 * pepper service (password shucking risk); the bcrypt provider rejects
 * overlong inputs explicitly.</p>
 *
 * <h2>Comparison form</h2>
 * <p>{@link #comparisonForm(CharSequence)} is the one folding under which a
 * candidate password and the entries of a local blocklist are compared
 * (since 00.84.00): NFKC, then lower case under {@link Locale#ROOT}. It is
 * deliberately coarser than the hashing normalisation, so that the full-width
 * {@code ＰＡＳＳＷＯＲＤ} or a ligature spelling of a listed password is found
 * in the list (CWE-176, CWE-521). It is used for comparison only, never for the
 * secret that is hashed.</p>
 */
public final class PasswordNormalizer {

  /** Unicode form of {@link #comparisonForm(CharSequence)}. */
  private static final Normalizer.Form COMPARISON_FORM = Normalizer.Form.NFKC;

  public PasswordNormalizer() {
  }

  /**
   * Returns the form under which a password is compared with a blocklist
   * entry: Unicode NFKC, then lower case under {@link Locale#ROOT}. Both sides
   * of the comparison - every list entry when the list is loaded, and the
   * candidate when it is checked - pass through this method, so equivalent
   * spellings meet (CWE-176).
   *
   * <p>The result is a {@link String}: callers that compare passwords accept
   * the JVM-memory caveat documented on the class. Whitespace is not trimmed
   * here; that is the caller's decision.</p>
   *
   * @param value the text to fold; non-null
   * @return the comparison form
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static String comparisonForm(CharSequence value) {
    Objects.requireNonNull(value, "value");
    return Normalizer.normalize(value, COMPARISON_FORM).toLowerCase(Locale.ROOT);
  }

  /**
   * Returns a new {@link SecretValue} containing the normalised form.
   * The input is left intact (callers are usually mid-pipeline and
   * close their own secret in a try-with-resources block).
   */
  public SecretValue normalize(SecretValue input, PasswordInputPolicy policy) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(policy, "policy");
    if (!policy.unicodeNormalisationEnabled()) {
      // JS-SEC-047 (CWE-226): input.asChars() returns a fresh plaintext copy that ofChars copies
      // again; zero this transient in a finally block, mirroring the enabled branch below, so the
      // class honours its own "zero every temporary it constructs" contract.
      char[] passthrough = input.asChars();
      try {
        return SecretValue.ofChars(passthrough);
      } finally {
        Arrays.fill(passthrough, '\0');
      }
    }
    char[] chars = input.asChars();
    char[] normalisedChars = null;
    try {
      CharBuffer wrapped = CharBuffer.wrap(chars);
      String normalised = Normalizer.normalize(wrapped, policy.normalisationForm());
      normalisedChars = normalised.toCharArray();
      return SecretValue.ofChars(normalisedChars);
    } finally {
      Arrays.fill(chars, '\0');
      if (normalisedChars != null) {
        Arrays.fill(normalisedChars, '\0');
      }
    }
  }
}
