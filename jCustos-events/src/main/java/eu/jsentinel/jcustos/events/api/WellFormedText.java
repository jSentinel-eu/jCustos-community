package eu.jsentinel.jcustos.events.api;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Well-formedness check for text that is going to be signed, hashed or
 * transported as UTF-8 (JS-SEC-111, CWE-176).
 *
 * <p>A Java string is a sequence of UTF-16 code units and may contain a
 * surrogate without its partner. Such a string has no UTF-8 encoding:
 * {@code String.getBytes(UTF_8)} silently writes {@code '?'} in its place, so
 * two different strings yield the same bytes — and the same signature. Text
 * that enters a signature base therefore has to be checked, not encoded
 * leniently.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class WellFormedText {

  private WellFormedText() {
  }

  /**
   * @param text the text to check
   * @return {@code true} if every surrogate in {@code text} is part of a
   *     high-low pair, i.e. the text has exactly one UTF-8 encoding
   */
  public static boolean isWellFormed(CharSequence text) {
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (Character.isHighSurrogate(c) && i + 1 < text.length()
          && Character.isLowSurrogate(text.charAt(i + 1))) {
        i++;
      } else if (Character.isSurrogate(c)) {
        return false;
      }
    }
    return true;
  }
}
