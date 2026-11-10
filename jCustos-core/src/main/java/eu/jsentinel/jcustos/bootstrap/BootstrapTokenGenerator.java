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
package eu.jsentinel.jcustos.bootstrap;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;

/**
 * Generates fresh {@link BootstrapToken}s using {@link SecureRandom} and a
 * 32-character ambiguity-free alphabet (drops {@code O 0 I 1}). Token shape
 * is {@code XXXX-XXXX-XXXX-XXXX-XXXX} which yields ~100 bits of entropy.
 */
public final class BootstrapTokenGenerator {

  private static final char[] ALPHABET =
      "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
  private static final int GROUPS = 5;
  private static final int GROUP_LENGTH = 4;

  private final SecureRandom random;
  private final Clock clock;

  public BootstrapTokenGenerator() {
    this(new SecureRandom(), Clock.systemUTC());
  }

  public BootstrapTokenGenerator(SecureRandom random, Clock clock) {
    this.random = random;
    this.clock = clock;
  }

  public BootstrapToken generate() {
    StringBuilder sb = new StringBuilder(GROUPS * (GROUP_LENGTH + 1) - 1);
    for (int g = 0; g < GROUPS; g++) {
      if (g > 0) sb.append('-');
      for (int i = 0; i < GROUP_LENGTH; i++) {
        sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
      }
    }
    return new BootstrapToken(sb.toString(), Instant.now(clock));
  }

  /**
   * Tells whether {@code value} has the shape this generator produces:
   * five groups of four characters from the generator's alphabet, separated
   * by {@code '-'}. Used to refuse a token
   * file whose content was not written by the framework (JS-SEC-130, CWE-345).
   *
   * @param value candidate token value; {@code null} is not well-formed
   * @return whether the value could have been generated here
   * @since 00.84.00
   */
  public static boolean isWellFormed(String value) {
    if (value == null || value.length() != GROUPS * (GROUP_LENGTH + 1) - 1) {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      boolean separatorPosition = i % (GROUP_LENGTH + 1) == GROUP_LENGTH;
      if (separatorPosition ? c != '-' : !inAlphabet(c)) {
        return false;
      }
    }
    return true;
  }

  private static boolean inAlphabet(char c) {
    for (char allowed : ALPHABET) {
      if (allowed == c) {
        return true;
      }
    }
    return false;
  }
}
