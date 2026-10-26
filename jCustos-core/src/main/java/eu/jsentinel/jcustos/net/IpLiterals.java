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
package eu.jsentinel.jcustos.net;

import java.net.InetAddress;
import java.util.Optional;

/**
 * Strict IP-literal parsing without name resolution. Accepts the textual
 * forms that appear in peer addresses and {@code X-Forwarded-For} entries:
 * {@code 203.0.113.5}, {@code 203.0.113.5:4711}, {@code 2001:db8::1},
 * {@code [2001:db8::1]} and {@code [2001:db8::1]:4711}. Anything that is not
 * such a literal, hostnames in particular, parses to empty.
 */
final class IpLiterals {

  private IpLiterals() {
  }

  /**
   * Parses an IP literal.
   *
   * @param text candidate, may be {@code null}
   * @return the address, or empty when {@code text} is not an IP literal
   */
  static Optional<InetAddress> parse(String text) {
    if (text == null) {
      return Optional.empty();
    }
    String literal = stripPort(text.trim());
    if (literal.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(InetAddress.ofLiteral(literal));
    } catch (IllegalArgumentException notALiteral) {
      return Optional.empty();
    }
  }

  private static String stripPort(String text) {
    if (text.startsWith("[")) {
      int close = text.indexOf(']');
      return close < 0 ? text : text.substring(1, close);
    }
    int firstColon = text.indexOf(':');
    if (firstColon >= 0 && firstColon == text.lastIndexOf(':')) {
      // exactly one colon: IPv4 with a port suffix
      return text.substring(0, firstColon);
    }
    return text;
  }
}
