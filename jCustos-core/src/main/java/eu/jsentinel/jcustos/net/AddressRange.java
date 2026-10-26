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
import java.util.Objects;

/**
 * An IP address or CIDR range used to describe trusted proxies, for example
 * {@code 127.0.0.1}, {@code 10.0.0.0/8}, {@code ::1} or {@code fd00::/8}.
 * IPv4 and IPv6 ranges never match addresses of the other family; an
 * IPv4-mapped IPv6 address is treated as IPv4.
 */
final class AddressRange {

  private final byte[] base;
  private final int prefixLength;
  private final String text;

  private AddressRange(byte[] base, int prefixLength, String text) {
    this.base = base;
    this.prefixLength = prefixLength;
    this.text = text;
  }

  /**
   * Parses an address or CIDR range.
   *
   * @param text address literal, optionally followed by {@code /prefix}
   * @return the range
   * @throws IllegalArgumentException when the text is not an IP literal or the prefix is out of range
   */
  static AddressRange parse(String text) {
    Objects.requireNonNull(text, "text");
    String trimmed = text.trim();
    int slash = trimmed.indexOf('/');
    String addressPart = slash < 0 ? trimmed : trimmed.substring(0, slash);
    InetAddress address = IpLiterals.parse(addressPart)
        .orElseThrow(() -> new IllegalArgumentException(
            "trusted proxy '" + trimmed + "' is not an IP address or CIDR range"));
    byte[] bytes = address.getAddress();
    int bits = bytes.length * 8;
    int prefix = bits;
    if (slash >= 0) {
      try {
        prefix = Integer.parseInt(trimmed.substring(slash + 1).trim());
      } catch (NumberFormatException malformed) {
        throw new IllegalArgumentException(
            "trusted proxy '" + trimmed + "' has a malformed prefix length");
      }
      if (prefix < 0 || prefix > bits) {
        throw new IllegalArgumentException(
            "trusted proxy '" + trimmed + "' has a prefix length outside 0.." + bits);
      }
    }
    return new AddressRange(bytes, prefix, trimmed);
  }

  /**
   * @param address candidate
   * @return {@code true} when the first {@code prefixLength} bits match
   */
  boolean contains(InetAddress address) {
    byte[] candidate = address.getAddress();
    if (candidate.length != base.length) {
      return false;
    }
    int fullBytes = prefixLength / 8;
    for (int i = 0; i < fullBytes; i++) {
      if (candidate[i] != base[i]) {
        return false;
      }
    }
    int remainingBits = prefixLength % 8;
    if (remainingBits == 0) {
      return true;
    }
    int mask = 0xFF << (8 - remainingBits);
    return (candidate[fullBytes] & mask) == (base[fullBytes] & mask);
  }

  @Override
  public String toString() {
    return text;
  }
}
