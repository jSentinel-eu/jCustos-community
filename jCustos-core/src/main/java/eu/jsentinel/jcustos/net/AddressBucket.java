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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * The bucket in which a counter keyed on client addresses counts an address (JS-SEC-062,
 * CWE-307): the address counter of the login policies.
 *
 * <p>An IPv6 host is usually given a whole prefix - a /64 through SLAAC and privacy extensions,
 * a mobile device, a customer LAN - and can pick a new source address within it for every
 * request. A counter keyed on the exact address never sees two attempts from such a host.
 * {@link #of(String, int)} maps every address of one prefix onto the same text:
 *
 * <ul>
 *   <li>an IPv6 literal becomes its network prefix of {@code ipv6PrefixLength} bits, written in
 *       the canonical form of RFC 5952 (lower case, no leading zeros, the longest run of two or
 *       more zero groups as {@code ::}) with the length appended: {@code 2001:db8:1:2:a:b:c:d}
 *       with 64 becomes {@code 2001:db8:1:2::/64}, with 128 {@code 2001:db8:1:2:a:b:c:d/128};</li>
 *   <li>an IPv4 literal stays exact, in dotted-decimal form: {@code 203.0.113.5}. An
 *       IPv4-mapped IPv6 address ({@code ::ffff:203.0.113.5}) is the same IPv4 address;</li>
 *   <li>a port and the brackets of {@code [2001:db8::1]:4711} or {@code 203.0.113.5:4711} are
 *       dropped, as the client-address resolvers drop them;</li>
 *   <li>anything else - a host name, an IPv6 address with a named zone, text that is no IP
 *       literal - is trimmed and lower-cased and otherwise kept: one exact bucket, as before
 *       the prefix existed.</li>
 * </ul>
 *
 * <p>The result depends on the text and the length alone - no name resolution, no clock, no
 * state - so every node and every policy that applies the same length derives the same bucket.
 * Addresses that embed an IPv4 address in their low bits (NAT64 {@code 64:ff9b::/96}, Teredo
 * {@code 2001::/32}, the deprecated IPv4-compatible {@code ::a.b.c.d}) are IPv6 literals and
 * share the bucket of their prefix like any other.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class AddressBucket {

  /** Number of bits of an IPv6 address, the longest prefix: {@value}. */
  public static final int IPV6_BITS = 128;

  private static final int IPV6_GROUPS = 8;

  private AddressBucket() {
  }

  /**
   * The bucket of {@code clientAddress}; see the type description.
   *
   * @param clientAddress    the client address as an adapter or resolver reports it; non-null
   * @param ipv6PrefixLength bits of an IPv6 address that identify its bucket, from 0 to
   *                         {@value #IPV6_BITS}; IPv4 addresses are always exact
   * @return the bucket, a stable text
   * @throws IllegalArgumentException when {@code ipv6PrefixLength} is outside 0 to
   *                                  {@value #IPV6_BITS}
   */
  public static String of(String clientAddress, int ipv6PrefixLength) {
    Objects.requireNonNull(clientAddress, "clientAddress");
    if (ipv6PrefixLength < 0 || ipv6PrefixLength > IPV6_BITS) {
      throw new IllegalArgumentException("ipv6PrefixLength must be between 0 and " + IPV6_BITS
          + ": " + ipv6PrefixLength);
    }
    Optional<InetAddress> literal = IpLiterals.parse(clientAddress);
    if (literal.isEmpty()) {
      return clientAddress.trim().toLowerCase(Locale.ROOT);
    }
    InetAddress address = literal.get();
    if (address instanceof Inet4Address) {
      // the JDK already returns an Inet4Address for an IPv4-mapped IPv6 literal
      return address.getHostAddress();
    }
    byte[] bytes = address.getAddress();
    for (int i = 0; i < bytes.length; i++) {
      int bitsKept = Math.clamp(ipv6PrefixLength - i * 8L, 0, 8);
      bytes[i] = (byte) (bytes[i] & (0xFF << (8 - bitsKept)));
    }
    return canonicalIpv6(bytes) + "/" + ipv6PrefixLength;
  }

  /** RFC 5952, section 4: the canonical text of a 16-byte IPv6 address. */
  private static String canonicalIpv6(byte[] bytes) {
    int[] groups = new int[IPV6_GROUPS];
    for (int i = 0; i < IPV6_GROUPS; i++) {
      groups[i] = ((bytes[2 * i] & 0xFF) << 8) | (bytes[2 * i + 1] & 0xFF);
    }
    // the longest run of at least two zero groups; the first one when two runs are equally long
    int runStart = -1;
    int runLength = 1;
    int i = 0;
    while (i < IPV6_GROUPS) {
      if (groups[i] != 0) {
        i++;
        continue;
      }
      int end = i;
      while (end < IPV6_GROUPS && groups[end] == 0) {
        end++;
      }
      if (end - i > runLength) {
        runStart = i;
        runLength = end - i;
      }
      i = end;
    }
    StringBuilder text = new StringBuilder(39);
    int group = 0;
    while (group < IPV6_GROUPS) {
      if (group == runStart) {
        text.append("::");
        group += runLength;
        continue;
      }
      if (!text.isEmpty() && text.charAt(text.length() - 1) != ':') {
        text.append(':');
      }
      text.append(Integer.toHexString(groups[group]));
      group++;
    }
    return text.toString();
  }
}
