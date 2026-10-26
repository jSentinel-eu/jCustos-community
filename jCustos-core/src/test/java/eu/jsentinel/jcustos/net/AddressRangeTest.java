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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AddressRange and IpLiterals")
class AddressRangeTest {

  private static InetAddress ip(String literal) {
    return IpLiterals.parse(literal).orElseThrow();
  }

  @Test
  @DisplayName("CIDR prefixes match on the leading bits only")
  void cidrMatching() {
    AddressRange ten = AddressRange.parse("10.0.0.0/8");
    assertTrue(ten.contains(ip("10.255.255.255")));
    assertFalse(ten.contains(ip("11.0.0.0")));

    AddressRange slash20 = AddressRange.parse("192.168.16.0/20");
    assertTrue(slash20.contains(ip("192.168.31.255")));
    assertFalse(slash20.contains(ip("192.168.32.0")));

    assertTrue(AddressRange.parse("0.0.0.0/0").contains(ip("203.0.113.5")));
    assertTrue(AddressRange.parse("127.0.0.1").contains(ip("127.0.0.1")));
    assertFalse(AddressRange.parse("127.0.0.1").contains(ip("127.0.0.2")));
  }

  @Test
  @DisplayName("IPv6 ranges, family mismatch and IPv4-mapped addresses")
  void ipv6AndFamilies() {
    AddressRange ula = AddressRange.parse("fd00::/8");
    assertTrue(ula.contains(ip("fdab:cdef::1")));
    assertFalse(ula.contains(ip("fe80::1")));
    assertFalse(ula.contains(ip("10.0.0.1")), "an IPv6 range never matches IPv4");
    assertFalse(AddressRange.parse("10.0.0.0/8").contains(ip("::1")), "an IPv4 range never matches IPv6");
    assertTrue(AddressRange.parse("127.0.0.1").contains(ip("::ffff:127.0.0.1")),
        "an IPv4-mapped address is IPv4");
    assertTrue(AddressRange.parse("[::1]").contains(ip("0:0:0:0:0:0:0:1")));
  }

  @Test
  @DisplayName("parse rejects hostnames and prefixes outside the family width")
  void parseValidation() {
    assertThrows(IllegalArgumentException.class, () -> AddressRange.parse("proxy.example"));
    assertThrows(IllegalArgumentException.class, () -> AddressRange.parse("10.0.0.0/33"));
    assertThrows(IllegalArgumentException.class, () -> AddressRange.parse("::1/129"));
    assertThrows(IllegalArgumentException.class, () -> AddressRange.parse("10.0.0.0/-1"));
    assertThrows(IllegalArgumentException.class, () -> AddressRange.parse("10.0.0.0/eight"));
    assertEquals("10.0.0.0/8", AddressRange.parse(" 10.0.0.0/8 ").toString());
  }

  @Test
  @DisplayName("IpLiterals accepts ports and brackets, never resolves names")
  void literals() {
    assertEquals("203.0.113.5", ip("203.0.113.5:4711").getHostAddress());
    assertEquals("2001:db8:0:0:0:0:0:1", ip("[2001:db8::1]:443").getHostAddress());
    assertEquals("2001:db8:0:0:0:0:0:1", ip("2001:db8::1").getHostAddress());
    assertTrue(IpLiterals.parse("localhost").isEmpty());
    assertTrue(IpLiterals.parse("unknown").isEmpty());
    assertTrue(IpLiterals.parse("203.0.113.256").isEmpty());
    assertTrue(IpLiterals.parse(null).isEmpty());
    assertTrue(IpLiterals.parse("   ").isEmpty());
    assertTrue(IpLiterals.parse("[").isEmpty());
  }
}
