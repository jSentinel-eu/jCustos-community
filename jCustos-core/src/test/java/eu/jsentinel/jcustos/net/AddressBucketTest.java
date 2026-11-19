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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JS-SEC-062 (CWE-307): the bucket of the login address counter - IPv6 per prefix, IPv4 exact,
 * one canonical text for every spelling. Synthetic documentation addresses only.
 */
@DisplayName("AddressBucket - IPv6 per prefix, IPv4 exact (JS-SEC-062)")
class AddressBucketTest {

  @Test
  @DisplayName("two addresses of one /64 share a bucket, written in RFC 5952 form with the length")
  void sameSlash64SharesTheBucket() {
    assertEquals("2001:db8:1:2::/64", AddressBucket.of("2001:db8:1:2:a:b:c:d", 64));
    assertEquals("2001:db8:1:2::/64", AddressBucket.of("2001:0DB8:0001:0002:ffff::1", 64));
    assertNotEquals(AddressBucket.of("2001:db8:1:2::1", 64), AddressBucket.of("2001:db8:1:3::1", 64),
        "a neighbouring /64 is a bucket of its own");
  }

  @Test
  @DisplayName("a shorter prefix groups wider: two /64 of one /48")
  void slash48GroupsWider() {
    assertEquals("2001:db8:1::/48", AddressBucket.of("2001:db8:1:2::1", 48));
    assertEquals("2001:db8:1::/48", AddressBucket.of("2001:db8:1:ffff::1", 48));
    assertNotEquals(AddressBucket.of("2001:db8:1::1", 48), AddressBucket.of("2001:db8:2::1", 48));
    assertEquals("2001:db8:1:8000::/49", AddressBucket.of("2001:db8:1:ffff::1", 49),
        "a length that is no multiple of 16 cuts inside a group");
  }

  @Test
  @DisplayName("128 keeps every IPv6 address exact")
  void slash128IsExact() {
    assertEquals("2001:db8:1:2:a:b:c:d/128", AddressBucket.of("2001:db8:1:2:a:b:c:d", 128));
    assertNotEquals(AddressBucket.of("2001:db8::1", 128), AddressBucket.of("2001:db8::2", 128));
  }

  @Test
  @DisplayName("every spelling of an address gives the same text: case, leading zeros, ::, brackets, port")
  void spellingsCollapse() throws Exception {
    String expected = "2001:db8:1:2::/64";
    for (String spelling : new String[]{"2001:db8:1:2::5", "2001:DB8:1:2:0:0:0:5",
        "2001:0db8:0001:0002:0000:0000:0000:0005", "[2001:db8:1:2::5]", "[2001:db8:1:2::5]:4711",
        "  2001:db8:1:2::5  ", InetAddress.ofLiteral("2001:db8:1:2::5").getHostAddress()}) {
      assertEquals(expected, AddressBucket.of(spelling, 64), spelling);
    }
  }

  @Test
  @DisplayName("RFC 5952: the longest zero run is compressed, the first of two equal runs, never a single zero group")
  void canonicalText() {
    assertEquals("::/64", AddressBucket.of("::1", 64));
    assertEquals("::1/128", AddressBucket.of("::1", 128));
    assertEquals("2001:db8::1:0:0:1/128", AddressBucket.of("2001:db8:0:0:1:0:0:1", 128));
    assertEquals("2001:db8:0:1:1:1:1:1/128", AddressBucket.of("2001:db8:0:1:1:1:1:1", 128));
    assertEquals("2001:0:0:1::1/128", AddressBucket.of("2001:0:0:1:0:0:0:1", 128));
    assertEquals("fe80::/64", AddressBucket.of("fe80::1%1", 64), "a numeric zone is dropped");
  }

  @Test
  @DisplayName("IPv4 stays exact; an IPv4-mapped IPv6 address is that IPv4 address")
  void ipv4IsExact() {
    assertEquals("203.0.113.5", AddressBucket.of("203.0.113.5", 64));
    assertEquals("203.0.113.5", AddressBucket.of("203.0.113.5", 32));
    assertNotEquals(AddressBucket.of("203.0.113.5", 64), AddressBucket.of("203.0.113.6", 64));
    assertEquals("203.0.113.5", AddressBucket.of("::ffff:203.0.113.5", 64));
    assertEquals("203.0.113.5", AddressBucket.of("::FFFF:cb00:7105", 64));
    assertEquals("203.0.113.5", AddressBucket.of("[::ffff:203.0.113.5]:4711", 64));
    assertEquals("203.0.113.5", AddressBucket.of("203.0.113.5:4711", 64), "the port is dropped");
  }

  @Test
  @DisplayName("text that is no IP literal is kept as one exact bucket, trimmed and lower-cased")
  void nonLiteralsStayExact() {
    assertEquals("client.example", AddressBucket.of("  Client.Example ", 64));
    assertEquals("fe80::1%eth0", AddressBucket.of("fe80::1%eth0", 64), "a named zone is no literal");
    assertEquals("/203.0.113.5:4711", AddressBucket.of("/203.0.113.5:4711", 64),
        "a socket address with its slash is no literal");
    assertEquals("-", AddressBucket.of("-", 64));
  }

  @Test
  @DisplayName("a prefix length outside 0..128 is refused; a null address is refused")
  void invalidArgumentsAreRefused() {
    assertThrows(IllegalArgumentException.class, () -> AddressBucket.of("2001:db8::1", -1));
    assertThrows(IllegalArgumentException.class, () -> AddressBucket.of("2001:db8::1", 129));
    assertThrows(NullPointerException.class, () -> AddressBucket.of(null, 64));
    assertEquals("::/0", AddressBucket.of("2001:db8::1", 0));
  }
}
