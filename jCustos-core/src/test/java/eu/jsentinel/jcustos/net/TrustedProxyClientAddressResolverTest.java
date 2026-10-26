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

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("TrustedProxyClientAddressResolver (JS-SEC-061)")
class TrustedProxyClientAddressResolverTest {

  private static final String PROXY = "127.0.0.1";
  private static final String CLIENT = "203.0.113.5";
  private static final String ATTACKER_CHOICE = "198.51.100.9";

  private final ClientAddressResolver loopbackProxy = ClientAddressResolver.trustedProxies(PROXY, "::1");

  private static ClientRequestView request(String peer, Map<String, String> headers) {
    return ClientRequestView.of(peer, headers);
  }

  @Test
  @DisplayName("untrusted peer: forged X-Forwarded-For and Forwarded do not change the address")
  void untrustedPeer_forgedHeadersIgnored() {
    Optional<String> resolved = loopbackProxy.resolve(request(CLIENT, Map.of(
        "X-Forwarded-For", ATTACKER_CHOICE,
        "Forwarded", "for=" + ATTACKER_CHOICE,
        "X-Real-IP", ATTACKER_CHOICE)));
    assertEquals(Optional.of(CLIENT), resolved);
  }

  @Test
  @DisplayName("trusted peer: the right-most X-Forwarded-For entry is the client")
  void trustedPeer_rightMostEntryWins() {
    Optional<String> resolved = loopbackProxy.resolve(request(PROXY, Map.of(
        "X-Forwarded-For", ATTACKER_CHOICE + ", " + CLIENT)));
    assertEquals(Optional.of(CLIENT), resolved, "the proxy appended the real client last");
  }

  @Test
  @DisplayName("trusted peer: a single X-Forwarded-For entry is the client")
  void trustedPeer_singleEntry() {
    assertEquals(Optional.of(CLIENT),
        loopbackProxy.resolve(request(PROXY, Map.of("x-forwarded-for", CLIENT))));
  }

  @Test
  @DisplayName("trusted peer: Forwarded and X-Real-IP are ignored even from a trusted proxy")
  void trustedPeer_otherHeadersIgnored() {
    Optional<String> resolved = loopbackProxy.resolve(request(PROXY, Map.of(
        "Forwarded", "for=" + ATTACKER_CHOICE,
        "X-Real-IP", ATTACKER_CHOICE,
        "X-Client-IP", ATTACKER_CHOICE)));
    assertEquals(Optional.of(PROXY), resolved, "without X-Forwarded-For the peer is the client");
  }

  @Test
  @DisplayName("trusted chain: hops inside the trusted set are skipped")
  void trustedChain_skipsTrustedHops() {
    ClientAddressResolver resolver = ClientAddressResolver.trustedProxies("10.0.0.0/8");
    Optional<String> resolved = resolver.resolve(request("10.0.0.1", Map.of(
        "X-Forwarded-For", CLIENT + ", 10.0.0.7")));
    assertEquals(Optional.of(CLIENT), resolved);
  }

  @Test
  @DisplayName("every hop trusted: the request originated inside the trusted set")
  void allHopsTrusted_returnsOrigin() {
    ClientAddressResolver resolver = ClientAddressResolver.trustedProxies("10.0.0.0/8");
    assertEquals(Optional.of("10.0.0.3"),
        resolver.resolve(request("10.0.0.1", Map.of("X-Forwarded-For", "10.0.0.3"))));
  }

  @Test
  @DisplayName("malformed entry appended by the proxy falls back to the peer")
  void malformedEntry_fallsBackToPeer() {
    assertEquals(Optional.of(PROXY),
        loopbackProxy.resolve(request(PROXY, Map.of("X-Forwarded-For", "unknown"))));
    assertEquals(Optional.of(PROXY),
        loopbackProxy.resolve(request(PROXY, Map.of("X-Forwarded-For", "evil.example"))));
  }

  @Test
  @DisplayName("port suffixes and IPv6 brackets are stripped, output is canonical")
  void portsAndBracketsStripped() {
    assertEquals(Optional.of(CLIENT),
        loopbackProxy.resolve(request(PROXY, Map.of("X-Forwarded-For", CLIENT + ":4711"))));
    assertEquals(Optional.of("2001:db8:0:0:0:0:0:1"),
        loopbackProxy.resolve(request(PROXY, Map.of("X-Forwarded-For", "[2001:DB8::1]:443"))));
    assertEquals(Optional.of(CLIENT),
        loopbackProxy.resolve(request("[::1]:50000", Map.of("X-Forwarded-For", CLIENT))));
  }

  @Test
  @DisplayName("IPv6 CIDR range trusts the proxy; IPv4-mapped peer matches its IPv4 range")
  void ipv6RangeAndMappedPeer() {
    ClientAddressResolver v6 = ClientAddressResolver.trustedProxies("fd00::/8");
    assertEquals(Optional.of(CLIENT),
        v6.resolve(request("fd12:3456::1", Map.of("X-Forwarded-For", CLIENT))));
    assertEquals(Optional.of(CLIENT),
        loopbackProxy.resolve(request("::ffff:127.0.0.1", Map.of("X-Forwarded-For", CLIENT))));
  }

  @Test
  @DisplayName("multi-valued header: entries of all X-Forwarded-For headers are read in wire order")
  void multiValuedHeader() {
    ClientRequestView view = ClientRequestView.of(PROXY, name ->
        "X-Forwarded-For".equalsIgnoreCase(name)
            ? List.of(ATTACKER_CHOICE, "192.0.2.10, " + CLIENT)
            : List.of());
    assertEquals(Optional.of(CLIENT), loopbackProxy.resolve(view));
  }

  @Test
  @DisplayName("blank or missing peer address resolves to empty")
  void noPeer_empty() {
    assertTrue(loopbackProxy.resolve(request(null, Map.of("X-Forwarded-For", CLIENT))).isEmpty());
    assertTrue(loopbackProxy.resolve(request("  ", Map.of())).isEmpty());
  }

  @Test
  @DisplayName("configuration rejects empty sets, hostnames and bad prefixes")
  void configurationValidation() {
    assertThrows(IllegalArgumentException.class, () -> ClientAddressResolver.trustedProxies(List.of()));
    assertThrows(IllegalArgumentException.class, () -> ClientAddressResolver.trustedProxies("proxy.example"));
    assertThrows(IllegalArgumentException.class, () -> ClientAddressResolver.trustedProxies("10.0.0.0/33"));
    assertThrows(IllegalArgumentException.class, () -> ClientAddressResolver.trustedProxies("10.0.0.0/x"));
    assertThrows(NullPointerException.class, () -> ClientAddressResolver.trustedProxies((String) null));
  }

  @Test
  @DisplayName("factories return the expected implementations")
  void factories() {
    assertInstanceOf(TrustedProxyClientAddressResolver.class, ClientAddressResolver.trustedProxies(PROXY));
    assertInstanceOf(DefaultClientAddressResolver.class, ClientAddressResolver.remoteAddress());
  }
}
