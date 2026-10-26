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

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DefaultClientAddressResolver (JS-SEC-061)")
class DefaultClientAddressResolverTest {

  private final ClientAddressResolver resolver = ClientAddressResolver.remoteAddress();

  @Test
  @DisplayName("the connection peer is the client; every forwarding header is ignored")
  void peerWins() {
    Optional<String> resolved = resolver.resolve(ClientRequestView.of("203.0.113.5", Map.of(
        "X-Forwarded-For", "198.51.100.9",
        "Forwarded", "for=198.51.100.9",
        "X-Real-IP", "198.51.100.9")));
    assertEquals(Optional.of("203.0.113.5"), resolved);
  }

  @Test
  @DisplayName("IP literals are canonicalised, other peer strings pass through trimmed")
  void canonicalForm() {
    assertEquals(Optional.of("2001:db8:0:0:0:0:0:1"),
        resolver.resolve(ClientRequestView.of(" [2001:DB8::1] ", Map.of())));
    assertEquals(Optional.of("127.0.0.1"),
        resolver.resolve(ClientRequestView.of("::ffff:127.0.0.1", Map.of())));
    assertEquals(Optional.of("client.example"),
        resolver.resolve(ClientRequestView.of(" client.example ", Map.of())));
  }

  @Test
  @DisplayName("null or blank peer resolves to empty")
  void noPeer() {
    assertTrue(resolver.resolve(ClientRequestView.of(null, Map.of())).isEmpty());
    assertTrue(resolver.resolve(ClientRequestView.of("", Map.of())).isEmpty());
  }

  @Test
  @DisplayName("ClientRequestView.of(map) looks headers up case-insensitively and tolerates null")
  void viewSemantics() {
    ClientRequestView view = ClientRequestView.of("203.0.113.5", Map.of("X-Forwarded-For", "a"));
    assertEquals(java.util.List.of("a"), view.headers("x-forwarded-FOR"));
    assertTrue(view.headers("Forwarded").isEmpty());
    assertTrue(view.headers(null).isEmpty());
    assertTrue(ClientRequestView.of("203.0.113.5", (Map<String, String>) null).headers("X").isEmpty());
  }
}
