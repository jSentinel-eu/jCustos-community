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
package eu.jsentinel.jcustos.demo.rest.server;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * SP06: the demo's request adapter reports the connection peer as {@code Optional}, as
 * {@code RestRequest.remoteAddress()} asks: the peer the transport reported, or empty when it
 * reported none or a blank one.
 */
@DisplayName("SP06 — demo request: the connection peer is optional and never blank")
class DemoRemoteAddressTest {

  @Test
  @DisplayName("a reported peer is returned as it was reported")
  void reportedPeer() {
    assertEquals(Optional.of("203.0.113.5"), DemoHttpRequest.fromHeaderLines("GET", "/api/x",
        Map.of(), Map.of(), null, "203.0.113.5").remoteAddress());
    assertEquals(Optional.of("127.0.0.1"), new DemoHttpRequest("POST", "/api/login", Map.of(),
        Map.of(), "{}", "127.0.0.1").remoteAddress());
  }

  @Test
  @DisplayName("no peer, or a blank one, is empty")
  void absentOrBlankPeer() {
    assertEquals(Optional.empty(), new DemoHttpRequest("GET", "/api/x", Map.of(), Map.of(),
        new byte[0]).remoteAddress());
    assertEquals(Optional.empty(), DemoHttpRequest.fromHeaderLines("GET", "/api/x",
        Map.of(), Map.of(), null, null).remoteAddress());
    assertEquals(Optional.empty(), DemoHttpRequest.fromHeaderLines("GET", "/api/x",
        Map.of(), Map.of(), null, "").remoteAddress());
    assertEquals(Optional.empty(), new DemoHttpRequest("GET", "/api/x", Map.of(), Map.of(),
        new byte[0], " \t ").remoteAddress());
  }
}
