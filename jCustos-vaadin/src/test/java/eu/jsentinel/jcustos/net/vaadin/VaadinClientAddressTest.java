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
package eu.jsentinel.jcustos.net.vaadin;

import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.mocks.MockRequest;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinServletRequest;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("VaadinClientAddress (JS-SEC-061)")
class VaadinClientAddressTest extends BrowserlessTest {

  private static final String CLIENT = "203.0.113.5";
  private static final String FORGED = "198.51.100.9";

  @Route("client-address-fixture")
  public static class Fixture extends Div {
  }

  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  private MockRequest currentMockRequest() {
    navigate(Fixture.class);
    VaadinRequest current = VaadinRequest.getCurrent();
    assertNotNull(current, "Browserless must bind a current VaadinRequest");
    // browserless wraps its MockRequest in one or more servlet wrappers
    ServletRequest unwrapped = (VaadinServletRequest) current;
    while (unwrapped instanceof HttpServletRequestWrapper wrapper) {
      unwrapped = wrapper.getRequest();
    }
    return (MockRequest) unwrapped;
  }

  @Test
  @DisplayName("default resolver: the peer address is used and forged forwarding headers are ignored")
  void defaultResolver_ignoresForgedHeaders() {
    MockRequest request = currentMockRequest();
    String peer = request.getRemoteAddr();
    assertNotNull(peer, "the mock request must report a peer address");
    request.getHeaders().put("X-Forwarded-For", List.of(FORGED));
    request.getHeaders().put("Forwarded", List.of("for=" + FORGED));

    Optional<String> resolved = VaadinClientAddress.current();

    assertEquals(Optional.of(peer), resolved);
  }

  @Test
  @DisplayName("trusted proxy resolver: X-Forwarded-For from the trusted peer is honoured")
  void trustedProxy_honoursForwardedFor() {
    MockRequest request = currentMockRequest();
    String peer = request.getRemoteAddr();
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(peer));
    request.getHeaders().put("X-Forwarded-For", List.of(FORGED + ", " + CLIENT));

    assertEquals(Optional.of(CLIENT), VaadinClientAddress.current());
  }

  @Test
  @DisplayName("without a current request the helper is empty and never throws")
  void noRequest_empty() {
    com.vaadin.flow.internal.CurrentInstance.set(VaadinRequest.class, null);
    assertTrue(VaadinClientAddress.current().isEmpty());
  }
}
