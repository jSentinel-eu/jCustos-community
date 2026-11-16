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
package eu.jsentinel.jcustos.identity.oidc.vaadin;

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.identity.oidc.InMemorySessionRegistry;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.flow.server.SessionDestroyEvent;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * JS-SEC-078 / JS-SEC-117: the cleanup forgets a destroyed session in the back-channel
 * registry - under the reference the registry should hold, and under the raw id a registry
 * written before 00.84.00 holds. Real registry, real Vaadin session of the browserless
 * service.
 */
@DisplayName("JS-SEC-117 — VaadinSessionRegistryCleanup forgets sessions registered by reference or by id")
class VaadinSessionRegistryCleanupTest {

  private static final String ISSUER = "https://idp.example";

  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private String sessionId;

  @BeforeEach
  void start() {
    MockVaadin.setup();
    session = VaadinSession.getCurrent();
    sessionId = session.getSession().getId();
  }

  @AfterEach
  void stop() {
    MockVaadin.tearDown();
  }

  @Test
  @DisplayName("a session registered under its reference is forgotten when Vaadin destroys it")
  void registeredByReference_isForgotten() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sid-1"), SessionRef.of(sessionId));
    registry.register(ISSUER, "bob", Optional.of("sid-2"), SessionRef.of("another-session"));

    new VaadinSessionRegistryCleanup(registry)
        .sessionDestroy(new SessionDestroyEvent(VaadinService.getCurrent(), session));

    assertEquals(1, registry.trackedSessionCount(), "only the destroyed session is forgotten");
    assertEquals(Set.of(SessionRef.of("another-session")),
        registry.terminate(ISSUER, Optional.of("bob"), Optional.empty()));
  }

  @Test
  @DisplayName("a session registered under its raw id is forgotten as well")
  void registeredByRawId_isForgotten() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sid-1"), sessionId);

    new VaadinSessionRegistryCleanup(registry)
        .sessionDestroy(new SessionDestroyEvent(VaadinService.getCurrent(), session));

    assertEquals(0, registry.trackedSessionCount());
  }
}
