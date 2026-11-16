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

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.demo.rest.cli.CliOperationClient;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static com.svenruppert.dependencies.core.net.HttpStatus.UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1188, CWE-798, CWE-319): the reference defaults of the demo server. It
 * listens on loopback only, creates no fixed-password account unless asked to by name, and
 * refuses bootstrap mode {@code DISABLED} when nothing else could create an administrator.
 */
@DisplayName("Demo REST server — safe reference defaults")
class DemoServerExposureTest {

  @Test
  @DisplayName("the server is bound to the loopback interface")
  void listensOnLoopbackOnly() throws IOException {
    DemoRestServer server = DemoRestServer.start(0, BootstrapConfiguration.transientConsole(), false);
    try {
      assertTrue(server.address().getAddress().isLoopbackAddress(),
          "plain-HTTP demo must not listen on " + server.address());
    } finally {
      server.stop();
    }
  }

  @Test
  @DisplayName("bootstrap mode DISABLED without the seed switch refuses to start")
  void disabledBootstrapWithoutSeedRefusesToStart() {
    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> DemoRestServer.start(0, BootstrapConfiguration.disabled(), false));
    assertTrue(refused.getMessage().contains(DemoUserStore.INSECURE_SEED_ACCOUNTS_PROPERTY),
        "the refusal must name the development switch: " + refused.getMessage());
  }

  @Test
  @DisplayName("without the switch no fixed-password account exists; with it in bootstrap mode, no admin/admin")
  void seedAccountsOnlyOnRequest() throws IOException, InterruptedException {
    DemoRestServer plain = DemoRestServer.start(0, BootstrapConfiguration.transientConsole(), false);
    try {
      CliOperationClient client = new CliOperationClient("http://localhost:" + plain.port());
      assertEquals(UNAUTHORIZED.code(), client.login("editor", "editor").statusCode());
      assertEquals(UNAUTHORIZED.code(), client.login("viewer", "viewer").statusCode());
      assertEquals(UNAUTHORIZED.code(), client.login("admin", "admin").statusCode());
    } finally {
      plain.stop();
    }

    DemoRestServer seeded = DemoRestServer.start(0, BootstrapConfiguration.transientConsole(), true);
    try {
      CliOperationClient client = new CliOperationClient("http://localhost:" + seeded.port());
      assertEquals(OK.code(), client.login("editor", "editor").statusCode());
      assertEquals(UNAUTHORIZED.code(), client.login("admin", "admin").statusCode(),
          "with a bootstrap flow the administrator never comes from the seed");
    } finally {
      seeded.stop();
    }
  }

  @Test
  @DisplayName("a store built without a seed is empty")
  void plainStoreIsEmpty() {
    DemoUserStore store = new DemoUserStore(PasswordHashingServices.defaults());
    assertTrue(store.listAll().isEmpty());
    assertFalse(store.hasAnyAdministrator());
  }
}
