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
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Coverage for {@code GET /api/documents/inspect} —
 * {@code @RequiresAnyPermission} OR semantics.
 * <p>
 * Demo seed: viewer holds {@code document:read} only; editor holds
 * {@code document:read} + {@code document:create}. Both must reach
 * the inspector; an unauthenticated request is refused with the
 * regular 401.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server — @RequiresAnyPermission inspect endpoint")
class DemoInspectDocumentsTest {

  private DemoRestServer server;
  private CliOperationClient client;

  @BeforeAll
  void start() throws IOException {
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    client = new CliOperationClient("http://localhost:" + server.port());
  }

  @AfterAll
  void stop() {
    server.stop();
  }

  @Test
  @DisplayName("viewer (document:read only) reaches the inspector → 200 + ANY semantics")
  void viewerReachesInspector() throws IOException, InterruptedException {
    String token = login("viewer", "viewer");
    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.DOCUMENTS_INSPECT, token, null);
    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("ANY", payload.get("semantics"),
        "inspector must report its evaluator semantics");
    assertNotNull(payload.get("documentCount"));
  }

  @Test
  @DisplayName("editor (document:read + document:create) reaches the inspector → 200")
  void editorReachesInspector() throws IOException, InterruptedException {
    String token = login("editor", "editor");
    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.DOCUMENTS_INSPECT, token, null);
    assertEquals(OK.code(), response.statusCode());
  }

  @Test
  @DisplayName("unauthenticated request → 401 with generic body")
  void unauthenticatedRefused() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.DOCUMENTS_INSPECT, null, null);
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
    assertEquals("Unauthorized", response.body());
  }

  private String login(String username, String password)
      throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
