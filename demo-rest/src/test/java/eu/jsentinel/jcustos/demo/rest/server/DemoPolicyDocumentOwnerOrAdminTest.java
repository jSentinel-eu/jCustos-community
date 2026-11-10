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

/**
 * End-to-end coverage of the V00.70 Policy-DSL example
 * {@code document.owner-or-admin} as wired by {@link DemoRestServer}:
 * <ul>
 *   <li>Admin can inspect any document (allowIf role=ADMIN).</li>
 *   <li>Owner can inspect their own document (orIf
 *       ownerMatchesSubject).</li>
 *   <li>Non-admin non-owner is refused with 403.</li>
 *   <li>Unauthenticated requests are refused with 401 ahead of
 *       policy evaluation.</li>
 * </ul>
 * The demo seed contains one doc per role (id=1 editor, id=2
 * viewer, id=3 admin) — see
 * {@link eu.jsentinel.jcustos.demo.rest.domain.DemoOwnedDocumentStore}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server — Policy-DSL document.owner-or-admin")
class DemoPolicyDocumentOwnerOrAdminTest {

  private DemoRestServer server;
  private CliOperationClient client;

  @BeforeAll
  void start() throws IOException {
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled());
    client = new CliOperationClient("http://localhost:" + server.port());
  }

  @AfterAll
  void stop() {
    server.stop();
  }

  @Test
  @DisplayName("Admin can inspect any document (allowIf hasRole(ROLE_ADMIN))")
  void adminCanInspectAny() throws IOException, InterruptedException {
    String adminToken = login("admin", "admin");

    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.OWNED_DOCUMENT_BY_ID + "1", adminToken, null);
    assertEquals(OK.code(), response.statusCode(),
        "admin must reach the editor-owned document");
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("editor", payload.get("ownerId"));
  }

  @Test
  @DisplayName("Owner can inspect their own document (orIf ownerMatchesSubject)")
  void ownerCanInspectOwn() throws IOException, InterruptedException {
    String editorToken = login("editor", "editor");

    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.OWNED_DOCUMENT_BY_ID + "1", editorToken, null);
    assertEquals(OK.code(), response.statusCode(),
        "editor must reach their own document (id=1, ownerId=editor)");
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("editor", payload.get("ownerId"));
  }

  @Test
  @DisplayName("Non-admin non-owner is refused (default deny path)")
  void nonAdminNonOwnerIs403() throws IOException, InterruptedException {
    String editorToken = login("editor", "editor");

    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.OWNED_DOCUMENT_BY_ID + "2", editorToken, null);
    assertEquals(FORBIDDEN.code(), response.statusCode(),
        "editor must NOT reach the viewer-owned document (id=2, ownerId=viewer)");
  }

  @Test
  @DisplayName("Viewer can inspect their own document")
  void viewerCanInspectOwn() throws IOException, InterruptedException {
    String viewerToken = login("viewer", "viewer");

    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.OWNED_DOCUMENT_BY_ID + "2", viewerToken, null);
    assertEquals(OK.code(), response.statusCode(),
        "viewer must reach their own document (id=2, ownerId=viewer)");
  }

  @Test
  @DisplayName("Viewer cannot inspect admin's document → 403")
  void viewerCannotInspectAdminDoc() throws IOException, InterruptedException {
    String viewerToken = login("viewer", "viewer");

    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.OWNED_DOCUMENT_BY_ID + "3", viewerToken, null);
    assertEquals(FORBIDDEN.code(), response.statusCode(),
        "viewer must NOT reach the admin-owned document (id=3)");
  }

  @Test
  @DisplayName("Unauthenticated request is refused before the policy runs → 401")
  void unauthenticatedIs401() throws IOException, InterruptedException {
    // JS-SEC-157: without a subject the RequiresPolicyEvaluator answers
    // Unauthenticated before the policy is consulted, so the perimeter
    // response is 401 (it used to fall through to the policy's default
    // deny and came back as 403).
    HttpResponse<String> response = client.call(
        "GET", DemoEndpoints.OWNED_DOCUMENT_BY_ID + "1", null, null);
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
  }

  private String login(String username, String password)
      throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
