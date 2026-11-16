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
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server integration")
class DemoRestServerTest {

  private DemoRestServer server;
  private CliOperationClient client;

  @BeforeAll
  void start() throws IOException {
    // These tests rely on the pre-populated admin/editor/viewer accounts,
    // so explicitly disable the bootstrap mechanism (admin/admin must exist).
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    client = new CliOperationClient("http://localhost:" + server.port());
  }

  @AfterAll
  void stop() {
    server.stop();
  }

  @Test
  @DisplayName("login with valid credentials returns a token")
  void loginValid() throws IOException, InterruptedException {
    HttpResponse<String> response = client.login("admin", "admin");
    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertNotNull(payload.get("token"));
    assertEquals("Admin User", payload.get("displayName"));
  }

  @Test
  @DisplayName("login with invalid credentials fails with 401")
  void loginInvalid() throws IOException, InterruptedException {
    HttpResponse<String> response = client.login("admin", "wrong");
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
    assertFalse(response.body().contains("at "));
  }

  @Test
  @DisplayName("operations without token returns 401")
  void operationsWithoutToken() throws IOException, InterruptedException {
    HttpResponse<String> response = client.operations(null);
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
  }

  @Test
  @DisplayName("operations for viewer returns only document:read")
  void operationsViewer() throws IOException, InterruptedException {
    String token = loginAs("viewer", "viewer");
    HttpResponse<String> response = client.operations(token);
    assertEquals(OK.code(), response.statusCode());
    List<String> ids = operationIds(response.body());
    assertEquals(List.of("list-documents"), ids);
  }

  @Test
  @DisplayName("operations for editor returns read, create, update")
  void operationsEditor() throws IOException, InterruptedException {
    String token = loginAs("editor", "editor");
    HttpResponse<String> response = client.operations(token);
    assertEquals(OK.code(), response.statusCode());
    List<String> ids = operationIds(response.body());
    assertTrue(ids.contains("list-documents"));
    assertTrue(ids.contains("create-document"));
    assertFalse(ids.contains("delete-document"));
    assertFalse(ids.contains("admin-status"));
  }

  @Test
  @DisplayName("operations for admin returns all demo operations")
  void operationsAdmin() throws IOException, InterruptedException {
    String token = loginAs("admin", "admin");
    HttpResponse<String> response = client.operations(token);
    assertEquals(OK.code(), response.statusCode());
    List<String> ids = operationIds(response.body());
    assertTrue(ids.containsAll(
        List.of("list-documents", "create-document", "delete-document", "admin-status")));
  }

  @Test
  @DisplayName("viewer can list documents")
  void viewerCanList() throws IOException, InterruptedException {
    String token = loginAs("viewer", "viewer");
    HttpResponse<String> response = client.call("GET", "/api/documents", token, null);
    assertEquals(OK.code(), response.statusCode());
    assertTrue(response.body().contains("documents"));
  }

  @Test
  @DisplayName("viewer cannot delete a document (403, handler does not run)")
  void viewerCannotDelete() throws IOException, InterruptedException {
    String token = loginAs("viewer", "viewer");
    HttpResponse<String> response = client.call("DELETE", "/api/documents/1", token, null);
    assertEquals(FORBIDDEN.code(), response.statusCode());
    assertEquals("Forbidden", response.body());
  }

  @Test
  @DisplayName("editor can create a document")
  void editorCanCreate() throws IOException, InterruptedException {
    String token = loginAs("editor", "editor");
    String body = DemoJson.encode(Map.of("title", "Editor doc"));
    HttpResponse<String> response = client.call("POST", "/api/documents", token, body);
    assertEquals(CREATED.code(), response.statusCode());
    assertTrue(response.body().contains("Editor doc"));
  }

  @Test
  @DisplayName("editor cannot access admin status (403)")
  void editorCannotAccessAdmin() throws IOException, InterruptedException {
    String token = loginAs("editor", "editor");
    HttpResponse<String> response = client.call("GET", "/api/admin/status", token, null);
    assertEquals(FORBIDDEN.code(), response.statusCode());
    assertEquals("Forbidden", response.body());
  }

  @Test
  @DisplayName("admin can call all demo operations")
  void adminCanCallAll() throws IOException, InterruptedException {
    String token = loginAs("admin", "admin");

    assertEquals(OK.code(), client.call("GET", "/api/documents", token, null).statusCode());

    HttpResponse<String> created = client.call(
        "POST", "/api/documents", token, DemoJson.encode(Map.of("title", "Admin doc")));
    assertEquals(CREATED.code(), created.statusCode());

    HttpResponse<String> admin = client.call("GET", "/api/admin/status", token, null);
    assertEquals(OK.code(), admin.statusCode());
    assertTrue(admin.body().contains("ok"));
  }

  @Test
  @DisplayName("requests without authentication receive 401 with no internals leaked")
  void unauthenticatedHas401() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call("GET", "/api/documents", null, null);
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
    assertEquals("Unauthorized", response.body());
    assertFalse(response.body().contains("Exception"));
    assertFalse(response.body().contains("com.svenruppert"));
  }

  @Test
  @DisplayName("logout invalidates the token")
  void logoutInvalidatesToken() throws IOException, InterruptedException {
    String token = loginAs("admin", "admin");
    assertEquals(OK.code(), client.logout(token).statusCode());
    assertEquals(UNAUTHORIZED.code(), client.me(token).statusCode());
  }

  @Test
  @DisplayName("GET /api/audit returns 403 for users without audit:read")
  void auditRequiresPermission() throws IOException, InterruptedException {
    String editorToken = loginAs("editor", "editor");
    HttpResponse<String> response = client.call("GET", "/api/audit", editorToken, null);
    assertEquals(FORBIDDEN.code(), response.statusCode());
  }

  @Test
  @DisplayName("GET /api/audit returns the buffered events for admin")
  void auditReturnsEventsForAdmin() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("GET", "/api/audit", adminToken, null);

    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events = (List<Map<String, Object>>) payload.get("events");
    assertNotNull(events);
    // The admin login above must show up as a LoginSucceeded event in the
    // ring buffer (newest first ordering).
    assertTrue(events.stream()
            .anyMatch(e -> "LoginSucceeded".equals(e.get("type"))
                && "admin".equals(e.get("username"))),
        "expected a LoginSucceeded event for admin in the audit log");
  }

  @Test
  @DisplayName("GET /api/admin/users returns 403 for users without admin:roles")
  void listUsersRequiresPermission() throws IOException, InterruptedException {
    String editorToken = loginAs("editor", "editor");
    HttpResponse<String> response = client.call("GET", "/api/admin/users", editorToken, null);
    assertEquals(FORBIDDEN.code(), response.statusCode());
  }

  @Test
  @DisplayName("GET /api/admin/users lists every registered user for an admin")
  void listUsersReturnsAll() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("GET", "/api/admin/users", adminToken, null);

    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> users = (List<Map<String, Object>>) payload.get("users");
    assertNotNull(users);
    assertTrue(users.size() >= 3, "demo seed contains admin, editor, viewer at minimum");
    assertTrue(users.stream().anyMatch(u ->
        "admin".equals(u.get("username")) && "ROLE_ADMIN".equals(u.get("role"))));
  }

  @Test
  @DisplayName("PUT /api/admin/users/{username} changes the role and reports changed=true")
  void setUserRoleChangesAndReports() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("PUT",
        "/api/admin/users/viewer", adminToken, "{\"role\":\"ROLE_EDITOR\"}");

    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("ROLE_EDITOR", payload.get("role"));
    assertEquals(Boolean.TRUE, payload.get("changed"));

    // Restore so subsequent tests still see the seeded layout.
    client.call("PUT", "/api/admin/users/viewer", adminToken, "{\"role\":\"ROLE_VIEWER\"}");
  }

  @Test
  @DisplayName("PUT /api/admin/users/{username} returns 403 for non-admins")
  void setUserRoleRequiresPermission() throws IOException, InterruptedException {
    String editorToken = loginAs("editor", "editor");
    HttpResponse<String> response = client.call("PUT",
        "/api/admin/users/viewer", editorToken, "{\"role\":\"ROLE_EDITOR\"}");
    assertEquals(FORBIDDEN.code(), response.statusCode());
  }

  @Test
  @DisplayName("PUT /api/admin/users/{username} returns 400 for an unknown role")
  void setUserRoleRejectsUnknownRole() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("PUT",
        "/api/admin/users/viewer", adminToken, "{\"role\":\"ROLE_NOBODY\"}");
    assertEquals(BAD_REQUEST.code(), response.statusCode());
  }

  @Test
  @DisplayName("POST /api/admin/users creates a new user and returns 201")
  void createUserHappyPath() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("POST",
        "/api/admin/users", adminToken,
        "{\"username\":\"alice\",\"password\":\"secret123\",\"displayName\":\"Alice Demo\",\"role\":\"ROLE_VIEWER\"}");

    assertEquals(CREATED.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("alice", payload.get("username"));
    assertEquals("Alice Demo", payload.get("displayName"));
    assertEquals("ROLE_VIEWER", payload.get("role"));

    // Cleanup so the server-wide fixture stays predictable for following tests.
    client.call("DELETE", "/api/admin/users/alice", adminToken, null);
  }

  @Test
  @DisplayName("POST /api/admin/users returns 409 for duplicate username")
  void createUserDuplicate() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("POST",
        "/api/admin/users", adminToken,
        "{\"username\":\"editor\",\"password\":\"x\",\"role\":\"ROLE_VIEWER\"}");
    assertEquals(CONFLICT.code(), response.statusCode());
  }

  @Test
  @DisplayName("POST /api/admin/users returns 400 for unknown role")
  void createUserBadRole() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("POST",
        "/api/admin/users", adminToken,
        "{\"username\":\"x\",\"password\":\"x\",\"role\":\"ROLE_NOPE\"}");
    assertEquals(BAD_REQUEST.code(), response.statusCode());
  }

  @Test
  @DisplayName("DELETE /api/admin/users/{username} removes the user (204) and a second delete returns 404")
  void deleteUserHappyPath() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    client.call("POST", "/api/admin/users", adminToken,
        "{\"username\":\"temp\",\"password\":\"x\",\"role\":\"ROLE_VIEWER\"}");

    HttpResponse<String> response = client.call("DELETE",
        "/api/admin/users/temp", adminToken, null);
    assertEquals(NO_CONTENT.code(), response.statusCode());

    HttpResponse<String> second = client.call("DELETE",
        "/api/admin/users/temp", adminToken, null);
    assertEquals(NOT_FOUND.code(), second.statusCode());
  }

  @Test
  @DisplayName("POST/DELETE /api/admin/users require admin:roles (403 for editor)")
  void createDeleteRequirePermission() throws IOException, InterruptedException {
    String editorToken = loginAs("editor", "editor");
    HttpResponse<String> postResponse = client.call("POST",
        "/api/admin/users", editorToken,
        "{\"username\":\"x\",\"password\":\"x\",\"role\":\"ROLE_VIEWER\"}");
    HttpResponse<String> deleteResponse = client.call("DELETE",
        "/api/admin/users/admin", editorToken, null);
    assertEquals(FORBIDDEN.code(), postResponse.statusCode());
    assertEquals(FORBIDDEN.code(), deleteResponse.statusCode());
  }

  @Test
  @DisplayName("GET /api/audit?type=LoginSucceeded narrows the result set")
  void auditTypeFilter() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call(
        "GET", "/api/audit?type=LoginSucceeded", adminToken, null);

    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events = (List<Map<String, Object>>) payload.get("events");
    assertTrue(events.stream().allMatch(e -> "LoginSucceeded".equals(e.get("type"))),
        "type=LoginSucceeded must filter out every other event type");
  }

  @Test
  @DisplayName("POST /api/admin/users with a blocklisted password returns 400 — V00.71 compromised check")
  void createUserCompromisedPasswordRejected() throws IOException, InterruptedException {
    String adminToken = loginAs("admin", "admin");
    HttpResponse<String> response = client.call("POST",
        "/api/admin/users", adminToken,
        "{\"username\":\"weakling\",\"password\":\"password123\",\"role\":\"ROLE_VIEWER\"}");
    // Generic 400 — CWE-209: server does not disclose which dictionary matched.
    assertEquals(BAD_REQUEST.code(), response.statusCode());
    // Confirm the user was NOT created.
    HttpResponse<String> users = client.call(
        "GET", "/api/admin/users", adminToken, null);
    assertFalse(users.body().contains("\"weakling\""),
        "blocked username must not appear in /api/admin/users");
  }

  private String loginAs(String username, String password) throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }

  @SuppressWarnings("unchecked")
  private static List<String> operationIds(String body) {
    Map<String, Object> payload = DemoJson.decodeObject(body);
    List<Object> ops = (List<Object>) payload.get("operations");
    return ops.stream()
        .map(o -> String.valueOf(((Map<String, Object>) o).get("id")))
        .toList();
  }
}
