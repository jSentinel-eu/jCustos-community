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
package eu.jsentinel.jcustos.demo.restclient.backend;

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.demo.rest.server.DemoRestServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for {@link HttpDemoBackendClient} against an
 * in-process {@link DemoRestServer}. Disables bootstrap so the
 * pre-populated admin/admin user is available.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("HttpDemoBackendClient against in-process demo-rest")
class HttpDemoBackendClientTest {

  private DemoRestServer server;
  private HttpDemoBackendClient client;

  @BeforeAll
  void start() throws IOException {
    // The fixed-password demo accounts exist only behind an explicit switch (JS-SEC-137).
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    BackendConfig config = new BackendConfig(
        "http://localhost:" + server.port(),
        Duration.ofSeconds(2),
        Duration.ofSeconds(5));
    client = new HttpDemoBackendClient(config);
  }

  @AfterAll
  void stop() {
    if (server != null) server.stop();
  }

  // ── login + currentUser + logout ─────────────────────────────

  @Test
  @DisplayName("login with valid credentials returns token + RemoteUser with roles/permissions")
  void loginValid() {
    LoginResult result = client.login(new Credentials("admin", "admin"));
    assertInstanceOf(LoginResult.Authenticated.class, result);
    LoginResult.Authenticated ok = (LoginResult.Authenticated) result;
    assertNotNull(ok.token());
    assertEquals("Admin User", ok.user().displayName());
    assertTrue(ok.user().permissions().stream()
        .anyMatch(p -> "document:delete".equals(p.value())));
  }

  @Test
  @DisplayName("login with wrong password returns InvalidCredentials")
  void loginInvalid() {
    LoginResult result = client.login(new Credentials("admin", "wrong"));
    assertInstanceOf(LoginResult.InvalidCredentials.class, result);
  }

  @Test
  @DisplayName("currentUser without token throws Unauthenticated")
  void currentUserUnauthenticated() {
    BackendException ex = assertThrows(BackendException.class,
        () -> client.currentUser("not-a-real-token"));
    assertEquals(BackendException.Kind.Unauthenticated, ex.kind());
  }

  @Test
  @DisplayName("currentUser with valid token returns the user")
  void currentUserOk() {
    String token = loginAs("admin", "admin");
    RemoteUser user = client.currentUser(token);
    assertEquals("admin", user.subjectId());
  }

  @Test
  @DisplayName("logout invalidates the token")
  void logoutFlow() {
    String token = loginAs("admin", "admin");
    client.logout(token);
    BackendException ex = assertThrows(BackendException.class,
        () -> client.currentUser(token));
    assertEquals(BackendException.Kind.Unauthenticated, ex.kind());
  }

  // ── operations + documents (filtered by permission) ──────────

  @Test
  @DisplayName("visibleOperations is filtered by the subject's permissions")
  void operationsViewerVsAdmin() {
    String viewerToken = loginAs("viewer", "viewer");
    List<RemoteOperation> viewerOps = client.visibleOperations(viewerToken);
    assertEquals(1, viewerOps.size());
    assertEquals("list-documents", viewerOps.getFirst().id());

    String adminToken = loginAs("admin", "admin");
    List<RemoteOperation> adminOps = client.visibleOperations(adminToken);
    assertTrue(adminOps.size() >= 4);
  }

  @Test
  @DisplayName("listDocuments works for any role with document:read")
  void listDocumentsViewer() {
    String token = loginAs("viewer", "viewer");
    List<RemoteDocument> docs = client.listDocuments(token);
    assertFalse(docs.isEmpty());
  }

  @Test
  @DisplayName("createDocument is denied for viewer and accepted for editor")
  void createDocumentPermissions() {
    String viewer = loginAs("viewer", "viewer");
    BackendException denied = assertThrows(BackendException.class,
        () -> client.createDocument(viewer, "viewer-attempt"));
    assertEquals(BackendException.Kind.Forbidden, denied.kind());

    String editor = loginAs("editor", "editor");
    RemoteDocument created = client.createDocument(editor, "editor-doc");
    assertNotNull(created.title());
    assertTrue(created.id() > 0);
  }

  @Test
  @DisplayName("deleteDocument is denied for viewer, accepted for admin")
  void deleteDocumentPermissions() {
    String editor = loginAs("editor", "editor");
    RemoteDocument doomed = client.createDocument(editor, "to-delete");

    String viewer = loginAs("viewer", "viewer");
    BackendException denied = assertThrows(BackendException.class,
        () -> client.deleteDocument(viewer, doomed.id()));
    assertEquals(BackendException.Kind.Forbidden, denied.kind());

    String admin = loginAs("admin", "admin");
    client.deleteDocument(admin, doomed.id());
  }

  @Test
  @DisplayName("adminStatus is denied for editor and accepted for admin")
  void adminStatusPermissions() {
    String editor = loginAs("editor", "editor");
    BackendException denied = assertThrows(BackendException.class,
        () -> client.adminStatus(editor));
    assertEquals(BackendException.Kind.Forbidden, denied.kind());

    String admin = loginAs("admin", "admin");
    RemoteAdminStatus status = client.adminStatus(admin);
    assertEquals("ok", status.status());
  }

  // ── bootstrap ─────────────────────────────────────────────────

  @Test
  @DisplayName("bootstrapStatus reflects the configured mode")
  void bootstrapStatusReflectsConfig() {
    var status = client.bootstrapStatus();
    assertFalse(status.bootstrapRequired());
    assertEquals(BootstrapMode.DISABLED, status.mode());
  }

  @Test
  @DisplayName("createInitialAdmin returns AlreadyInitialized when admin already exists")
  void bootstrapAlreadyInitialized() {
    BootstrapResult result = client.createInitialAdmin(new BootstrapAdminRequest(
        "any-token", "second-admin", "verystrong-1".toCharArray(), "Second", null));
    assertInstanceOf(BootstrapResult.AlreadyInitialized.class, result);
  }

  // ── bootstrap on a separate persistent-mode server ───────────

  @Test
  @DisplayName("createInitialAdmin succeeds against a fresh PERSISTENT_FILE backend")
  void bootstrapPersistentLifecycle() throws Exception {
    Path tokenFile = Files.createTempDirectory("rc-bootstrap-").resolve("bootstrap.token");
    DemoRestServer freshServer = DemoRestServer.start(0,
        BootstrapConfiguration.persistent(tokenFile));
    try {
      BackendConfig cfg = new BackendConfig(
          "http://localhost:" + freshServer.port(),
          Duration.ofSeconds(2), Duration.ofSeconds(5));
      DemoBackendClient freshClient = new HttpDemoBackendClient(cfg);

      assertTrue(freshClient.bootstrapStatus().bootstrapRequired());
      String token = readTokenFromFile(tokenFile);

      BootstrapResult ok = freshClient.createInitialAdmin(new BootstrapAdminRequest(
          token, "rcadmin", "verystrong-1".toCharArray(), "RC Admin", null));
      assertInstanceOf(BootstrapResult.Created.class, ok);
      assertFalse(freshClient.bootstrapStatus().bootstrapRequired());

      BootstrapResult conflict = freshClient.createInitialAdmin(new BootstrapAdminRequest(
          "wrong", "another", "verystrong-1".toCharArray(), null, null));
      assertInstanceOf(BootstrapResult.AlreadyInitialized.class, conflict);
    } finally {
      freshServer.stop();
    }
  }

  // ── helpers ──────────────────────────────────────────────────

  private String loginAs(String username, String password) {
    LoginResult result = client.login(new Credentials(username, password));
    return ((LoginResult.Authenticated) result).token();
  }

  private static String readTokenFromFile(Path path) throws IOException {
    Optional<String> tokenLine = Files.readAllLines(path).stream()
        .filter(line -> line.startsWith("token=")).findFirst();
    return tokenLine.orElseThrow().substring("token=".length()).trim();
  }
}