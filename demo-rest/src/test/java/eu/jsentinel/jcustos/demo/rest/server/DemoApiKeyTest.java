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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end coverage of the V00.70 Phase-7b API-key flow:
 * <ul>
 *   <li>{@code POST /api/admin/api-keys} mints a key with explicit
 *       scopes — only an admin may call it.</li>
 *   <li>The {@code X-Api-Key} header on a subsequent request feeds
 *       {@link eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService}
 *       and the resolved {@code JCustosSubject} carries the key's
 *       scopes as its permission set (no role inheritance).</li>
 *   <li>{@code POST /api/admin/api-keys/revoke} flips the record
 *       and the same {@code X-Api-Key} is refused on the next
 *       call.</li>
 * </ul>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server — Phase-7b API-key flow")
class DemoApiKeyTest {

  private DemoRestServer server;
  private CliOperationClient client;
  private HttpClient http;
  private String baseUrl;

  @BeforeAll
  void start() throws IOException {
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    baseUrl = "http://localhost:" + server.port();
    client = new CliOperationClient(baseUrl);
    http = HttpClient.newHttpClient();
  }

  @AfterAll
  void stop() {
    server.stop();
  }

  @Test
  @DisplayName("Admin can mint a key, the X-Api-Key header authenticates, scopes drive authorization")
  void createUseRevoke() throws IOException, InterruptedException {
    String adminToken = login("admin", "admin");

    // 1) create a key scoped to document:read
    Map<String, Object> created = mintKey(adminToken, "doc-reader", "viewer",
        List.of("document:read"));
    String plainKey = (String) created.get("plainKey");
    String keyHash = (String) created.get("keyHash");
    assertNotNull(plainKey);
    assertNotNull(keyHash);
    assertEquals(List.of("document:read"), created.get("scopes"));

    // 2) use it against /api/documents — scope grants access
    HttpResponse<String> documents = sendWithApiKey("GET", "/api/documents", plainKey);
    assertEquals(OK.code(), documents.statusCode(),
        "X-Api-Key with document:read scope must reach the documents endpoint");

    // 3) the same key must NOT be able to delete (no document:delete scope)
    HttpResponse<String> deleteAttempt = sendWithApiKey(
        "DELETE", "/api/documents/1", plainKey);
    assertEquals(FORBIDDEN.code(), deleteAttempt.statusCode(),
        "key without document:delete scope must be refused");

    // 4) revoke it
    HttpResponse<String> revoke = sendJsonAuthed(
        "POST", DemoEndpoints.ADMIN_API_KEYS_REVOKE, adminToken,
        "{\"keyHash\":\"" + keyHash + "\"}");
    assertEquals(OK.code(), revoke.statusCode());

    // 5) the same plain key now fails — ApiKeyAuthenticationService
    //    returns empty for a revoked record, so the resolver falls
    //    through to the bearer path (no token → no subject → 401).
    HttpResponse<String> afterRevoke = sendWithApiKey("GET", "/api/documents", plainKey);
    assertEquals(UNAUTHORIZED.code(), afterRevoke.statusCode());
  }

  @Test
  @DisplayName("Non-admin cannot mint a key")
  void mintRequiresAdmin() throws IOException, InterruptedException {
    String editorToken = login("editor", "editor");
    HttpResponse<String> response = sendJsonAuthed(
        "POST", DemoEndpoints.ADMIN_API_KEYS, editorToken,
        "{\"name\":\"x\",\"subjectId\":\"y\",\"scopes\":[\"document:read\"]}");
    assertEquals(FORBIDDEN.code(), response.statusCode());
  }

  @Test
  @DisplayName("Mint with blank scopes → 400 Bad Request")
  void mintRejectsBlankScopes() throws IOException, InterruptedException {
    String adminToken = login("admin", "admin");
    HttpResponse<String> response = sendJsonAuthed(
        "POST", DemoEndpoints.ADMIN_API_KEYS, adminToken,
        "{\"name\":\"x\",\"subjectId\":\"y\",\"scopes\":[]}");
    assertEquals(BAD_REQUEST.code(), response.statusCode());
  }

  @Test
  @DisplayName("Revoking an unknown keyHash → 404")
  void revokeUnknown() throws IOException, InterruptedException {
    String adminToken = login("admin", "admin");
    HttpResponse<String> response = sendJsonAuthed(
        "POST", DemoEndpoints.ADMIN_API_KEYS_REVOKE, adminToken,
        "{\"keyHash\":\"deadbeef\"}");
    assertEquals(NOT_FOUND.code(), response.statusCode());
  }

  @Test
  @DisplayName("X-Api-Key takes precedence over a stale Bearer token")
  void apiKeyWinsOverBearer() throws IOException, InterruptedException {
    String adminToken = login("admin", "admin");

    // Mint a key with document:read for a synthetic subject id.
    Map<String, Object> created = mintKey(adminToken, "precedence-key",
        "synthetic-bot", List.of("document:read"));
    String plainKey = (String) created.get("plainKey");

    // Send BOTH the bearer token (admin) AND the X-Api-Key (read-only).
    HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/api/me"))
        .header("Authorization", "Bearer " + adminToken)
        .header(DemoSubjectResolver.API_KEY_HEADER, plainKey)
        .GET()
        .build();
    HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

    assertEquals(OK.code(), response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("synthetic-bot", payload.get("subjectId"),
        "API-key path must be picked first; the bearer-token admin must not be returned");
    assertEquals(List.of("document:read"), payload.get("permissions"),
        "the resolved subject must carry the key's scopes, not the admin's permission set");
  }

  // ── helpers ────────────────────────────────────────────────────

  private Map<String, Object> mintKey(String adminToken, String name,
                                      String subjectId, List<String> scopes)
      throws IOException, InterruptedException {
    String scopesJson = scopes.stream()
        .map(s -> "\"" + s + "\"")
        .reduce((a, b) -> a + "," + b).orElse("");
    String body = "{\"name\":\"" + name + "\","
        + "\"subjectId\":\"" + subjectId + "\","
        + "\"scopes\":[" + scopesJson + "]}";
    HttpResponse<String> response = sendJsonAuthed(
        "POST", DemoEndpoints.ADMIN_API_KEYS, adminToken, body);
    assertEquals(CREATED.code(), response.statusCode(),
        "admin must be able to mint a key");
    return DemoJson.decodeObject(response.body());
  }

  private HttpResponse<String> sendWithApiKey(String method, String path, String apiKey)
      throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header(DemoSubjectResolver.API_KEY_HEADER, apiKey)
        .method(method, HttpRequest.BodyPublishers.noBody())
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> sendJsonAuthed(String method, String path,
                                              String bearerToken, String body)
      throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Authorization", "Bearer " + bearerToken)
        .header("Content-Type", "application/json")
        .method(method, HttpRequest.BodyPublishers.ofString(body))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private String login(String username, String password)
      throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
