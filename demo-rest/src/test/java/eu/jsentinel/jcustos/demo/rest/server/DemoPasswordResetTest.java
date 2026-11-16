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
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end coverage of the V00.70 Phase-7a account-lifecycle
 * endpoints exposed by demo-rest:
 * {@code POST /api/password-reset/request} → issued token (demo
 * convenience: token returned in body so tests can pick it up);
 * {@code POST /api/password-reset/consume} → single-use, idempotent.
 * <p>
 * Drives the live server (no mocks) and asserts on observable
 * behaviour: status codes, body shape, audit emission.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server — Phase-7a password-reset endpoints")
class DemoPasswordResetTest {

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
  @DisplayName("request → returns a plain token + expiresAt for the subject")
  void requestIssuesToken() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.PASSWORD_RESET_REQUEST, null,
        "{\"subjectId\":\"viewer\"}");
    assertEquals(OK.code(), response.statusCode());

    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertEquals("viewer", payload.get("subjectId"));
    assertNotNull(payload.get("token"), "request must echo the plain token");
    assertNotNull(payload.get("expiresAt"), "request must surface expiresAt");
    assertTrue(((String) payload.get("token")).length() > 16,
        "token must carry enough entropy to be unguessable");
  }

  @Test
  @DisplayName("consume → 200 + subjectId on the first call, 410 Gone on the second")
  void consumeIsSingleUse() throws IOException, InterruptedException {
    String token = issueToken("editor");

    HttpResponse<String> first = client.call(
        "POST", DemoEndpoints.PASSWORD_RESET_CONSUME, null,
        "{\"token\":\"" + token + "\"}");
    assertEquals(OK.code(), first.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(first.body());
    assertEquals("editor", payload.get("subjectId"));

    HttpResponse<String> second = client.call(
        "POST", DemoEndpoints.PASSWORD_RESET_CONSUME, null,
        "{\"token\":\"" + token + "\"}");
    assertEquals(NOT_FOUND.code(), second.statusCode(),
        "already-consumed token resolves to the store's not-found branch");
  }

  @Test
  @DisplayName("consume with an unknown token → 404 Not Found")
  void consumeRejectsUnknownToken() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.PASSWORD_RESET_CONSUME, null,
        "{\"token\":\"this-token-was-never-issued-and-cannot-exist\"}");
    assertEquals(NOT_FOUND.code(), response.statusCode());
  }

  @Test
  @DisplayName("request with blank subjectId → 400 Bad Request")
  void requestRejectsBlankSubject() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.PASSWORD_RESET_REQUEST, null,
        "{\"subjectId\":\"\"}");
    assertEquals(BAD_REQUEST.code(), response.statusCode());
  }

  @Test
  @DisplayName("request emits a PasswordResetRequested audit event")
  void requestPublishesAudit() throws IOException, InterruptedException {
    issueToken("admin");

    String adminToken = login("admin", "admin");
    HttpResponse<String> audit = client.call(
        "GET", "/api/audit?type=PasswordResetRequested", adminToken, null);
    assertEquals(OK.code(), audit.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(audit.body());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events = (List<Map<String, Object>>) payload.get("events");
    assertTrue(events.stream()
            .anyMatch(e -> "PasswordResetRequested".equals(e.get("type"))),
        "request must publish a PasswordResetRequested audit event");
  }

  private String issueToken(String subjectId) throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.PASSWORD_RESET_REQUEST, null,
        "{\"subjectId\":\"" + subjectId + "\"}");
    assertEquals(OK.code(), response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }

  private String login(String username, String password)
      throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
