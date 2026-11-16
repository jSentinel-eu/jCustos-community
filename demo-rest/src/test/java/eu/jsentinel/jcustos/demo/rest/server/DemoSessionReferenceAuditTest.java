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

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.demo.rest.cli.CliOperationClient;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-117 (CWE-522, CWE-532), finding 6 of the 2026-11-10 analysis: the audit trail
 * names a session by its reference, never by the bearer token. Before the fix the login
 * published {@code LoginSucceeded} with the token as {@code sessionId}, and
 * {@code GET /api/audit} handed every active token to anyone holding {@code audit:read}.
 * Drives the real server over loopback HTTP.
 */
@DisplayName("Demo REST server — audit names sessions by reference, never by token")
class DemoSessionReferenceAuditTest {

  private DemoRestServer server;
  private CliOperationClient client;

  @BeforeEach
  void start() throws IOException {
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    client = new CliOperationClient("http://localhost:" + server.port());
  }

  @AfterEach
  void stop() {
    server.stop();
  }

  @Test
  @DisplayName("GET /api/audit contains no issued token; LoginSucceeded carries the sref- reference")
  void auditContainsNoToken() throws IOException, InterruptedException {
    String viewerToken = login("viewer", "viewer");
    assertEquals(OK.code(), client.me(viewerToken).statusCode());
    assertEquals(OK.code(), client.logout(viewerToken).statusCode());
    String editorToken = login("editor", "editor");
    String adminToken = login("admin", "admin");

    HttpResponse<String> audit = client.call("GET", "/api/audit", adminToken, null);
    assertEquals(OK.code(), audit.statusCode());
    for (String token : List.of(viewerToken, editorToken, adminToken)) {
      // no substring of the token either - a prefix is enough to narrow a guess
      assertFalse(audit.body().contains(token.substring(0, 12)),
          "the audit answer must not contain a bearer token (or a part of it)");
    }

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events =
        (List<Map<String, Object>>) DemoJson.decodeObject(audit.body()).get("events");
    Map<String, Object> viewerLogin = events.stream()
        .filter(e -> "LoginSucceeded".equals(e.get("type")) && "viewer".equals(e.get("username")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("LoginSucceeded for viewer missing"));
    String sessionId = String.valueOf(viewerLogin.get("sessionId"));
    assertTrue(SessionRef.isReference(sessionId),
        "LoginSucceeded.sessionId must be a session reference: " + sessionId);
    assertEquals(SessionRef.of(viewerToken), sessionId,
        "the reference must be the one the token's session is recorded under");
  }

  private String login(String username, String password) throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode(), "login(" + username + ") must succeed");
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
