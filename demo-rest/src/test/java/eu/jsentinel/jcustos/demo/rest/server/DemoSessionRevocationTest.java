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
import eu.jsentinel.jcustos.rest.HttpStatusDecisionMapper;
import eu.jsentinel.jcustos.rest.RestSessionRevocation;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static com.svenruppert.dependencies.core.net.HttpStatus.UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-131 (CWE-613): a session whose record is revoked stops working over REST. The
 * demo records every login in the published {@code SessionStore} under the session
 * reference and resolves that reference per request; the record is revoked here directly
 * in the store - as an administrator tool or another node would - while the token is still
 * known to {@link DemoTokenStore}. Drives the real server over loopback HTTP.
 */
@DisplayName("Demo REST server — a revoked session record ends the session")
class DemoSessionRevocationTest {

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
    RestSessionRevocation.reset();
  }

  @Test
  @DisplayName("login records an ACTIVE session under the token's reference, never under the token")
  void loginRecordsSessionUnderReference() throws IOException, InterruptedException {
    String token = login("viewer", "viewer");

    SessionRecord record = server.sessionStore()
        .findById(SessionId.of(DemoTokenStore.sessionReference(token)))
        .orElseThrow(() -> new AssertionError("no session record for the login"));
    assertEquals(SessionStatus.ACTIVE, record.status());
    assertEquals("viewer", record.subjectId().value());
    assertTrue(server.sessionStore().findById(SessionId.of(token)).isEmpty(),
        "the token itself must never be a session key");
  }

  @Test
  @DisplayName("a REVOKED record refuses the next request with 401 + Bearer challenge and audits SessionInvalidated")
  void revokedRecordEndsTheSession() throws IOException, InterruptedException {
    String viewerToken = login("viewer", "viewer");
    String adminToken = login("admin", "admin");
    assertEquals(OK.code(), client.me(viewerToken).statusCode(), "fresh session must work");

    SessionId sessionId = SessionId.of(DemoTokenStore.sessionReference(viewerToken));
    SessionRecord record = server.sessionStore().findById(sessionId).orElseThrow();
    server.sessionStore().save(record.withStatus(SessionStatus.REVOKED));

    HttpResponse<String> me = client.me(viewerToken);
    assertEquals(UNAUTHORIZED.code(), me.statusCode(),
        "an authenticated-only route must refuse the revoked session");
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        me.headers().firstValue("WWW-Authenticate").orElse(null));
    HttpResponse<String> documents = client.call("GET", "/api/documents", viewerToken, null);
    assertEquals(UNAUTHORIZED.code(), documents.statusCode(),
        "a permission-protected route must refuse the revoked session");
    assertEquals(OK.code(), client.me(adminToken).statusCode(),
        "another session of the server is unaffected");

    HttpResponse<String> audit = client.call(
        "GET", "/api/audit?type=SessionInvalidated", adminToken, null);
    assertEquals(OK.code(), audit.statusCode());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events =
        (List<Map<String, Object>>) DemoJson.decodeObject(audit.body()).get("events");
    assertTrue(events.stream().anyMatch(e -> "Revoked".equals(e.get("reason"))
            && sessionId.value().equals(e.get("sessionId"))),
        "the refusal must be audited as SessionInvalidated(Revoked) under the reference: " + events);
  }

  @Test
  @DisplayName("logout deletes the session record")
  void logoutDeletesTheRecord() throws IOException, InterruptedException {
    String token = login("editor", "editor");
    SessionId sessionId = SessionId.of(DemoTokenStore.sessionReference(token));
    assertTrue(server.sessionStore().findById(sessionId).isPresent());

    assertEquals(OK.code(), client.logout(token).statusCode());

    assertTrue(server.sessionStore().findById(sessionId).isEmpty(),
        "logout must delete the record of the session");
    assertEquals(UNAUTHORIZED.code(), client.me(token).statusCode());
  }

  private String login(String username, String password) throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode(), "login(" + username + ") must succeed");
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
