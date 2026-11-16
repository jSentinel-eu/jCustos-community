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
import eu.jsentinel.jcustos.rest.RestJCustosVersionFilter;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end coverage of the V00.70 Phase 4c
 * {@link RestJCustosVersionFilter} as wired by
 * {@link DemoRestServer}. Drives the live server (no mocks) to
 * prove that:
 * <ol>
 *   <li>A token issued before a role change continues to work.</li>
 *   <li>An admin-driven {@code setUserRole} bumps the user's
 *       security version → the existing token drifts.</li>
 *   <li>The next request with the stale token returns
 *       {@code 401} + {@code WWW-Authenticate: SessionStale}.</li>
 *   <li>A fresh login captures the new version → the new token
 *       passes the filter.</li>
 *   <li>The drift is recorded as a {@code SessionStale} event in
 *       the audit ring buffer.</li>
 * </ol>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server — JCustosVersion drift detection")
class DemoJCustosVersionDriftTest {

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
  @DisplayName("Role change bumps JCustosVersion → stale token returns 401 + WWW-Authenticate: SessionStale")
  void roleChangeDriftsExistingToken() throws IOException, InterruptedException {
    String viewerToken = login("viewer", "viewer");

    // Token is fresh — /api/me works.
    HttpResponse<String> beforeDrift = client.me(viewerToken);
    assertEquals(OK.code(), beforeDrift.statusCode(),
        "fresh token must work before any role change");

    // Admin promotes viewer to editor — this bumps the JCustosVersion.
    String adminToken = login("admin", "admin");
    HttpResponse<String> roleChange = client.call(
        "PUT", "/api/admin/users/viewer", adminToken,
        "{\"role\":\"ROLE_EDITOR\"}");
    assertEquals(OK.code(), roleChange.statusCode(), "role change must succeed");

    try {
      // The existing viewer token is now stale.
      HttpResponse<String> afterDrift = client.me(viewerToken);
      assertEquals(UNAUTHORIZED.code(), afterDrift.statusCode(),
          "stale token must be refused with 401");
      assertEquals(RestJCustosVersionFilter.SESSION_STALE_CHALLENGE,
          afterDrift.headers().firstValue("WWW-Authenticate").orElse(null),
          "filter must advertise the SessionStale challenge");
      assertEquals("Unauthorized", afterDrift.body(),
          "filter must write the generic perimeter body");

      // Fresh login captures the new version → the new token passes.
      String refreshedToken = login("viewer", "viewer");
      assertEquals(OK.code(), client.me(refreshedToken).statusCode(),
          "fresh login after drift must yield a working token");
    } finally {
      // Restore the seed so subsequent tests see ROLE_VIEWER.
      client.call("PUT", "/api/admin/users/viewer", adminToken,
          "{\"role\":\"ROLE_VIEWER\"}");
    }
  }

  @Test
  @DisplayName("JCustosVersion drift emits a SessionStale audit event")
  void driftPublishesAuditEvent() throws IOException, InterruptedException {
    String viewerToken = login("viewer", "viewer");
    String adminToken = login("admin", "admin");

    HttpResponse<String> roleChange = client.call(
        "PUT", "/api/admin/users/viewer", adminToken,
        "{\"role\":\"ROLE_EDITOR\"}");
    assertEquals(OK.code(), roleChange.statusCode());

    try {
      // Trigger the filter once — that's the call site that publishes the audit event.
      assertEquals(UNAUTHORIZED.code(), client.me(viewerToken).statusCode());

      HttpResponse<String> auditResponse = client.call(
          "GET", "/api/audit?type=SessionStale", adminToken, null);
      assertEquals(OK.code(), auditResponse.statusCode());
      Map<String, Object> payload = DemoJson.decodeObject(auditResponse.body());
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> events = (List<Map<String, Object>>) payload.get("events");
      assertTrue(events.stream()
              .anyMatch(e -> "SessionStale".equals(e.get("type"))
                  && "viewer".equals(e.get("subjectId"))),
          "drift must record a SessionStale event for viewer in the audit log");
    } finally {
      client.call("PUT", "/api/admin/users/viewer", adminToken,
          "{\"role\":\"ROLE_VIEWER\"}");
    }
  }

  @Test
  @DisplayName("Filter is a no-op for requests without a token")
  void noTokenIsPassThrough() throws IOException, InterruptedException {
    // No version context → filter returns true → request continues into the
    // authentication filter, which produces the regular 401 Unauthorized.
    HttpResponse<String> response = client.me(null);
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
    assertEquals("Unauthorized", response.body());
    // The SessionStale challenge must NOT be advertised when there's no token —
    // that header is reserved for the drift outcome. Since JS-SEC-086 the
    // authentication filter's 401 carries the generic Bearer challenge instead.
    assertEquals("Bearer",
        response.headers().firstValue("WWW-Authenticate").orElse(null),
        "no version context → Bearer challenge, not SessionStale");
  }

  private String login(String username, String password)
      throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode(),
        "login(" + username + ") must succeed");
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
