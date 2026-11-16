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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end coverage of the V00.70 Phase-7b refresh-token rotation
 * endpoints in demo-rest:
 * <ul>
 *   <li>{@code POST /api/auth/token/issue} mints a fresh
 *       {@link eu.jsentinel.jcustos.authentication.TokenService.TokenPair}.</li>
 *   <li>{@code POST /api/auth/token/refresh} consumes the refresh
 *       token and returns a NEW pair (rotation).</li>
 *   <li>Replaying the consumed refresh token returns 401 +
 *       {@code WWW-Authenticate: TokenRotated}.</li>
 *   <li>{@code POST /api/auth/token/revoke} invalidates an active
 *       refresh token; rotating it afterwards fails.</li>
 * </ul>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server — Phase-7b refresh-token rotation")
class DemoTokenServiceTest {

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
  @DisplayName("issue → returns access + refresh tokens with TTLs")
  void issueReturnsTokenPair() throws IOException, InterruptedException {
    Map<String, Object> pair = issue("alice");
    assertNotNull(pair.get("accessToken"));
    assertNotNull(pair.get("refreshToken"));
    assertNotNull(pair.get("accessExpiresAt"));
    assertNotNull(pair.get("refreshExpiresAt"));
    assertEquals("alice", pair.get("subjectId"));
  }

  @Test
  @DisplayName("refresh → consumes the old refresh token + returns a new pair")
  void refreshRotatesPair() throws IOException, InterruptedException {
    Map<String, Object> first = issue("rotate-me");
    String originalRefresh = (String) first.get("refreshToken");

    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_REFRESH, null,
        "{\"refreshToken\":\"" + originalRefresh + "\"}");
    assertEquals(OK.code(), response.statusCode());

    Map<String, Object> rotated = DemoJson.decodeObject(response.body());
    assertNotNull(rotated.get("accessToken"));
    assertNotEquals(first.get("accessToken"), rotated.get("accessToken"),
        "rotation must produce a fresh access token");
    assertNotEquals(originalRefresh, rotated.get("refreshToken"),
        "rotation must produce a fresh refresh token");
  }

  @Test
  @DisplayName("Replaying a consumed refresh token → 401 + WWW-Authenticate: TokenRotated")
  void replayDetectsConsumedRefresh() throws IOException, InterruptedException {
    Map<String, Object> first = issue("replay-detector");
    String refresh = (String) first.get("refreshToken");

    // First rotation succeeds.
    assertEquals(OK.code(), client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_REFRESH, null,
        "{\"refreshToken\":\"" + refresh + "\"}").statusCode());

    // Replaying the now-consumed refresh token must be refused.
    HttpResponse<String> replay = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_REFRESH, null,
        "{\"refreshToken\":\"" + refresh + "\"}");
    assertEquals(UNAUTHORIZED.code(), replay.statusCode());
    assertEquals("TokenRotated",
        replay.headers().firstValue("WWW-Authenticate").orElse(null));
  }

  @Test
  @DisplayName("revoke → kills the refresh token, subsequent refresh fails")
  void revokeKillsRefresh() throws IOException, InterruptedException {
    Map<String, Object> first = issue("revokable");
    String refresh = (String) first.get("refreshToken");

    HttpResponse<String> revoke = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_REVOKE, null,
        "{\"refreshToken\":\"" + refresh + "\"}");
    assertEquals(OK.code(), revoke.statusCode());

    HttpResponse<String> rotateAfter = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_REFRESH, null,
        "{\"refreshToken\":\"" + refresh + "\"}");
    assertEquals(UNAUTHORIZED.code(), rotateAfter.statusCode(),
        "revoked refresh must fail rotation");
  }

  @Test
  @DisplayName("issue with blank subjectId → 400")
  void issueRejectsBlankSubject() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_ISSUE, null,
        "{\"subjectId\":\"\"}");
    assertEquals(BAD_REQUEST.code(), response.statusCode());
  }

  @Test
  @DisplayName("refresh with unknown token → 401")
  void refreshRejectsUnknownToken() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_REFRESH, null,
        "{\"refreshToken\":\"there-is-no-such-token-anywhere\"}");
    assertEquals(UNAUTHORIZED.code(), response.statusCode());
  }

  private Map<String, Object> issue(String subjectId)
      throws IOException, InterruptedException {
    HttpResponse<String> response = client.call(
        "POST", DemoEndpoints.AUTH_TOKEN_ISSUE, null,
        "{\"subjectId\":\"" + subjectId + "\"}");
    assertEquals(OK.code(), response.statusCode());
    return DemoJson.decodeObject(response.body());
  }
}
