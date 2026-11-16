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
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Brute-force throttling end-to-end against the real REST server.
 * <p>
 * Uses an aggressive {@link InMemoryLoginAttemptPolicy} configuration so
 * the lockout is reached quickly without slowing the test down.
 */
@DisplayName("Demo REST server — brute-force throttling")
class DemoBruteForceTest {

  private static final int FAILURE_THRESHOLD = 3;

  private DemoRestServer server;
  private final HttpClient http = HttpClient.newHttpClient();

  @BeforeEach
  void start() throws IOException {
    LoginAttemptConfiguration tightConfig = new LoginAttemptConfiguration(
        FAILURE_THRESHOLD,
        Duration.ofMinutes(5),
        Duration.ofMinutes(5),
        Duration.ofMinutes(10));
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(
        tightConfig, Clock.systemUTC(), null);

    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), policy,
        new InMemoryLoginAttemptPolicy(), true);
  }

  @AfterEach
  void stop() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  @DisplayName("threshold-many wrong logins → next attempt is locked out with 429")
  void lockoutAfterThreshold() throws Exception {
    String base = "http://localhost:" + server.port();

    for (int i = 0; i < FAILURE_THRESHOLD; i++) {
      HttpResponse<String> response = postLogin(base, "admin", "wrong");
      assertEquals(UNAUTHORIZED.code(), response.statusCode(),
          "every wrong-password attempt before lockout must return 401");
    }

    // Even with the correct password, the next attempt is throttled
    HttpResponse<String> locked = postLogin(base, "admin", "admin");
    assertEquals(TOO_MANY_REQUESTS.code(), locked.statusCode(),
        "after the threshold the next attempt must be locked out");
    assertEquals("Too Many Requests", locked.body());
  }

  @Test
  @DisplayName("a successful login before the threshold resets the counter")
  void successResetsCounter() throws Exception {
    String base = "http://localhost:" + server.port();

    // 1 fewer failure than threshold so the lockout is not yet reached
    for (int i = 0; i < FAILURE_THRESHOLD - 1; i++) {
      assertEquals(UNAUTHORIZED.code(), postLogin(base, "admin", "wrong").statusCode());
    }
    // valid login → resets
    HttpResponse<String> ok = postLogin(base, "admin", "admin");
    assertEquals(OK.code(), ok.statusCode());

    // After reset we get the full quota of failures back
    for (int i = 0; i < FAILURE_THRESHOLD - 1; i++) {
      assertEquals(UNAUTHORIZED.code(), postLogin(base, "admin", "wrong").statusCode(),
          "counter must have reset after the successful login");
    }
  }

  @Test
  @DisplayName("a fresh policy is unaffected by audit infrastructure failures")
  void auditFailureDoesNotBlockLogin() throws Exception {
    // Plain integration smoke — login still succeeds against the real server
    String base = "http://localhost:" + server.port();
    HttpResponse<String> ok = postLogin(base, "viewer", "viewer");
    assertEquals(OK.code(), ok.statusCode());
    assertNotNull(DemoJson.decodeObject(ok.body()).get("token"));
  }

  // ── Helpers ───────────────────────────────────────────────────

  private HttpResponse<String> postLogin(String base, String user, String password) throws Exception {
    String json = DemoJson.encode(Map.of("username", user, "password", password));
    HttpRequest request = HttpRequest.newBuilder(URI.create(base + DemoEndpoints.LOGIN))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(json))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  // Suppress an unused import warning if Instant / ZoneOffset get tidied later
  @SuppressWarnings("unused")
  private static Instant epoch() {
    return Instant.EPOCH.atZone(ZoneOffset.UTC).toInstant();
  }
}
