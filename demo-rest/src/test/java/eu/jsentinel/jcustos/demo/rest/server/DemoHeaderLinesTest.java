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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.demo.rest.cli.CliOperationClient;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.TrustedProxyClientAddressResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.BAD_REQUEST;
import static com.svenruppert.dependencies.core.net.HttpStatus.CREATED;
import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-113 (CWE-348, CWE-290): every header line reaches the library, and a repeated
 * credential header is refused before any filter or handler runs. The requests are written
 * byte by byte over a raw loopback socket, because an HTTP client library folds or refuses
 * repeated header lines itself.
 */
@DisplayName("Demo REST server — header lines (X-Forwarded-For, repeated Authorization)")
class DemoHeaderLinesTest {

  private static final String CLIENT_FORGED = "203.0.113.9";
  private static final String PROXY_APPENDED = "198.51.100.7";

  private DemoRestServer server;
  private CliOperationClient client;
  private ClientAddressResolver previousResolver;

  @BeforeEach
  void start() throws IOException {
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled(), true);
    client = new CliOperationClient("http://localhost:" + server.port());
    previousResolver = JCustosServiceResolver.findClientAddressResolver().orElse(null);
  }

  @AfterEach
  void stop() {
    server.stop();
    JCustosServiceResolver.setClientAddressResolver(previousResolver);
  }

  @Test
  @DisplayName("two Authorization lines: 400, the handler does not run")
  void repeatedAuthorizationIsRefusedBeforeTheHandler() throws IOException, InterruptedException {
    String editorToken = login("editor", "editor");
    int before = documentCount(editorToken);

    String body = "{\"title\":\"smuggled\"}";
    String raw = "POST /api/documents HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Authorization: Bearer " + editorToken + "\r\n"
        + "Authorization: Bearer " + editorToken + "\r\n"
        + "Content-Type: application/json\r\n"
        + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
        + "Connection: close\r\n"
        + "\r\n"
        + body;
    String response = exchange(raw);

    assertTrue(response.startsWith("HTTP/1.1 " + BAD_REQUEST.code()),
        "a repeated Authorization header must be refused with 400: " + statusLine(response));
    assertEquals(before, documentCount(editorToken),
        "the create handler must not have run");
  }

  @Test
  @DisplayName("one Authorization line over the same raw socket path is served (control)")
  void singleAuthorizationIsServed() throws IOException, InterruptedException {
    String editorToken = login("editor", "editor");
    String body = "{\"title\":\"regular\"}";
    String raw = "POST /api/documents HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Authorization: Bearer " + editorToken + "\r\n"
        + "Content-Type: application/json\r\n"
        + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
        + "Connection: close\r\n"
        + "\r\n"
        + body;

    String response = exchange(raw);

    assertTrue(response.startsWith("HTTP/1.1 " + CREATED.code()),
        "a single Authorization line must be served: " + statusLine(response));
  }

  @Test
  @DisplayName("two X-Forwarded-For lines: the trusted proxy's line decides the client address")
  void everyForwardedForLineReachesTheResolver() throws IOException, InterruptedException {
    JCustosServiceResolver.setClientAddressResolver(
        new TrustedProxyClientAddressResolver(List.of("127.0.0.1/32", "::1/128")));
    String adminToken = login("admin", "admin");

    String body = "{\"username\":\"viewer\",\"password\":\"viewer\"}";
    String raw = "POST /api/login HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "X-Forwarded-For: " + CLIENT_FORGED + "\r\n"
        + "X-Forwarded-For: " + PROXY_APPENDED + "\r\n"
        + "Content-Type: application/json\r\n"
        + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
        + "Connection: close\r\n"
        + "\r\n"
        + body;
    String response = exchange(raw);
    assertTrue(response.startsWith("HTTP/1.1 " + OK.code()), statusLine(response));

    HttpResponse<String> audit = client.call(
        "GET", "/api/audit?type=LoginSucceeded", adminToken, null);
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events =
        (List<Map<String, Object>>) DemoJson.decodeObject(audit.body()).get("events");
    Map<String, Object> newest = events.stream()
        .filter(e -> "viewer".equals(e.get("username")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("LoginSucceeded for viewer missing: " + events));
    assertEquals(PROXY_APPENDED, newest.get("clientAddress"),
        "the line the trusted proxy appended must decide, not the line the client sent");
  }

  private String exchange(String raw) throws IOException {
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), server.port())) {
      socket.setSoTimeout(5_000);
      OutputStream out = socket.getOutputStream();
      out.write(raw.getBytes(StandardCharsets.UTF_8));
      out.flush();
      InputStream in = socket.getInputStream();
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      byte[] chunk = new byte[1024];
      int read;
      while ((read = in.read(chunk)) >= 0) {
        buffer.write(chunk, 0, read);
      }
      return buffer.toString(StandardCharsets.UTF_8);
    }
  }

  private static String statusLine(String response) {
    int end = response.indexOf("\r\n");
    return end < 0 ? response : response.substring(0, end);
  }

  private int documentCount(String token) throws IOException, InterruptedException {
    HttpResponse<String> response = client.call("GET", "/api/documents", token, null);
    assertEquals(OK.code(), response.statusCode());
    List<?> documents = (List<?>) DemoJson.decodeObject(response.body()).get("documents");
    return documents.size();
  }

  private String login(String username, String password) throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(OK.code(), response.statusCode(), "login(" + username + ") must succeed");
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }
}
