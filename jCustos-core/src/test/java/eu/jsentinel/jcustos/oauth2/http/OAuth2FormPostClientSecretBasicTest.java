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
package eu.jsentinel.jcustos.oauth2.http;

import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Defect 3c7ec536 - RFC 6749 §2.3.1 (CWE-116): for {@code client_secret_basic} the client id
 * and the secret are first encoded with {@code application/x-www-form-urlencoded} (Appendix
 * B), then {@code id:secret} is Base64-encoded. A real JDK {@link HttpServer} on loopback
 * decodes the header the way a compliant authorisation server does - Base64, split at the
 * FIRST {@code :}, form-urldecode both parts - and must arrive at the values the client was
 * configured with.
 */
@DisplayName("3c7ec536 — client_secret_basic form-urlencodes id and secret before Base64 (RFC 6749 §2.3.1)")
class OAuth2FormPostClientSecretBasicTest {

  private static final String BASIC_PREFIX = "Basic ";

  private HttpServer server;
  private URI endpoint;
  /** What the server read: the Base64-decoded user-info, then id and secret, or the failure. */
  private final AtomicReference<String> receivedUserInfo = new AtomicReference<>();
  private final AtomicReference<List<String>> receivedCredentials = new AtomicReference<>();
  private final AtomicReference<String> decodingFailure = new AtomicReference<>();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      exchange.getRequestBody().readAllBytes();
      decodeAsCompliantServer(exchange.getRequestHeaders().getFirst("Authorization"));
      byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  /** RFC 6749 §2.3.1 read by the server: Base64, split at the first ':', form-urldecode both. */
  private void decodeAsCompliantServer(String authorization) {
    try {
      String userInfo = new String(Base64.getDecoder().decode(
          authorization.substring(BASIC_PREFIX.length())), StandardCharsets.UTF_8);
      receivedUserInfo.set(userInfo);
      int separator = userInfo.indexOf(':');
      receivedCredentials.set(List.of(
          URLDecoder.decode(userInfo.substring(0, separator), StandardCharsets.UTF_8),
          URLDecoder.decode(userInfo.substring(separator + 1), StandardCharsets.UTF_8)));
    } catch (RuntimeException malformed) {
      // a raw '%' that starts no valid escape is refused by the decoder, as by a server
      decodingFailure.set(malformed.getClass().getSimpleName());
    }
  }

  private List<String> sendBasic(String clientId, String secret) {
    OAuth2FormPost.post(HttpClient.newHttpClient(), endpoint, Map.of("grant_type", "client_credentials"),
            new ClientAuthentication.ClientSecretBasic(clientId, SecretValue.ofString(secret)))
        .getOrThrow();
    assertNull(decodingFailure.get(), "the server could not form-urldecode the credentials");
    return receivedCredentials.get();
  }

  @Test
  @DisplayName("a ':' in the client id does not move the split; '%', '+', space and 'ü' in the secret arrive unchanged")
  void reservedCharactersRoundTrip() {
    String clientId = "tenant:client-42";
    String secret = "p%41ss+word with ü";

    assertEquals(List.of(clientId, secret), sendBasic(clientId, secret));
    assertEquals("tenant%3Aclient-42:p%2541ss%2Bword+with+%C3%BC", receivedUserInfo.get(),
        "the one unescaped ':' is the separator; '%' and '+' are escaped, a space is '+'");
  }

  @Test
  @DisplayName("the example of RFC 6749 Appendix B encodes exactly as the RFC shows")
  void appendixBExample() {
    // U+0020 U+0025 U+0026 U+002B U+00A3 U+20AC -> "+%25%26%2B%C2%A3%E2%82%AC"
    String secret = " %&+£€";

    assertEquals(List.of("rp", secret), sendBasic("rp", secret));
    assertEquals("rp:+%25%26%2B%C2%A3%E2%82%AC", receivedUserInfo.get());
  }

  @Test
  @DisplayName("URLEncoder's choices beyond HTML 4.01 - '*' kept, '~' escaped - decode to the original value")
  void unreservedCharacters() {
    String secret = "a*b-c.d_e~f=g&h/i";

    assertEquals(List.of("rp.client_1", secret), sendBasic("rp.client_1", secret));
    assertEquals("rp.client_1:a*b-c.d_e%7Ef%3Dg%26h%2Fi", receivedUserInfo.get());
  }

  @Test
  @DisplayName("plain ASCII credentials keep the header they always had")
  void plainCredentialsUnchanged() {
    assertEquals(List.of("rp", "s3cret"), sendBasic("rp", "s3cret"));
    assertEquals("rp:s3cret", receivedUserInfo.get());
    assertTrue(receivedCredentials.get().stream().noneMatch(String::isEmpty));
  }
}
