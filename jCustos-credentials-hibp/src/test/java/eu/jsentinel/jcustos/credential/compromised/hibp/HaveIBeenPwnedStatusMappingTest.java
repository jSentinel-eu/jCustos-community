/*-
 * #%L
 * Security Credentials — HIBP (HaveIBeenPwned) Opt-In
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.compromised.hibp;

import com.sun.net.httpserver.HttpServer;
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * The status mapping of the JDK range lookup over a real loopback {@link HttpServer}: a
 * {@code 429} is {@code RATE_LIMITED}, any other non-2xx is {@code NETWORK}. Both answers carry
 * a padded body, so the empty-body guard (JS-SEC-046) cannot mask the status check.
 */
class HaveIBeenPwnedStatusMappingTest {

  private static final String PADDED_BODY = "0000000000000000000000000000000000A:0\r\n";

  private HttpServer server;

  @BeforeEach
  void enableDevFlag() {
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    System.clearProperty("jcustos.dev");
    if (server != null) {
      server.stop(0);
    }
  }

  @Test
  @DisplayName("a 429 from the range API is a RATE_LIMITED failure")
  void tooManyRequestsIsRateLimited() throws IOException {
    assertEquals(CompromisedPasswordResult.FailureReason.RATE_LIMITED,
        failureFor(HttpStatus.TOO_MANY_REQUESTS));
  }

  @Test
  @DisplayName("a 503 with a body is a NETWORK failure, not a verdict")
  void serviceUnavailableIsNetwork() throws IOException {
    assertEquals(CompromisedPasswordResult.FailureReason.NETWORK,
        failureFor(HttpStatus.SERVICE_UNAVAILABLE));
  }

  private CompromisedPasswordResult.FailureReason failureFor(HttpStatus status) throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/range/", exchange -> {
      byte[] body = PADDED_BODY.getBytes(StandardCharsets.US_ASCII);
      exchange.sendResponseHeaders(status.code(), body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    server.start();
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
            URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/range/"),
            Duration.ofSeconds(5));
    CompromisedPasswordResult result = checker.check(SecretValue.ofString("hunter222"));
    return assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, result).reason();
  }
}
