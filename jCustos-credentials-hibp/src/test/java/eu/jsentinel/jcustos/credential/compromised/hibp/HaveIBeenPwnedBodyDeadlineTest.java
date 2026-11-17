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

import com.sun.net.httpserver.HttpExchange;
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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The range query has one deadline for headers and body, and a body that does not arrive in time
 * is a {@code TIMEOUT} failure - on every JDK. Before, {@code HttpRequest.timeout} bounded the
 * headers only on some JDKs, a mirror that stalled after the headers held the thread of a password
 * change or reset, and where the JDK did bound the body its expiry was reported as
 * {@code NETWORK}. A real {@link HttpServer} on loopback stalls on purpose. The candidate's UTF-8
 * bytes are encoded into one buffer that is zeroed after the check.
 */
@DisplayName("HaveIBeenPwned - a deadline for the whole range query, and the UTF-8 bytes zeroed")
class HaveIBeenPwnedBodyDeadlineTest {

  private static final Duration DEADLINE = Duration.ofMillis(400);
  /** Far beyond the deadline: a check that waits for it has no deadline. */
  private static final long STALL_SECONDS = 20;

  private HttpServer server;
  private ExecutorService handlers;
  /** Released after each test so that no handler outlives it. */
  private final CountDownLatch release = new CountDownLatch(1);

  @BeforeEach
  void enableDevFlag() {
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    System.clearProperty("jcustos.dev");
    release.countDown();
    if (server != null) {
      server.stop(0);
    }
    if (handlers != null) {
      handlers.shutdownNow();
    }
  }

  @Test
  @DisplayName("a 2xx whose body stalls after the headers is a TIMEOUT within the deadline")
  void stalledBodyIsTimeout() throws IOException {
    start(exchange -> {
      exchange.sendResponseHeaders(HttpStatus.OK.code(), 0); // chunked: the body may go on
      OutputStream body = exchange.getResponseBody();
      body.write("0000000000000000000000000000000000A:0\r\n".getBytes(StandardCharsets.US_ASCII));
      body.flush();
      stall();
      body.close();
    });

    long started = System.nanoTime();
    CompromisedPasswordResult result = checker().check(SecretValue.ofString("hunter222"));
    Duration took = Duration.ofNanos(System.nanoTime() - started);

    assertEquals(CompromisedPasswordResult.FailureReason.TIMEOUT,
        assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, result).reason());
    assertTrue(took.compareTo(Duration.ofSeconds(STALL_SECONDS / 2)) < 0,
        "the check must not wait for the stalled body: " + took);
  }

  @Test
  @DisplayName("headers that never come are a TIMEOUT within the deadline as well")
  void stalledHeadersAreTimeout() throws IOException {
    start(exchange -> {
      stall();
      exchange.sendResponseHeaders(HttpStatus.OK.code(), -1);
      exchange.close();
    });

    long started = System.nanoTime();
    CompromisedPasswordResult result = checker().check(SecretValue.ofString("hunter222"));
    Duration took = Duration.ofNanos(System.nanoTime() - started);

    assertEquals(CompromisedPasswordResult.FailureReason.TIMEOUT,
        assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, result).reason());
    assertTrue(took.compareTo(Duration.ofSeconds(STALL_SECONDS / 2)) < 0, took.toString());
  }

  @Test
  @DisplayName("a 429 is RATE_LIMITED at once, even when its body never ends - the body of an error is not read")
  void errorBodyIsNotRead() throws IOException {
    start(exchange -> {
      exchange.sendResponseHeaders(HttpStatus.TOO_MANY_REQUESTS.code(), 0);
      OutputStream body = exchange.getResponseBody();
      body.write("slow down".getBytes(StandardCharsets.US_ASCII));
      body.flush();
      stall();
      body.close();
    });

    assertEquals(CompromisedPasswordResult.FailureReason.RATE_LIMITED,
        assertInstanceOf(CompromisedPasswordResult.CheckFailed.class,
            checker().check(SecretValue.ofString("hunter222"))).reason());
  }

  @Test
  @DisplayName("a body that arrives in time is still read and scanned")
  void timelyBodyIsScanned() throws IOException {
    start(exchange -> {
      byte[] body = "0000000000000000000000000000000000A:0\r\n"
          .getBytes(StandardCharsets.US_ASCII);
      exchange.sendResponseHeaders(HttpStatus.OK.code(), body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });

    assertEquals(CompromisedPasswordResult.Clean.INSTANCE,
        checker().check(SecretValue.ofString("hunter222")));
  }

  @Test
  @DisplayName("the buffer that held the candidate's UTF-8 bytes is zeroed after the check")
  void utf8BytesAreZeroed() {
    List<byte[]> handedOut = new ArrayList<>();
    List<String> prefixes = new ArrayList<>();
    HaveIBeenPwnedCompromisedPasswordChecker checker = new HaveIBeenPwnedCompromisedPasswordChecker(
        prefix -> {
          prefixes.add(prefix);
          // the bytes are in the buffer while the range is asked for
          assertFalse(Arrays.equals(new byte[handedOut.get(0).length], handedOut.get(0)));
          return new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
              "0000000000000000000000000000000000A:0\r\n", null);
        },
        length -> {
          byte[] buffer = new byte[length];
          handedOut.add(buffer);
          return buffer;
        });

    checker.check(SecretValue.ofString("pässwört-hunter222"));

    assertEquals(1, handedOut.size(), "one buffer for the encoding, no other");
    assertArrayEquals(new byte[handedOut.get(0).length], handedOut.get(0),
        "the UTF-8 bytes of the candidate must not stay on the heap");
    assertEquals(List.of(sha1Prefix("pässwört-hunter222")), prefixes,
        "the digest is that of the UTF-8 bytes");
  }

  @Test
  @DisplayName("encodeUtf8 writes what StandardCharsets.UTF_8 writes - umlauts, a surrogate pair, an unpaired surrogate")
  void encodeUtf8MatchesTheJdk() {
    for (String candidate : List.of("", "plain-ascii", "pässwört", "emoji-😀-pair",
        "lone-\uD800-surrogate", "trailing-\uDC00")) {
      char[] chars = candidate.toCharArray();
      byte[] buffer = new byte[chars.length * 3];
      int length = HaveIBeenPwnedCompromisedPasswordChecker.encodeUtf8(chars, buffer);
      ByteBuffer jdk = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
      byte[] expected = new byte[jdk.remaining()];
      jdk.get(expected);
      assertArrayEquals(expected, Arrays.copyOf(buffer, length), candidate);
    }
  }

  private static String sha1Prefix(String candidate) {
    try {
      byte[] digest = java.security.MessageDigest.getInstance("SHA-1")
          .digest(candidate.getBytes(StandardCharsets.UTF_8));
      return String.format("%02X%02X%02X", digest[0], digest[1], digest[2]).substring(0, 5);
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private interface Handler {
    void handle(HttpExchange exchange) throws IOException;
  }

  private void start(Handler handler) throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    handlers = Executors.newCachedThreadPool();
    server.setExecutor(handlers);
    server.createContext("/range/", exchange -> {
      try {
        handler.handle(exchange);
      } catch (IOException clientGone) {
        // the checker cancelled the exchange: expected for the stalling handlers
      }
    });
    server.start();
  }

  private HaveIBeenPwnedCompromisedPasswordChecker checker() {
    return HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/range/"), DEADLINE);
  }

  private void stall() {
    try {
      release.await(STALL_SECONDS, TimeUnit.SECONDS);
    } catch (InterruptedException stopped) {
      Thread.currentThread().interrupt();
    }
  }
}
