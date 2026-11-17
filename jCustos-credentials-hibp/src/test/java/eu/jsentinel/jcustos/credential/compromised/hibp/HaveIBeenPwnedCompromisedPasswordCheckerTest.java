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

import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HaveIBeenPwnedCompromisedPasswordCheckerTest {

  /** JS-SEC-098: since 00.84.00 a range-API stub on loopback http needs the dev flag. */
  @BeforeEach
  void enableDevFlag() {
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void clearDevFlag() {
    System.clearProperty("jcustos.dev");
  }

  /** Records every prefix passed to the range lookup. */
  private static final class CapturingLookup implements
      Function<String, HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse> {
    final List<String> prefixes = new ArrayList<>();
    final Function<String, HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse> delegate;

    CapturingLookup(
        Function<String, HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse> delegate) {
      this.delegate = delegate;
    }

    @Override
    public HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse apply(String prefix) {
      prefixes.add(prefix);
      return delegate.apply(prefix);
    }
  }

  private static String sha1HexUpper(String s) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-1").digest(s.getBytes("UTF-8"));
      StringBuilder sb = new StringBuilder();
      for (byte b : d) {
        sb.append(String.format("%02X", b));
      }
      return sb.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  @DisplayName("Only the first five SHA-1 hex chars are sent — no plaintext leaves the JVM")
  void onlyPrefixIsTransmitted() {
    CapturingLookup lookup = new CapturingLookup(
        prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
            "", null));
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(lookup);
    checker.check(SecretValue.ofString("hunter222"));
    assertEquals(1, lookup.prefixes.size());
    String prefix = lookup.prefixes.get(0);
    assertEquals(5, prefix.length(),
        "the prefix must be exactly 5 hex characters");
    assertTrue(prefix.matches("[0-9A-F]{5}"),
        "the prefix must be uppercase hex");
    // verify it really matches the candidate's SHA-1 prefix
    String expected = sha1HexUpper("hunter222").substring(0, 5);
    assertEquals(expected, prefix);
    // verify nothing in the captured prefix list reveals the plaintext
    for (String p : lookup.prefixes) {
      assertTrue(!p.toLowerCase(Locale.ROOT).contains("hunter"),
          "prefix must not contain plaintext");
    }
  }

  @Test
  @DisplayName("Suffix match in response body produces Pwned with reported count")
  void suffixMatchProducesPwned() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5);
    String body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7\n"
        + suffix + ":42\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:9\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("hunter222"));
    CompromisedPasswordResult.Pwned p = assertInstanceOf(
        CompromisedPasswordResult.Pwned.class, r);
    assertEquals(42L, p.occurrences());
  }

  @Test
  @DisplayName("a padding entry (suffix match with count 0) yields Clean, not a false-positive Pwned (R022)")
  void paddingEntryCountZeroIsClean() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5);
    // Add-Padding responses include the queried suffix with count 0 when the
    // password is not actually breached. The old Math.max(count, 1) turned that
    // into a false-positive Pwned(1).
    String body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n"
        + suffix + ":0\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:0\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("hunter222")));
  }

  @Test
  @DisplayName("R12: an oversized range body is bounded and degrades to a NETWORK failure (no OOM)")
  void oversizedBodyIsBoundedAsNetworkFailure() throws Exception {
    com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
        new java.net.InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/range/", exchange -> {
      // 2 MiB of body — well past the 1 MiB cap. A hostile/compromised mirror
      // could stream far more; the checker must not buffer it whole.
      int size = 2 * 1024 * 1024;
      exchange.sendResponseHeaders(200, size);
      byte[] chunk = new byte[8192];
      java.util.Arrays.fill(chunk, (byte) 'A');
      try (java.io.OutputStream os = exchange.getResponseBody()) {
        int written = 0;
        while (written < size) {
          int n = Math.min(chunk.length, size - written);
          os.write(chunk, 0, n);
          written += n;
        }
      }
    });
    server.start();
    try {
      java.net.URI endpoint = java.net.URI.create(
          "http://127.0.0.1:" + server.getAddress().getPort() + "/range/");
      HaveIBeenPwnedCompromisedPasswordChecker checker =
          HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
              endpoint, java.time.Duration.ofSeconds(5));
      CompromisedPasswordResult result = checker.check(SecretValue.ofString("hunter222"));
      CompromisedPasswordResult.CheckFailed failed =
          assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, result,
              "an over-cap body must degrade to a failure, never report pwned/clean");
      assertEquals(CompromisedPasswordResult.FailureReason.NETWORK, failed.reason());
    } finally {
      server.stop(0);
    }
  }

  @Test
  @DisplayName("usingJdkHttpClient sends the Add-Padding: true header (R022)")
  void sendsAddPaddingHeader() throws Exception {
    com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
        new java.net.InetSocketAddress("127.0.0.1", 0), 0);
    java.util.concurrent.atomic.AtomicReference<String> captured =
        new java.util.concurrent.atomic.AtomicReference<>();
    server.createContext("/range/", exchange -> {
      captured.set(exchange.getRequestHeaders().getFirst("Add-Padding"));
      byte[] body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n"
          .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      exchange.sendResponseHeaders(200, body.length);
      try (java.io.OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    try {
      java.net.URI endpoint = java.net.URI.create(
          "http://127.0.0.1:" + server.getAddress().getPort() + "/range/");
      HaveIBeenPwnedCompromisedPasswordChecker checker =
          HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
              endpoint, java.time.Duration.ofSeconds(5));
      checker.check(SecretValue.ofString("hunter222"));
      assertEquals("true", captured.get(),
          "the HIBP range request must carry Add-Padding: true");
    } finally {
      server.stop(0);
    }
  }

  @Test
  @DisplayName("No suffix match yields Clean")
  void noSuffixMatchClean() {
    String body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7\n"
        + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:9\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE,
        checker.check(SecretValue.ofString("an-unguessable-passphrase")));
  }

  @Test
  @DisplayName("JS-SEC-046: an empty 2xx body fails CLOSED (CheckFailed), not Clean (a stripped body must not pass a breached password)")
  void emptyBodyFailsClosed() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                "", null));
    // with Add-Padding a real range response is never empty; an empty body means a hostile/broken
    // mirror, so we must not silently accept the password.
    CompromisedPasswordResult.CheckFailed failed = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class,
        checker.check(SecretValue.ofString("hunter222")));
    // exit-review F3: labelled precisely as a protocol anomaly, not a transport failure.
    assertEquals(CompromisedPasswordResult.FailureReason.MALFORMED_RESPONSE, failed.reason());
  }

  @Test
  @DisplayName("JS-SEC-046: usingJdkHttpClient rejects a non-loopback http:// endpoint")
  void rejectsPlainHttpEndpoint() {
    assertThrows(IllegalArgumentException.class, () ->
        HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
            java.net.URI.create("http://mirror.example.com/range/"), java.time.Duration.ofSeconds(2)));
  }

  @Test
  @DisplayName("JS-SEC-046/098: usingJdkHttpClient accepts https and, with -Djcustos.dev=true, loopback http")
  void acceptsHttpsAndLoopbackHttp() {
    // none throws at construction
    for (String uri : List.of("https://api.pwnedpasswords.com/range/", "http://127.0.0.1:8080/range/",
        "http://127.0.0.2:8080/range/", "http://[::1]:8080/range/", "http://localhost:8080/range/")) {
      HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
          java.net.URI.create(uri), java.time.Duration.ofSeconds(2));
    }
  }

  @Test
  @DisplayName("JS-SEC-098: without -Djcustos.dev=true loopback http is refused like any other http")
  void rejectsLoopbackHttpWithoutDevFlag() {
    System.clearProperty("jcustos.dev");
    for (String uri : List.of("http://127.0.0.1:8080/range/", "http://localhost:8080/range/",
        "http://[::1]:8080/range/")) {
      IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, () ->
          HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
              java.net.URI.create(uri), java.time.Duration.ofSeconds(2)), uri);
      assertTrue(refused.getMessage().startsWith("hibp/endpoint-not-https: "), refused.getMessage());
    }
    HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
        HaveIBeenPwnedCompromisedPasswordChecker.DEFAULT_ENDPOINT, java.time.Duration.ofSeconds(2));
  }

  @Test
  @DisplayName("JS-SEC-098: a lookalike of a loopback host is refused even with -Djcustos.dev=true")
  void rejectsLoopbackLookalike() {
    for (String uri : List.of("http://localhost.evil.example/range/", "http://127.0.0.1.nip.io/range/",
        "http://localhost@mirror.example/range/")) {
      assertThrows(IllegalArgumentException.class, () ->
          HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
              java.net.URI.create(uri), java.time.Duration.ofSeconds(2)), uri);
    }
  }

  @Test
  @DisplayName("Suffix match is case-insensitive (server may respond in lower or mixed case)")
  void suffixMatchCaseInsensitive() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5).toLowerCase(Locale.ROOT);
    String body = suffix + ":3\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("hunter222"));
    assertInstanceOf(CompromisedPasswordResult.Pwned.class, r);
  }

  @Test
  @DisplayName("Range lookup reporting NETWORK propagates to CheckFailed.NETWORK")
  void networkFailurePropagates() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                null, CompromisedPasswordResult.FailureReason.NETWORK));
    CompromisedPasswordResult r = checker.check(
        SecretValue.ofString("anything"));
    CompromisedPasswordResult.CheckFailed cf = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class, r);
    assertEquals(CompromisedPasswordResult.FailureReason.NETWORK, cf.reason());
  }

  @Test
  @DisplayName("Range lookup reporting RATE_LIMITED propagates")
  void rateLimitedPropagates() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                null, CompromisedPasswordResult.FailureReason.RATE_LIMITED));
    CompromisedPasswordResult.CheckFailed cf = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class,
        checker.check(SecretValue.ofString("anything")));
    assertEquals(CompromisedPasswordResult.FailureReason.RATE_LIMITED,
        cf.reason());
  }

  @Test
  @DisplayName("Unexpected RuntimeException from the lookup degrades to CheckFailed.UNKNOWN")
  void unexpectedExceptionDegrades() {
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> {
              throw new RuntimeException("boom");
            });
    CompromisedPasswordResult.CheckFailed cf = assertInstanceOf(
        CompromisedPasswordResult.CheckFailed.class,
        checker.check(SecretValue.ofString("anything")));
    assertEquals(CompromisedPasswordResult.FailureReason.UNKNOWN, cf.reason());
  }

  @Test
  @DisplayName("RangeResponse invariant: exactly one of body / failure is non-null")
  void rangeResponseInvariant() {
    assertThrows(IllegalArgumentException.class,
        () -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
            null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
            "x", CompromisedPasswordResult.FailureReason.NETWORK));
  }

  @Test
  @DisplayName("usingJdkHttpClient factory rejects null endpoint and timeout")
  void factoryInvariants() {
    assertThrows(NullPointerException.class,
        () -> HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
            null, java.time.Duration.ofSeconds(2)));
    assertThrows(NullPointerException.class,
        () -> HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
            HaveIBeenPwnedCompromisedPasswordChecker.DEFAULT_ENDPOINT, null));
  }

  @Test
  @DisplayName("Response with CR-LF line endings is handled")
  void crlfLineEndings() {
    String hex = sha1HexUpper("hunter222");
    String suffix = hex.substring(5);
    String body = suffix + ":11\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n";
    HaveIBeenPwnedCompromisedPasswordChecker checker =
        new HaveIBeenPwnedCompromisedPasswordChecker(
            prefix -> new HaveIBeenPwnedCompromisedPasswordChecker.RangeResponse(
                body, null));
    CompromisedPasswordResult.Pwned p = assertInstanceOf(
        CompromisedPasswordResult.Pwned.class,
        checker.check(SecretValue.ofString("hunter222")));
    assertEquals(11L, p.occurrences());
  }
}
