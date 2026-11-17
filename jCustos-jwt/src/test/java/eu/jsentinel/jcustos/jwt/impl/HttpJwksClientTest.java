package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("HttpJwksClient — caching discipline over a real JDK HttpServer (no mocks)")
class HttpJwksClientTest {

  private static final Instant NOW = Instant.parse("2026-06-25T12:00:00Z");

  private HttpServer server;
  private final AtomicInteger requests = new AtomicInteger();
  private final AtomicReference<String> body = new AtomicReference<>("{\"keys\":[]}");
  private final AtomicInteger status = new AtomicInteger(200);
  private final AtomicReference<String> cacheControl = new AtomicReference<>(null);
  private final AtomicReference<CountDownLatch> gate = new AtomicReference<>(null);
  private final AtomicReference<CountDownLatch> started = new AtomicReference<>(null);
  private String jwksUrl;

  private RSAKey k1;
  private RSAKey k2;

  @BeforeEach
  void start() throws Exception {
    k1 = new RSAKeyGenerator(2048).keyID("k1").generate();
    k2 = new RSAKeyGenerator(2048).keyID("k2").generate();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext("/jwks", exchange -> {
      requests.incrementAndGet();
      CountDownLatch s = started.get();
      if (s != null) {
        s.countDown();
      }
      CountDownLatch g = gate.get();
      if (g != null) {
        try {
          g.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      byte[] payload = body.get().getBytes(StandardCharsets.UTF_8);
      if (cacheControl.get() != null) {
        exchange.getResponseHeaders().add("Cache-Control", cacheControl.get());
      }
      exchange.sendResponseHeaders(status.get(), payload.length == 0 ? -1 : payload.length);
      try (var out = exchange.getResponseBody()) {
        out.write(payload);
      }
      exchange.close();
    });
    server.start();
    jwksUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    // JS-SEC-098: since 00.84.00 a JWKS stub on loopback http needs the dev flag as well.
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private static String jwks(RSAKey... keys) {
    return new JWKSet(List.of(keys).stream().map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK()).toList())
        .toString();
  }

  private HttpJwksClient client() {
    return new HttpJwksClient(URI.create(jwksUrl), HttpClient.newHttpClient(), () -> NOW);
  }

  @Test
  @DisplayName("JS-SEC-033: an oversized Cache-Control max-age is clamped so the cache expires within 24h")
  void oversizedMaxAgeIsClamped() {
    AtomicReference<Instant> clock = new AtomicReference<>(NOW);
    HttpJwksClient client = new HttpJwksClient(
        URI.create(jwksUrl), HttpClient.newHttpClient(), clock::get);
    body.set(jwks(k1));
    cacheControl.set("max-age=999999999"); // ~31 years — a hostile/misconfigured endpoint

    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get());

    // still within the 24h clamp — served from cache
    clock.set(NOW.plus(java.time.Duration.ofHours(23)));
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "within the 24h clamp -> served from cache");

    // past the 24h clamp — unclamped this key set would stay fresh for years; clamped it refetches
    clock.set(NOW.plus(java.time.Duration.ofHours(25)));
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(2, requests.get(), "past the 24h clamp -> cache expired, refetched");
  }

  @Test
  @DisplayName("a fresh cache (Cache-Control max-age) is not re-fetched")
  void ttlAvoidsRefetch() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "second lookup within TTL must not re-fetch");
  }

  @Test
  @DisplayName("a kid miss triggers exactly one refresh (hot rotation)")
  void kidMissTriggersRefresh() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get());
    // rotate: the endpoint now serves k1 + k2
    body.set(jwks(k1, k2));
    Optional<PublicKey> rotated = client.findKey("k2", JwsAlgorithm.RS256);
    assertTrue(rotated.isPresent(), "the freshly rotated key must resolve");
    assertEquals(2, requests.get(), "the kid miss triggered one refresh");
  }

  @Test
  @DisplayName("an endpoint failure opens a 30s negative cache (no hammering)")
  void negativeCacheAvoidsHammer() {
    status.set(503);
    body.set("service unavailable");
    HttpJwksClient client = client();
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "a second lookup inside the negative-cache window must not re-fetch");
  }

  @Test
  @DisplayName("F3: a failed refresh exposes a non-secret errorClass token, never a Throwable")
  void refreshFailureExposesErrorClassNotThrowable() {
    status.set(503);
    body.set("service unavailable: backend db at 10.0.0.5 down"); // would-be-leaky detail
    eu.jsentinel.jcustos.jwt.api.JwksRefreshResult result = client().refreshOnce();
    assertFalse(result.succeeded(), "a 503 refresh must not be reported as succeeded");
    assertTrue(result.errorClass().isPresent(), "a failed refresh must carry an errorClass");
    assertEquals("Non2xxResponse", result.errorClass().get(),
        "the errorClass is a stable non-secret token, not a message or class with internals");
    assertFalse(result.errorClass().get().contains("10.0.0.5"),
        "no response-body detail may leak into the errorClass");
  }

  @Test
  @DisplayName("R10: a kid-less token returns empty, never an NPE (healthy cache)")
  void nullKidReturnsEmptyOnHealthyCache() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    // A JWS without a `kid` header: the immutable cache map would throw on
    // get(null) — the guard must return empty instead.
    assertFalse(client.findKey(null, JwsAlgorithm.RS256).isPresent(),
        "a kid-less token must resolve to empty, not throw");
  }

  @Test
  @DisplayName("R10: a kid-less token inside the negative-cache window returns empty, never an NPE")
  void nullKidDuringNegativeCacheWindow() {
    // This was the actual request-path DoS vector: endpoint faulted -> negative
    // cache open -> a flood of kid-less tokens previously hit get(null) on the
    // immutable empty map and threw NPE out of validate().
    status.set(503);
    body.set("service unavailable");
    HttpJwksClient client = client();
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertFalse(client.findKey(null, JwsAlgorithm.RS256).isPresent(),
        "a kid-less token inside the negative-cache window must resolve to empty, not throw");
    assertEquals(1, requests.get(),
        "the kid-less lookup inside the negative-cache window must not re-fetch");
  }

  @Test
  @DisplayName("concurrent lookups during a slow fetch trigger a single request (single-flight)")
  void singleFlightUnderConcurrency() throws Exception {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    CountDownLatch release = new CountDownLatch(1);
    CountDownLatch leaderStarted = new CountDownLatch(1);
    gate.set(release);
    started.set(leaderStarted);

    Thread leader = new Thread(() -> client.findKey("k1", JwsAlgorithm.RS256));
    leader.start();
    assertTrue(leaderStarted.await(5, TimeUnit.SECONDS), "leader fetch should have reached the server");

    int followers = 4;
    CountDownLatch done = new CountDownLatch(followers);
    for (int i = 0; i < followers; i++) {
      new Thread(() -> {
        client.findKey("k1", JwsAlgorithm.RS256);
        done.countDown();
      }).start();
    }
    // give the followers a moment to coalesce onto the in-flight refresh
    Thread.sleep(150);
    release.countDown();
    assertTrue(done.await(5, TimeUnit.SECONDS), "followers should complete");
    leader.join(5_000);
    assertEquals(1, requests.get(), "single-flight collapses the stampede to one fetch");
  }

  @Test
  @DisplayName("an oversized JWKS body is rejected (no OOM) and opens the negative cache (RF01)")
  void oversizedBodyRejected() {
    // > 1 MiB of body: a hostile / MITM'd endpoint. Must be rejected before parsing.
    body.set("x".repeat((1 << 20) + 16));
    HttpJwksClient client = client();
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "the failure opens a negative-cache window — no re-fetch");
  }

  @Test
  @DisplayName("JS-SEC-001: a flood of unknown kids after a successful fetch is throttled to one extra refresh")
  void unknownKidFloodIsThrottled() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "one fetch to populate the cache");

    // A stream of distinct unknown kids (reachable before signature
    // verification) must not force a network refresh each. The first miss
    // probes once (could be a rotation); the endpoint still serves only k1, so
    // a throttle window opens and the rest are served from cache.
    for (int i = 0; i < 50; i++) {
      assertFalse(client.findKey("rogue-" + i, JwsAlgorithm.RS256).isPresent());
    }
    assertEquals(2, requests.get(),
        "the unknown-kid flood is capped at one extra refresh (throttle window), not one per kid");
  }

  @Test
  @DisplayName("JS-SEC-018: a non-loopback http jwks_uri is rejected at construction (CWE-319)")
  void nonLoopbackHttpRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new HttpJwksClient(URI.create("http://idp.example.com/jwks"),
            HttpClient.newHttpClient(), () -> NOW));
  }

  @Test
  @DisplayName("JS-SEC-018/098: https anywhere and, with -Djcustos.dev=true, loopback http are accepted")
  void httpsAndLoopbackAccepted() {
    new HttpJwksClient(URI.create("https://idp.example.com/jwks"),
        HttpClient.newHttpClient(), () -> NOW);
    new HttpJwksClient(URI.create("http://127.0.0.1:8080/jwks"),
        HttpClient.newHttpClient(), () -> NOW);
    new HttpJwksClient(URI.create("http://localhost:8080/jwks"),
        HttpClient.newHttpClient(), () -> NOW);
    new HttpJwksClient(URI.create("http://127.0.0.2:8080/jwks"),
        HttpClient.newHttpClient(), () -> NOW);
    new HttpJwksClient(URI.create("http://[::1]:8080/jwks"),
        HttpClient.newHttpClient(), () -> NOW);
  }

  @Test
  @DisplayName("JS-SEC-098: without -Djcustos.dev=true loopback http is refused like any other http")
  void loopbackHttpWithoutDevFlagRefused() {
    System.clearProperty("jcustos.dev");
    for (String uri : List.of("http://127.0.0.1:8080/jwks", "http://localhost:8080/jwks",
        "http://[::1]:8080/jwks")) {
      IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
          () -> new HttpJwksClient(URI.create(uri), HttpClient.newHttpClient(), () -> NOW), uri);
      assertTrue(refused.getMessage().startsWith("jwks/uri-not-https: "), refused.getMessage());
    }
    // https needs no flag
    new HttpJwksClient(URI.create("https://idp.example.com/jwks"), HttpClient.newHttpClient(), () -> NOW);
  }

  @Test
  @DisplayName("JS-SEC-098: a lookalike of a loopback host is refused even with -Djcustos.dev=true")
  void loopbackLookalikeRefused() {
    for (String uri : List.of("http://localhost.evil.example/jwks", "http://127.0.0.1.nip.io/jwks",
        "http://localhost@evil.example/jwks")) {
      assertThrows(IllegalArgumentException.class,
          () -> new HttpJwksClient(URI.create(uri), HttpClient.newHttpClient(), () -> NOW), uri);
    }
  }
}
