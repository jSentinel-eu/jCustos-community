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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RefreshTokenRotator — rotation + reuse-detection against a real rotating token endpoint (no mocks)")
class RefreshTokenRotatorTest {

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicInteger counter = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      int n = counter.incrementAndGet();
      byte[] body = ("{\"access_token\":\"AT-" + n + "\",\"token_type\":\"Bearer\","
          + "\"refresh_token\":\"RT-" + (n + 1) + "\"}").getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    tokenEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private RefreshTokenRotator rotator(InMemoryRefreshTokenFamilyStore store) {
    return new RefreshTokenRotator(
        new HttpTokenEndpointClient(tokenEndpoint, new ClientAuthentication.NoneAuthentication("rp"),
            HttpClient.newHttpClient()),
        store);
  }

  @Test
  @DisplayName("a fresh refresh rotates the family; replaying a rotated token revokes the whole family")
  void rotateThenReuseRevokes() {
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore();
    RefreshTokenRotator rotator = rotator(store);
    rotator.registerInitial("fam", "RT-1");

    // 1) present RT-1 -> endpoint issues RT-2 -> ROTATED
    Result<TokenResponse, OAuth2Error> first = rotator.rotate("fam", SecretValue.ofString("RT-1"));
    assertTrue(first.toOptional().isPresent(), "the first rotation must succeed");

    // 2) replay RT-1 (already rotated away) -> REUSE_DETECTED -> family revoked
    Result<TokenResponse, OAuth2Error> reuse = rotator.rotate("fam", SecretValue.ofString("RT-1"));
    assertInstanceOf(OAuth2Error.RefreshTokenFamilyRevoked.class,
        reuse.map(t -> (OAuth2Error) null).getOrElse(e -> e));
    assertTrue(store.isRevoked("fam"), "the family must be revoked after reuse-detection");

    // 3) even the once-valid RT-2 is now dead (family revoked)
    Result<TokenResponse, OAuth2Error> afterRevoke = rotator.rotate("fam", SecretValue.ofString("RT-2"));
    assertInstanceOf(OAuth2Error.RefreshTokenFamilyRevoked.class,
        afterRevoke.map(t -> (OAuth2Error) null).getOrElse(e -> e));
  }

  @Test
  @DisplayName("R-EXIT-1: a replayed token revokes the family WITHOUT forwarding it to the AS")
  void reuseDetectedBeforeEndpointCall() {
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore();
    RefreshTokenRotator rotator = rotator(store);
    rotator.registerInitial("fam", "RT-1");
    rotator.rotate("fam", SecretValue.ofString("RT-1")).toOptional().orElseThrow();
    int callsAfterFirstRotation = counter.get();

    // Replay the already-rotated RT-1. A correctly-rotating AS would reject it, so
    // gating the family revoke on AS success would miss the theft. The pre-AS
    // detectReuse check must revoke the family and NOT forward the token onward.
    Result<TokenResponse, OAuth2Error> reuse = rotator.rotate("fam", SecretValue.ofString("RT-1"));
    assertInstanceOf(OAuth2Error.RefreshTokenFamilyRevoked.class,
        reuse.map(t -> (OAuth2Error) null).getOrElse(e -> e));
    assertTrue(store.isRevoked("fam"), "the family must be revoked");
    assertEquals(callsAfterFirstRotation, counter.get(),
        "a replayed token must never reach the token endpoint");
  }

  @Test
  @DisplayName("consecutive legitimate rotations keep succeeding")
  void consecutiveRotations() {
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore();
    RefreshTokenRotator rotator = rotator(store);
    rotator.registerInitial("fam", "RT-1");
    // RT-1 -> RT-2
    assertTrue(rotator.rotate("fam", SecretValue.ofString("RT-1")).toOptional().isPresent());
    // RT-2 -> RT-3 (the endpoint issued RT-2 as the n+1 of the first call)
    assertTrue(rotator.rotate("fam", SecretValue.ofString("RT-2")).toOptional().isPresent());
  }

  @Test
  @DisplayName("R9: the rotator does not classify - a never-issued token still revokes the family, as before 00.84.10")
  void neverIssuedTokenStillRevokes() {
    InMemoryRefreshTokenFamilyStore store = new InMemoryRefreshTokenFamilyStore();
    RefreshTokenRotator rotator = rotator(store);
    rotator.registerInitial("fam", "RT-1");
    assertTrue(rotator.rotate("fam", SecretValue.ofString("RT-1")).toOptional().isPresent());
    int calls = counter.get();

    // RT-99 was never issued. The store would classify it as UNKNOWN, but the rotator
    // keeps the 00.77 semantics of detectReuse: anything that is not current revokes.
    Result<TokenResponse, OAuth2Error> unknown = rotator.rotate("fam", SecretValue.ofString("RT-99"));
    assertInstanceOf(OAuth2Error.RefreshTokenFamilyRevoked.class,
        unknown.map(t -> (OAuth2Error) null).getOrElse(e -> e));
    assertTrue(store.isRevoked("fam"));
    assertEquals(calls, counter.get(), "the unknown token never reaches the token endpoint");
  }
}
