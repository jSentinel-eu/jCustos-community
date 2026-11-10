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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oidc.api.OidcProviderMetadata;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("HttpOidcDiscoveryClient — against a real HttpServer .well-known endpoint (no mocks)")
class HttpOidcDiscoveryClientTest {

  private HttpServer server;
  private String issuer;
  private final AtomicInteger calls = new AtomicInteger();
  private volatile String issuerInDoc;
  /** Extra members appended to the discovery document, e.g. the RFC 9207 flag. */
  private volatile String extraMembers = "";

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int port = server.getAddress().getPort();
    issuer = "http://127.0.0.1:" + port;
    issuerInDoc = issuer;
    server.createContext("/.well-known/openid-configuration", exchange -> {
      calls.incrementAndGet();
      String doc = "{\"issuer\":\"" + issuerInDoc + "\","
          + "\"authorization_endpoint\":\"" + issuer + "/auth\","
          + "\"token_endpoint\":\"" + issuer + "/token\","
          + "\"jwks_uri\":\"" + issuer + "/jwks\","
          + "\"userinfo_endpoint\":\"" + issuer + "/userinfo\","
          + "\"end_session_endpoint\":\"" + issuer + "/logout\","
          + "\"scopes_supported\":[\"openid\",\"profile\"]," + extraMembers
          + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
      byte[] out = doc.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  @Test
  @DisplayName("discover parses the endpoints and the supported-algorithm metadata")
  void discoverParsesMetadata() {
    OidcProviderMetadata md = new HttpOidcDiscoveryClient(HttpClient.newHttpClient())
        .discover(URI.create(issuer)).toOptional().orElseThrow();
    assertEquals(issuer, md.issuer());
    assertEquals(URI.create(issuer + "/token"), md.tokenEndpoint());
    assertEquals(URI.create(issuer + "/jwks"), md.jwksUri());
    assertEquals(URI.create(issuer + "/userinfo"), md.userinfoEndpoint().orElseThrow());
    assertEquals(URI.create(issuer + "/logout"), md.endSessionEndpoint().orElseThrow());
    assertTrue(md.scopesSupported().contains("openid"));
    assertTrue(md.idTokenSigningAlgValuesSupported().contains("RS256"));
  }

  @Test
  @DisplayName("JS-SEC-150: authorization_response_iss_parameter_supported is carried into the metadata")
  void issParameterSupportIsParsed() {
    // absent → false (the RFC 9207 §3 default)
    OidcProviderMetadata plain = new HttpOidcDiscoveryClient(HttpClient.newHttpClient())
        .discover(URI.create(issuer)).toOptional().orElseThrow();
    assertFalse(plain.authorizationResponseIssParameterSupported());

    extraMembers = "\"authorization_response_iss_parameter_supported\":true,";
    OidcProviderMetadata announcing = new HttpOidcDiscoveryClient(HttpClient.newHttpClient())
        .discover(URI.create(issuer)).toOptional().orElseThrow();
    assertTrue(announcing.authorizationResponseIssParameterSupported());

    // a string "true" is not the JSON boolean — treated as not announced
    extraMembers = "\"authorization_response_iss_parameter_supported\":\"true\",";
    OidcProviderMetadata sloppy = new HttpOidcDiscoveryClient(HttpClient.newHttpClient())
        .discover(URI.create(issuer)).toOptional().orElseThrow();
    assertFalse(sloppy.authorizationResponseIssParameterSupported());
  }

  @Test
  @DisplayName("an issuer mismatch in the document is rejected (substitution defence)")
  void issuerMismatchRejected() {
    issuerInDoc = "https://evil.example";
    Result<OidcProviderMetadata, OAuth2Error> r =
        new HttpOidcDiscoveryClient(HttpClient.newHttpClient()).discover(URI.create(issuer));
    assertInstanceOf(OAuth2Error.MalformedResponse.class, r.fold(m -> null, e -> e));
  }

  @Test
  @DisplayName("a repeated discovery is served from the TTL cache (one network call)")
  void cacheHitAvoidsSecondCall() {
    HttpOidcDiscoveryClient client = new HttpOidcDiscoveryClient(HttpClient.newHttpClient());
    client.discover(URI.create(issuer)).toOptional().orElseThrow();
    client.discover(URI.create(issuer)).toOptional().orElseThrow();
    assertEquals(1, calls.get(), "second discovery must hit the cache");
  }

  @Test
  @DisplayName("a non-https, non-loopback issuer is refused")
  void httpsEnforced() {
    System.clearProperty("jcustos.dev");
    assertThrows(IllegalArgumentException.class, () ->
        new HttpOidcDiscoveryClient(HttpClient.newHttpClient()).discover(URI.create("http://idp.example")));
  }
}
