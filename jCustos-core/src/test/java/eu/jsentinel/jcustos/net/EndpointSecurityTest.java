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
package eu.jsentinel.jcustos.net;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-098 (CWE-319, CWE-1041): the one transport rule of jCustos — {@code https}, or plain
 * {@code http} to a loopback host only with {@code -Djcustos.dev=true}; loopback recognised from
 * the text of the URI, without name resolution.
 */
@DisplayName("JS-SEC-098 — EndpointSecurity: one https rule for every endpoint")
class EndpointSecurityTest {

  private static final String CODE = "test/endpoint-not-https";

  private String previousDevFlag;

  @BeforeEach
  void rememberFlag() {
    previousDevFlag = System.getProperty(EndpointSecurity.DEV_MODE_PROPERTY);
    System.clearProperty(EndpointSecurity.DEV_MODE_PROPERTY);
  }

  @AfterEach
  void restoreFlag() {
    if (previousDevFlag == null) {
      System.clearProperty(EndpointSecurity.DEV_MODE_PROPERTY);
    } else {
      System.setProperty(EndpointSecurity.DEV_MODE_PROPERTY, previousDevFlag);
    }
  }

  private static void devMode() {
    System.setProperty(EndpointSecurity.DEV_MODE_PROPERTY, "true");
  }

  private static IllegalArgumentException refused(String uri) {
    return assertThrows(IllegalArgumentException.class,
        () -> EndpointSecurity.requireHttps(URI.create(uri), CODE), uri);
  }

  @Test
  @DisplayName("https with a host is accepted with and without the flag, and returned unchanged")
  void httpsAccepted() {
    URI endpoint = URI.create("https://idp.example/token");
    assertSame(endpoint, EndpointSecurity.requireHttps(endpoint, CODE));
    URI loopback = URI.create("https://127.0.0.1:8443/token");
    assertSame(loopback, EndpointSecurity.requireHttps(loopback, CODE), "https needs no flag, loopback or not");
    devMode();
    assertSame(endpoint, EndpointSecurity.requireHttps(endpoint, CODE));
    URI upper = URI.create("HTTPS://idp.example/token");
    assertSame(upper, EndpointSecurity.requireHttps(upper, CODE), "the scheme compares case-insensitively");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "http://localhost/jwks", "http://localhost:8080/jwks", "http://LOCALHOST:8080/jwks",
      "http://127.0.0.1:8080/jwks", "http://127.0.0.2/jwks", "http://127.255.255.254/jwks",
      "http://[::1]:8080/jwks", "http://[0:0:0:0:0:0:0:1]/jwks"})
  @DisplayName("plain http to a loopback host is refused without the flag (JWKS and HIBP included)")
  void loopbackHttpWithoutFlagRefused(String uri) {
    IllegalArgumentException refusal = refused(uri);
    assertTrue(refusal.getMessage().startsWith(CODE + ": "), refusal.getMessage());
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "http://localhost/jwks", "http://localhost:8080/jwks", "http://LOCALHOST:8080/jwks",
      "http://127.0.0.1:8080/jwks", "http://127.0.0.2/jwks", "http://127.255.255.254/jwks",
      "http://[::1]:8080/jwks", "http://[0:0:0:0:0:0:0:1]/jwks"})
  @DisplayName("plain http to a loopback host is accepted with -Djcustos.dev=true ([::1] and 127.0.0.0/8 included)")
  void loopbackHttpWithFlagAccepted(String uri) {
    devMode();
    URI endpoint = URI.create(uri);
    assertSame(endpoint, EndpointSecurity.requireHttps(endpoint, CODE));
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "http://idp.example/token", "http://203.0.113.5/token", "http://[2001:db8::1]/token",
      "http://0.0.0.0/token", "http://128.0.0.1/token",
      // lookalikes: names that start like a loopback host, userinfo that names one
      "http://localhost.evil.example/token", "http://127.0.0.1.nip.io/token",
      "http://localhost@evil.example/token", "http://127.0.0.1@evil.example/token",
      "http://localhost./token",
      // other schemes and URIs without a host
      "ftp://localhost/token", "file:///etc/passwd", "https:///token", "https:opaque",
      "http:///token", "localhost/token"})
  @DisplayName("a foreign host, a lookalike, another scheme or no host is refused even with the flag")
  void foreignOrLookalikeRefusedWithFlag(String uri) {
    devMode();
    IllegalArgumentException refusal = refused(uri);
    assertTrue(refusal.getMessage().startsWith(CODE + ": "), refusal.getMessage());
  }

  @Test
  @DisplayName("the flag must be exactly true")
  void flagMustBeTrue() {
    System.setProperty(EndpointSecurity.DEV_MODE_PROPERTY, "yes");
    refused("http://127.0.0.1/token");
    System.setProperty(EndpointSecurity.DEV_MODE_PROPERTY, "TRUE");
    assertTrue(EndpointSecurity.devModeEnabled(), "Boolean.getBoolean ignores case");
  }

  @Test
  @DisplayName("the message names scheme and host, never the path or the query")
  void messageOmitsPathAndQuery() {
    String message = refused("http://idp.example:8080/token?client_secret=s3cr3t#frag").getMessage();
    assertEquals(CODE + ": the endpoint must use https:// (got: http://idp.example); plain http is "
        + "accepted only for a loopback host with -Djcustos.dev=true", message);
    assertFalse(message.contains("s3cr3t"), message);
  }

  @Test
  @DisplayName("null endpoint or error code is a NullPointerException")
  void nullArguments() {
    assertThrows(NullPointerException.class, () -> EndpointSecurity.requireHttps(null, CODE));
    assertThrows(NullPointerException.class,
        () -> EndpointSecurity.requireHttps(URI.create("https://idp.example"), null));
  }

  @ParameterizedTest
  @ValueSource(strings = {"localhost", "LocalHost", "127.0.0.1", "127.0.0.2", "127.1.2.3",
      "[::1]", "::1", "0:0:0:0:0:0:0:1", "[::ffff:127.0.0.1]"})
  @DisplayName("isLoopbackHost: loopback names and literals")
  void loopbackHosts(String host) {
    assertTrue(EndpointSecurity.isLoopbackHost(host), host);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "localhost.", "localhost.evil.example", "evil-localhost", "127.0.0.1.nip.io",
      "127.0.0.1:80", "[::1]:80", "[::1", "::2", "0.0.0.0", "128.0.0.1", "10.0.0.1", "[2001:db8::1]",
      "0177.0.0.1", "ip6-localhost"})
  @DisplayName("isLoopbackHost: lookalikes, ports, other addresses and names that would need a resolver")
  void notLoopbackHosts(String host) {
    assertFalse(EndpointSecurity.isLoopbackHost(host), host);
  }

  @Test
  @DisplayName("isLoopbackHost: null is not a loopback host")
  void nullHost() {
    assertFalse(EndpointSecurity.isLoopbackHost(null));
  }

  @ParameterizedTest
  @ValueSource(strings = {"[::1]junk]", "[::1]]", "[[::1]]", "[127.0.0.1]", "[127.0.0.2]", "::1]",
      "127.0.0.1]", "[]", "[", " 127.0.0.1", "127.0.0.1 ", "\t127.0.0.1", "127.0.0.1\n", " localhost",
      "[ ::1]", "[::1 ]", "local host", "127.0.0.1\u00a0", "localhost\u0000"})
  @DisplayName("RF29: isLoopbackHost refuses text no URI host has - junk after the bracket, a bracketed IPv4 literal, white space")
  void notUriHostText(String host) {
    assertFalse(EndpointSecurity.isLoopbackHost(host),
        "until the exit review the literal parser cut at the first ']' and trimmed: '" + host + "'");
  }

  @Test
  @DisplayName("RF29: the hosts java.net.URI reports for loopback endpoints still count")
  void uriHostsStillCount() {
    for (String uri : new String[] {"http://[::1]:8080/x", "http://[0:0:0:0:0:0:0:1]/x",
        "http://[::ffff:127.0.0.1]/x", "http://127.0.0.1/x", "http://LOCALHOST/x"}) {
      assertTrue(EndpointSecurity.isLoopbackHost(URI.create(uri).getHost()), uri);
    }
  }

  @Test
  @DisplayName("RF28: isHttpsEndpoint is https with a host - what requireHttps accepts without the flag")
  void isHttpsEndpoint() {
    assertTrue(EndpointSecurity.isHttpsEndpoint(URI.create("https://idp.example/jwks")));
    assertTrue(EndpointSecurity.isHttpsEndpoint(URI.create("HTTPS://127.0.0.1:8443/jwks")));
    devMode();
    for (String uri : new String[] {"https:///jwks", "https:jwks", "http://localhost/jwks",
        "http://idp.example/jwks", "ftp://idp.example/jwks"}) {
      assertFalse(EndpointSecurity.isHttpsEndpoint(URI.create(uri)), uri);
    }
    assertThrows(NullPointerException.class, () -> EndpointSecurity.isHttpsEndpoint(null));
  }
}
