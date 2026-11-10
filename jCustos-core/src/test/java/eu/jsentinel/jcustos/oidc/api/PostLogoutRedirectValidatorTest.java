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
package eu.jsentinel.jcustos.oidc.api;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PostLogoutRedirectValidator.allowOnly — exact comparison (JS-SEC-119, CWE-601)")
class PostLogoutRedirectValidatorTest {

  private static final URI BYE = URI.create("https://app.example.com/bye");

  private static boolean allowed(PostLogoutRedirectValidator validator, String candidate) {
    return validator.isAllowed(URI.create(candidate));
  }

  // ── the baseline the fix must not disturb ────────────────────────

  @Test
  @DisplayName("scheme, host, port and path match exactly; query and fragment are ignored")
  void exactMatch() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(BYE);

    assertTrue(allowed(validator, "https://app.example.com/bye"));
    assertTrue(allowed(validator, "HTTPS://APP.EXAMPLE.COM/bye"), "scheme and host compare case-insensitively");
    assertTrue(allowed(validator, "https://app.example.com/bye?state=1#top"));
    assertFalse(allowed(validator, "https://app.example.com.attacker.test/bye"));
    assertFalse(allowed(validator, "https://app.example.com/bye/more"));
    assertFalse(allowed(validator, "https://app.example.com/BYE"), "the path compares case-sensitively");
    assertFalse(allowed(validator, "http://app.example.com/bye"));
    assertFalse(allowed(validator, "https://app.example.com:8443/bye"));
  }

  @Test
  @DisplayName("an empty allow-list and null entries are refused")
  void emptyOrNullEntries() {
    assertThrows(IllegalArgumentException.class, PostLogoutRedirectValidator::allowOnly);
    assertThrows(NullPointerException.class,
        () -> PostLogoutRedirectValidator.allowOnly(BYE, null));
  }

  // ── JS-SEC-119: host that java.net.URI cannot parse ──────────────

  @Test
  @DisplayName("JS-SEC-119: URI.getHost() is null for an underscore host — the premise of the finding")
  void underscoreHostHasNoParsedHost() {
    assertNull(URI.create("https://my_app.example.com/bye").getHost());
    assertNull(URI.create("https://evil_site.attacker.test/bye").getHost());
  }

  @Test
  @DisplayName("JS-SEC-119: an http/https entry without a parsable host is refused at construction")
  void underscoreHostEntryIsRefused() {
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> PostLogoutRedirectValidator.allowOnly(URI.create("https://my_app.example.com/bye")));
    assertTrue(ex.getMessage().contains("my_app.example.com"), ex.getMessage());
    assertThrows(IllegalArgumentException.class,
        () -> PostLogoutRedirectValidator.allowOnly(BYE, URI.create("http://my_app.example.com/bye")));
    assertThrows(IllegalArgumentException.class,
        () -> PostLogoutRedirectValidator.allowOnly(URI.create("https:/bye")),
        "an https URI without any authority has no host either");
  }

  @Test
  @DisplayName("JS-SEC-119: a candidate without a parsable host is never allowed")
  void underscoreHostCandidateIsRejected() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(BYE);

    assertFalse(allowed(validator, "https://evil_site.attacker.test/bye"));
    assertFalse(allowed(validator, "https://app_.example.com/bye"));
    assertFalse(allowed(validator, "https:/bye"));
    assertFalse(validator.isAllowed(null));
  }

  // ── JS-SEC-119: user information ─────────────────────────────────

  @Test
  @DisplayName("JS-SEC-119: a candidate with user information is rejected")
  void userInfoCandidateIsRejected() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(BYE);

    assertFalse(allowed(validator, "https://anything@app.example.com/bye"));
    assertFalse(allowed(validator, "https://app.example.com:443@app.example.com/bye"));
    assertFalse(allowed(validator, "https://user:secret@app.example.com/bye"));
    assertFalse(allowed(validator, "https://@app.example.com/bye"), "an empty user information is one too");
  }

  @Test
  @DisplayName("JS-SEC-119: an entry with user information is refused at construction")
  void userInfoEntryIsRefused() {
    assertThrows(IllegalArgumentException.class,
        () -> PostLogoutRedirectValidator.allowOnly(URI.create("https://ops@app.example.com/bye")));
  }

  // ── JS-SEC-119: default port ─────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-119: the default port equals no port, in both directions")
  void defaultPortIsNormalised() {
    PostLogoutRedirectValidator withoutPort = PostLogoutRedirectValidator.allowOnly(
        BYE, URI.create("http://intranet.example.com/bye"));
    assertTrue(allowed(withoutPort, "https://app.example.com:443/bye"));
    assertTrue(allowed(withoutPort, "http://intranet.example.com:80/bye"));
    assertFalse(allowed(withoutPort, "https://app.example.com:80/bye"), "80 is not the https default");
    assertFalse(allowed(withoutPort, "http://intranet.example.com:443/bye"), "443 is not the http default");

    PostLogoutRedirectValidator withPort = PostLogoutRedirectValidator.allowOnly(
        URI.create("https://app.example.com:443/bye"));
    assertTrue(allowed(withPort, "https://app.example.com/bye"));
    assertTrue(allowed(withPort, "https://app.example.com:443/bye"));
    assertFalse(allowed(withPort, "https://app.example.com:8443/bye"));
  }

  // ── JS-SEC-119: nothing that decides the target drops out ────────

  @Test
  @DisplayName("JS-SEC-119: non-web schemes compare on the raw authority when the host is not parsable")
  void nonWebSchemeComparesRawAuthority() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(
        URI.create("myapp://good_host/done"), URI.create("com.example.app:/logout"));

    assertTrue(allowed(validator, "myapp://good_host/done"));
    assertFalse(allowed(validator, "myapp://evil_host/done"));
    assertFalse(allowed(validator, "myapp://user@good_host/done"));
    assertTrue(allowed(validator, "com.example.app:/logout"));
    assertFalse(allowed(validator, "com.example.app:/other"));
  }

  @Test
  @DisplayName("JS-SEC-119: opaque URIs compare on the scheme-specific part")
  void opaqueUriComparesSchemeSpecificPart() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(
        URI.create("myapp:logout-done"));

    assertTrue(allowed(validator, "myapp:logout-done"));
    assertFalse(allowed(validator, "myapp:something-else"));
  }

  @Test
  @DisplayName("permitAll stays the unrestricted validator (ER22 is a separate issue)")
  void permitAllUnchanged() {
    assertTrue(PostLogoutRedirectValidator.permitAll()
        .isAllowed(URI.create("https://evil_site.attacker.test/bye")));
  }
}
