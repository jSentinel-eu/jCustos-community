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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;

import java.net.URI;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CWE-601: where the user lands after logout must not be decided by whoever
 * supplied the URI. The provider checks it against its registered set, but that
 * happens out of sight of this code — and if the URI came from the request, an
 * attacker picked it.
 */
@DisplayName("RpInitiatedLogoutInitiator — post_logout_redirect_uri validation (CWE-601)")
class RpInitiatedLogoutRedirectValidationTest {

  private static final URI END_SESSION = URI.create("https://op.example.test/logout");
  private static final URI ALLOWED = URI.create("https://app.example.test/bye");

  private static LogoutRequest logoutTo(URI redirect) {
    return new LogoutRequest("id-token-hint", Optional.of(redirect), Optional.empty());
  }

  @Test
  @DisplayName("an allowed target is forwarded to the provider")
  void allowedTargetPasses() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    URI logoutUri = initiator.buildLogoutUri(END_SESSION, logoutTo(ALLOWED));

    assertTrue(logoutUri.toString().contains("post_logout_redirect_uri"),
        "the redirect must survive validation: " + logoutUri);
  }

  @Test
  @DisplayName("a foreign target is refused instead of forwarded")
  void foreignTargetIsRefused() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> initiator.buildLogoutUri(END_SESSION,
            logoutTo(URI.create("https://attacker.test/harvest"))));

    assertTrue(ex.getMessage().contains("attacker.test"),
        "the message should name the rejected target, was: " + ex.getMessage());
  }

  @Test
  @DisplayName("a look-alike host does not pass — the classic prefix bypass")
  void lookAlikeHostIsRefused() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    // A prefix check on "https://app.example.test" would accept this.
    assertThrows(IllegalArgumentException.class,
        () -> initiator.buildLogoutUri(END_SESSION,
            logoutTo(URI.create("https://app.example.test.attacker.test/bye"))));
  }

  @Test
  @DisplayName("scheme and port are part of the identity of a target")
  void schemeAndPortMatter() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(ALLOWED);

    assertFalse(validator.isAllowed(URI.create("http://app.example.test/bye")),
        "downgrading https to http must not pass");
    assertFalse(validator.isAllowed(URI.create("https://app.example.test:8443/bye")),
        "a different port is a different target");
    assertTrue(validator.isAllowed(URI.create("https://APP.EXAMPLE.TEST/bye")),
        "host comparison is case-insensitive, as DNS is");
  }

  @Test
  @DisplayName("query and fragment do not change the decision")
  void queryAndFragmentIgnored() {
    PostLogoutRedirectValidator validator = PostLogoutRedirectValidator.allowOnly(ALLOWED);

    assertTrue(validator.isAllowed(URI.create("https://app.example.test/bye?lang=de#top")),
        "neither carries authority over where the browser goes");
  }

  // ── JS-SEC-089 (CWE-601): no allowlist, no redirect ─────────────

  @Test
  @DisplayName("JS-SEC-089: without a validator a foreign target is refused, not forwarded")
  void defaultConstructorRefusesAForeignTarget() {
    RpInitiatedLogoutInitiator initiator = new RpInitiatedLogoutInitiator();

    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> initiator.buildLogoutUri(END_SESSION,
            logoutTo(URI.create("https://attacker.test/harvest"))),
        "until 00.84.00 the no-argument constructor forwarded any target (open redirect)");

    assertTrue(ex.getMessage().contains("attacker.test"), ex.getMessage());
    assertTrue(ex.getMessage().contains("no allowlist is configured"),
        "the message should name the missing allowlist, was: " + ex.getMessage());
  }

  @Test
  @DisplayName("JS-SEC-089: without a validator even the application's own target is refused until it is allowed")
  void defaultConstructorRefusesEveryTargetUntilAnAllowlistIsSet() {
    assertThrows(IllegalArgumentException.class,
        () -> new RpInitiatedLogoutInitiator().buildLogoutUri(END_SESSION, logoutTo(ALLOWED)),
        "there is no same-origin rule to fall back to: the initiator does not know the origin");

    RpInitiatedLogoutInitiator withAllowlist =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));
    assertTrue(withAllowlist.buildLogoutUri(END_SESSION, logoutTo(ALLOWED)).toString()
        .contains("post_logout_redirect_uri="), "the allowlist is what opens the target");
  }

  @Test
  @DisplayName("JS-SEC-089: without a validator a logout without a redirect target still reaches the provider")
  void defaultConstructorBuildsALogoutWithoutTarget() {
    URI logoutUri = assertDoesNotThrow(() -> new RpInitiatedLogoutInitiator().buildLogoutUri(
        END_SESSION, new LogoutRequest("hint", Optional.empty(), Optional.of("st"))));

    assertEquals("https://op.example.test/logout?id_token_hint=hint&state=st", logoutUri.toString());
  }

  @Test
  @DisplayName("JS-SEC-089 (CWE-117): the refusal names the target without the format characters java.net.URI admits")
  void refusalMessageIsScrubbed() {
    URI reordering = URI.create("https://attacker.test/\u202Etxt.exe");

    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new RpInitiatedLogoutInitiator().buildLogoutUri(END_SESSION, logoutTo(reordering)));

    assertFalse(ex.getMessage().contains("\u202E"), "a right-to-left override would reorder the log line");
    assertTrue(ex.getMessage().contains("https://attacker.test/?txt.exe"), ex.getMessage());
  }

  @Test
  @DisplayName("JS-SEC-089, RF32: the first refused target writes exactly one oidc/logout-redirect-unvalidated warning")
  void firstRefusedTargetWarnsExactlyOnce() {
    RpInitiatedLogoutInitiator.resetUnvalidatedRedirectWarning();
    try {
      RpInitiatedLogoutInitiator withAllowlist =
          new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));
      assertThrows(IllegalArgumentException.class, () -> withAllowlist.buildLogoutUri(END_SESSION,
          logoutTo(URI.create("https://attacker.test/harvest"))));
      assertEquals(0, RpInitiatedLogoutInitiator.unvalidatedRedirectWarnings(),
          "an initiator with an allowlist does not warn - the refusal is the configured behaviour");

      RpInitiatedLogoutInitiator withoutAllowlist = new RpInitiatedLogoutInitiator();
      assertThrows(IllegalArgumentException.class,
          () -> withoutAllowlist.buildLogoutUri(END_SESSION, logoutTo(ALLOWED)));
      assertEquals(1, RpInitiatedLogoutInitiator.unvalidatedRedirectWarnings(),
          "the missing allowlist is announced with the refusal");

      for (int i = 0; i < 3; i++) {
        assertThrows(IllegalArgumentException.class,
            () -> new RpInitiatedLogoutInitiator().buildLogoutUri(END_SESSION, logoutTo(ALLOWED)));
      }
      assertEquals(1, RpInitiatedLogoutInitiator.unvalidatedRedirectWarnings(),
          "once per JVM - a view builds an initiator per logout");
      assertEquals("oidc/logout-redirect-unvalidated",
          RpInitiatedLogoutInitiator.UNVALIDATED_REDIRECT_WARNING);
    } finally {
      RpInitiatedLogoutInitiator.resetUnvalidatedRedirectWarning();
    }
  }

  @Test
  @DisplayName("RF32: construction and logouts without a target write no warning - the configuration the WARN calls correct")
  void correctConfigurationsDoNotWarn() {
    RpInitiatedLogoutInitiator.resetUnvalidatedRedirectWarning();
    try {
      RpInitiatedLogoutInitiator initiator = new RpInitiatedLogoutInitiator();
      assertEquals(0, RpInitiatedLogoutInitiator.unvalidatedRedirectWarnings(),
          "until the exit review every construction warned, also for a resolver without a target");
      for (int i = 0; i < 3; i++) {
        initiator.buildLogoutUri(END_SESSION, new LogoutRequest("hint", Optional.empty(), Optional.empty()));
      }
      assertEquals(0, RpInitiatedLogoutInitiator.unvalidatedRedirectWarnings(),
          "a logout without a post_logout_redirect_uri is not refused and not announced");
    } finally {
      RpInitiatedLogoutInitiator.resetUnvalidatedRedirectWarning();
    }
  }

  @Test
  @DisplayName("an empty allowlist is rejected at construction, not silently deny-all")
  void emptyAllowlistIsRejected() {
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, PostLogoutRedirectValidator::allowOnly);

    assertTrue(ex.getMessage().contains("LogoutRequest"),
        "the message should point at the intended alternative, was: " + ex.getMessage());
  }

  @Test
  @DisplayName("a logout without a redirect target is unaffected")
  void noRedirectNoValidation() {
    RpInitiatedLogoutInitiator initiator =
        new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(ALLOWED));

    URI logoutUri = initiator.buildLogoutUri(END_SESSION,
        new LogoutRequest("hint", Optional.empty(), Optional.empty()));

    assertEquals(-1, logoutUri.toString().indexOf("post_logout_redirect_uri"),
        "nothing to validate, nothing to add");
  }
}
