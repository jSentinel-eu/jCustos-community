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
package eu.jsentinel.jcustos.oauth2.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oidc.api.OidcProviderMetadata;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("oauth2/api — issuer binding of the authorisation response (JS-SEC-150, RFC 9207)")
class IssuerBindingApiTest {

  private static OAuth2ClientConfig legacyConfig() {
    return new OAuth2ClientConfig(
        new ClientAuthentication.NoneAuthentication("rp"),
        Optional.of(URI.create("https://idp.example/authorize")),
        URI.create("https://idp.example/token"),
        Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.of(URI.create("https://app.example/callback")),
        Set.of("openid"), true, true, Duration.ofMinutes(10));
  }

  @Test
  @DisplayName("CallbackParams: the four-argument constructor still works and carries no iss")
  void callbackParamsCompatibility() {
    AuthorizationCodeFlow.CallbackParams legacy = new AuthorizationCodeFlow.CallbackParams(
        Optional.of("code"), "state", Optional.empty(), Optional.empty());
    assertEquals(Optional.empty(), legacy.iss());

    AuthorizationCodeFlow.CallbackParams withIss = new AuthorizationCodeFlow.CallbackParams(
        Optional.of("code"), "state", Optional.empty(), Optional.empty(), Optional.of("https://idp.example"));
    assertEquals(Optional.of("https://idp.example"), withIss.iss());
    assertThrows(NullPointerException.class, () -> new AuthorizationCodeFlow.CallbackParams(
        Optional.of("code"), "state", Optional.empty(), Optional.empty(), null));
  }

  @Test
  @DisplayName("OAuth2ClientConfig: the eleven-argument constructor means 'no issuer binding'")
  void clientConfigCompatibility() {
    OAuth2ClientConfig legacy = legacyConfig();
    assertEquals(Optional.empty(), legacy.expectedIssuer());
    assertFalse(legacy.issuerParameterRequired());

    OAuth2ClientConfig bound = legacy.withExpectedIssuer("https://idp.example", true);
    assertEquals(Optional.of("https://idp.example"), bound.expectedIssuer());
    assertTrue(bound.issuerParameterRequired());
    assertEquals(legacy.tokenEndpoint(), bound.tokenEndpoint());
    assertEquals(legacy.scopes(), bound.scopes());
    assertEquals("rp", bound.clientId());
  }

  @Test
  @DisplayName("OAuth2ClientConfig: 'iss required' without an expected issuer, and a blank issuer, are refused")
  void clientConfigGuards() {
    OAuth2ClientConfig legacy = legacyConfig();
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> new OAuth2ClientConfig(legacy.clientAuth(), legacy.authorizationEndpoint(),
            legacy.tokenEndpoint(), legacy.revocationEndpoint(), legacy.introspectionEndpoint(),
            legacy.deviceAuthorizationEndpoint(), legacy.redirectUri(), legacy.scopes(), true, true,
            legacy.stateTtl(), Optional.empty(), true));
    assertTrue(ex.getMessage().startsWith("oauth2/issuer-required-without-expected-issuer"));
    assertThrows(IllegalArgumentException.class, () -> legacy.withExpectedIssuer(" ", false));
  }

  @Test
  @DisplayName("StateEntry: the bound issuer travels in 'extra' and is read by expectedIssuer()")
  void stateEntryCarriesIssuer() {
    Instant now = Instant.parse("2026-11-10T12:00:00Z");
    StateEntry plain = new StateEntry("v".repeat(43), Optional.empty(), Optional.empty(), Map.of(), now);
    assertEquals(Optional.empty(), plain.expectedIssuer());

    StateEntry bound = new StateEntry("v".repeat(43), Optional.empty(), Optional.empty(),
        Map.of(StateEntry.EXTRA_EXPECTED_ISSUER, "https://idp.example"), now);
    assertEquals(Optional.of("https://idp.example"), bound.expectedIssuer());
  }

  @Test
  @DisplayName("OidcProviderMetadata: the twelve-argument constructor means 'iss parameter not announced'")
  void providerMetadataCompatibility() {
    OidcProviderMetadata legacy = new OidcProviderMetadata("https://idp", URI.create("https://idp/auth"),
        URI.create("https://idp/token"), URI.create("https://idp/jwks"),
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
        Set.of("openid"), Set.of("code"), Set.of("RS256"));
    assertFalse(legacy.authorizationResponseIssParameterSupported());

    OidcProviderMetadata announcing = new OidcProviderMetadata("https://idp", URI.create("https://idp/auth"),
        URI.create("https://idp/token"), URI.create("https://idp/jwks"),
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
        Set.of("openid"), Set.of("code"), Set.of("RS256"), true);
    assertTrue(announcing.authorizationResponseIssParameterSupported());
  }
}
