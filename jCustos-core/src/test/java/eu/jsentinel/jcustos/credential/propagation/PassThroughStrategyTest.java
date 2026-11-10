/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PassThroughStrategy")
class PassThroughStrategyTest {

  private static final OutboundCall CALL = new OutboundCall("Svc", "method", "", Map.of());

  @Test
  @DisplayName("name() returns the documented constant")
  void nameStable() {
    assertEquals("pass-through", PassThroughStrategy.INSTANCE.name());
  }

  @Test
  @DisplayName("Empty inbound → empty result")
  void emptyInboundEmptyResult() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.empty()).isEmpty());
  }

  @Test
  @DisplayName("BearerToken → Authorization: Bearer …")
  void bearerForwarded() {
    Optional<HeaderValue> r = PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new BearerToken("abc")));
    assertEquals(new HeaderValue("Authorization", "Bearer abc"), r.orElseThrow());
  }

  @Test
  @DisplayName("OidcAccessToken → Authorization: Bearer …")
  void oidcForwarded() {
    Optional<HeaderValue> r = PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new OidcAccessToken("xyz",
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty())));
    assertEquals(new HeaderValue("Authorization", "Bearer xyz"), r.orElseThrow());
  }

  @Test
  @DisplayName("RefreshToken → empty (Class-A secret, must not leak)")
  void refreshNotForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new RefreshToken("rt",
            Optional.empty(), Optional.empty(), Optional.empty()))).isEmpty());
  }

  @Test
  @DisplayName("ApiKey → empty (no Bearer prefix; consumers add their own header strategy)")
  void apiKeyNotForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new ApiKey("ak",
            Optional.empty(), Optional.empty(), Optional.empty()))).isEmpty());
  }

  @Test
  @DisplayName("INSTANCE is a shared singleton")
  void instanceShared() {
    assertSame(PassThroughStrategy.INSTANCE, PassThroughStrategy.INSTANCE);
  }

  // ── JS-SEC-151 (CWE-441): the declared audience guards the pass-through ──────────

  private static final OutboundCall BILLING_CALL =
      new OutboundCall("BillingClient", "charge", "billing", Map.of());

  private static OidcAccessToken validatedTokenFor(Object aud) {
    eu.jsentinel.jcustos.jwt.api.ValidatedJwt jwt = new eu.jsentinel.jcustos.jwt.api.ValidatedJwt(
        "compact",
        new eu.jsentinel.jcustos.jwt.api.JoseHeader("RS256", Optional.empty(), Optional.empty()),
        Map.of("iss", "https://op.example.com", "aud", aud),
        java.time.Instant.parse("2026-11-10T12:00:00Z"));
    return OidcAccessToken.fromValidated("user-token", jwt);
  }

  @Test
  @DisplayName("JS-SEC-151: aud=api-a with declared audience 'billing' → nothing is forwarded")
  void foreignAudienceNotForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(validatedTokenFor("api-a"))).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-151: aud=billing with declared audience 'billing' → the header is forwarded")
  void matchingAudienceForwarded() {
    Optional<HeaderValue> r = PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(validatedTokenFor("billing")));
    assertEquals(new HeaderValue("Authorization", "Bearer user-token"), r.orElseThrow());
  }

  @Test
  @DisplayName("JS-SEC-151: a multi-valued aud that contains the declared audience is forwarded")
  void multiValuedAudienceForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(validatedTokenFor(java.util.List.of("api-a", "billing"))))
        .isPresent());
    // the comma-joined form without the validation result is understood as well
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(new BearerToken("t", Optional.empty(),
            Optional.of("api-a, billing"), Optional.empty()))).isPresent());
  }

  @Test
  @DisplayName("JS-SEC-151: a substring of an audience is not a match")
  void audienceSubstringIsNoMatch() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(validatedTokenFor("billing-internal"))).isEmpty());
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(new BearerToken("t", Optional.empty(),
            Optional.of("not-billing"), Optional.empty()))).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-151: a token of UNKNOWN audience is not forwarded to a declared audience (fail closed)")
  void unknownAudienceNotForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(new BearerToken("abc"))).isEmpty());
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(BILLING_CALL, Optional.of(new OidcAccessToken("xyz",
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()))).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-151: without a declared audience the token is forwarded as before, whatever its aud")
  void noDeclaredAudienceKeepsForwarding() {
    assertEquals(new HeaderValue("Authorization", "Bearer user-token"),
        PassThroughStrategy.INSTANCE.resolve(CALL, Optional.of(validatedTokenFor("api-a"))).orElseThrow());
  }
}
