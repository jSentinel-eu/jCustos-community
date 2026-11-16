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
package eu.jsentinel.jcustos.propagation.oidc.strategy;

import eu.jsentinel.jcustos.propagation.oidc.cache.TokenExchangeCache;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SA27 follow-up (JS-SEC-127, CWE-532): cached and received token-endpoint answers do not print their tokens. */
@DisplayName("JS-SEC-127 — TokenExchangeCache.CachedEntry and BoundedTokenHttp.Response mask their tokens")
class SecretRecordToStringTest {

  @Test
  @DisplayName("the cached access token is masked, the expiry stays readable")
  void cachedEntry() {
    Instant expiry = Instant.parse("2026-11-16T12:00:00Z");
    String text = new TokenExchangeCache.CachedEntry("exchanged-at-77", expiry).toString();
    assertFalse(text.contains("exchanged-at-77"), text);
    assertTrue(text.contains(expiry.toString()), text);
  }

  @Test
  @DisplayName("a token-endpoint response shows status and length, not the body")
  void response() {
    String body = "{\"access_token\":\"exchanged-at-78\",\"token_type\":\"Bearer\"}";
    String text = new BoundedTokenHttp.Response(200, body).toString();
    assertFalse(text.contains("exchanged-at-78"), text);
    assertTrue(text.contains("statusCode=200"), text);
    assertTrue(text.contains("<" + body.length() + " chars>"), text);
  }
}
