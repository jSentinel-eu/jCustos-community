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
package eu.jsentinel.jcustos.propagation.oidc.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JsonResponse — deprecated delegate over BoundedJson (H4, R09, ER31)")
@SuppressWarnings("removal")
class JsonResponseTest {

  @Test
  @DisplayName("ER31: a repeated key makes the body malformed, so no field is read")
  void repeatedKeyYieldsEmpty() {
    String body = "{\"access_token\":\"first\",\"access_token\":\"second\"}";
    assertTrue(JsonResponse.accessToken(body).isEmpty(),
        "a body with a repeated key must not yield either value");
  }

  @Test
  @DisplayName("ER31: escaped characters arrive decoded")
  void unicodeEscapeDecoded() {
    assertEquals(Optional.of("Bearer"),
        JsonResponse.tokenType("{\"token_type\":\"\\u0042earer\"}"));
  }

  @Test
  @DisplayName("ER31: a null or non-object body yields empty")
  void nullOrNonObjectYieldsEmpty() {
    assertTrue(JsonResponse.accessToken(null).isEmpty());
    assertTrue(JsonResponse.accessToken("[\"access_token\"]").isEmpty());
  }

  @Test
  @DisplayName("a normal value parses")
  void normalValue() {
    assertEquals(Optional.of(3600L),
        JsonResponse.expiresIn("{\"expires_in\":3600}"));
  }

  @Test
  @DisplayName("a missing field yields empty")
  void missingField() {
    assertTrue(JsonResponse.expiresIn("{\"token_type\":\"Bearer\"}").isEmpty());
  }

  @Test
  @DisplayName("an overlong digit run yields empty instead of throwing")
  void overflowYieldsEmpty() {
    // 30 digits — far beyond Long.MAX_VALUE.
    assertTrue(JsonResponse.expiresIn(
        "{\"expires_in\":999999999999999999999999999999}").isEmpty(),
        "an out-of-range expires_in must degrade to empty, not throw");
  }

  @Test
  @DisplayName("the three top-level fields are extracted from a normal token response")
  void topLevelFieldsExtracted() {
    String body = "{\"access_token\":\"abc.def.ghi\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
    assertEquals(Optional.of("abc.def.ghi"), JsonResponse.accessToken(body));
    assertEquals(Optional.of("Bearer"), JsonResponse.tokenType(body));
    assertEquals(Optional.of(3600L), JsonResponse.expiresIn(body));
  }

  @Test
  @DisplayName("R09: a nested access_token is NOT grabbed — only the top-level field")
  void nestedAccessTokenNotGrabbed() {
    // The real top-level token is "real-token". A nested object carries a
    // decoy "access_token" that the old non-anchored regex would have matched
    // first (it appears earlier in the body).
    String body = "{"
        + "\"error_context\":{\"echo\":{\"access_token\":\"NESTED-DECOY\"}},"
        + "\"access_token\":\"real-token\","
        + "\"token_type\":\"Bearer\""
        + "}";
    assertEquals(Optional.of("real-token"), JsonResponse.accessToken(body),
        "only the top-level access_token may be returned, never a nested one");
  }

  @Test
  @DisplayName("R09: a key that appears only nested yields empty at the top level")
  void onlyNestedYieldsEmpty() {
    String body = "{\"data\":{\"access_token\":\"NESTED-ONLY\"}}";
    assertTrue(JsonResponse.accessToken(body).isEmpty(),
        "a key present only inside a nested object must not be extracted");
  }

  @Test
  @DisplayName("R09: a string value containing the key text is not mistaken for the key")
  void keyTextInsideValueNotMatched() {
    // The value of "note" contains the substring access_token but is not a key.
    String body = "{\"note\":\"see access_token below\",\"access_token\":\"real\"}";
    assertEquals(Optional.of("real"), JsonResponse.accessToken(body));
  }
}
