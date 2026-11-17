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
package eu.jsentinel.jcustos.oauth2.internal;

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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-098 (CWE-1041): {@link OAuth2Json} keeps its signatures but reads through the one bounded
 * JSON reader of jCustos. The R09 guarantees of the former scanner hold; what is new is that a
 * malformed, oversized, too deep or duplicate-key body yields empty for every field, and that
 * unicode escapes are decoded.
 */
@DisplayName("JS-SEC-098 — OAuth2Json is a facade over BoundedJson")
class OAuth2JsonFacadeTest {

  @Test
  @DisplayName("R09 still holds: only top-level members are read, a key inside a value is no key")
  void topLevelOnly() {
    String body = "{\"error_context\":{\"echo\":{\"access_token\":\"NESTED-DECOY\"}},"
        + "\"note\":\"see access_token below\",\"access_token\":\"real-token\"}";
    assertEquals(Optional.of("real-token"), OAuth2Json.string(body, "access_token"));
    assertEquals(Optional.empty(), OAuth2Json.string("{\"data\":{\"access_token\":\"x\"}}", "access_token"));
  }

  @Test
  @DisplayName("unicode escapes are decoded (the scanner kept them raw)")
  void unicodeEscapeDecoded() {
    assertEquals(Optional.of("a-b/c"), OAuth2Json.string("{\"t\":\"a\\u002db\\/c\"}", "t"));
  }

  @Test
  @DisplayName("a repeated key makes the body unusable: every field is empty")
  void duplicateKeyEmptiesEveryField() {
    String body = "{\"active\":true,\"scope\":\"read\",\"active\":false}";
    assertEquals(Optional.empty(), OAuth2Json.bool(body, "active"));
    assertEquals(Optional.empty(), OAuth2Json.string(body, "scope"));
    assertEquals(Set.of(), OAuth2Json.stringOrArray(body, "scope"));
  }

  @Test
  @DisplayName("malformed, too deep or oversized bodies yield empty instead of a best-effort scan")
  void malformedBodiesYieldEmpty() {
    assertEquals(Optional.empty(), OAuth2Json.string("{\"access_token\":\"x\"", "access_token"));
    assertEquals(Optional.empty(), OAuth2Json.string("{\"access_token\":\"x\"} trailing", "access_token"));
    assertEquals(Optional.empty(), OAuth2Json.string("garbage {\"access_token\":\"x\"}", "access_token"));
    assertEquals(Optional.empty(), OAuth2Json.string((String) null, "access_token"));
    String deep = "{\"access_token\":\"x\",\"d\":" + "[".repeat(100) + "]".repeat(100) + "}";
    assertEquals(Optional.empty(), OAuth2Json.string(deep, "access_token"));
    String big = "{\"access_token\":\"x\",\"pad\":\"" + "a".repeat(1 << 20) + "\"}";
    assertEquals(Optional.empty(), OAuth2Json.string(big, "access_token"));
  }

  @Test
  @DisplayName("longValue and bool read only values of their own type; an overlong integer yields empty")
  void typedValues() {
    String body = "{\"exp\":1700000000,\"neg\":-5,\"str\":\"3600\",\"frac\":1.5,\"active\":true}";
    assertEquals(Optional.of(1700000000L), OAuth2Json.longValue(body, "exp"));
    assertEquals(Optional.of(-5L), OAuth2Json.longValue(body, "neg"));
    assertEquals(Optional.empty(), OAuth2Json.longValue(body, "str"));
    assertEquals(Optional.empty(), OAuth2Json.longValue(body, "frac"));
    assertEquals(Optional.of(true), OAuth2Json.bool(body, "active"));
    assertEquals(Optional.empty(), OAuth2Json.bool(body, "exp"));
    assertTrue(OAuth2Json.longValue("{\"expires_in\":999999999999999999999999999999}", "expires_in").isEmpty(),
        "H4: an out-of-range integer degrades to empty, it does not throw");
  }

  @Test
  @DisplayName("object(...) reads a body once; the map-taking accessors agree with the string-taking ones")
  void parseOnce() {
    String body = "{\"aud\":[\"rs-a\",\"rs-b\",7],\"iss\":\"op\",\"exp\":10}";
    Map<String, Object> json = OAuth2Json.object(body).orElseThrow();
    assertEquals(OAuth2Json.stringOrArray(body, "aud"), OAuth2Json.stringOrArray(json, "aud"));
    assertEquals(Set.of("rs-a", "rs-b"), OAuth2Json.stringOrArray(json, "aud"));
    assertEquals(OAuth2Json.string(body, "iss"), OAuth2Json.string(json, "iss"));
    assertEquals(OAuth2Json.longValue(body, "exp"), OAuth2Json.longValue(json, "exp"));
    assertTrue(OAuth2Json.object("[1]").isEmpty());
  }
}
