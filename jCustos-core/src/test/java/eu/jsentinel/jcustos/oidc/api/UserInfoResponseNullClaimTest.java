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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Defect 625469c2 (CWE-476): OIDC Core allows a UserInfo response to carry a claim with the
 * value JSON {@code null}. The record's immutable copy threw a {@link NullPointerException}
 * for it; a {@code null} claim is now an absent claim, as for the claims of a validated JWT
 * (JS-SEC-149).
 */
@DisplayName("625469c2 — UserInfoResponse: a JSON null claim is an absent claim, not a NullPointerException")
class UserInfoResponseNullClaimTest {

  @Test
  @DisplayName("a top-level null claim is dropped; the other claims stay, the copy is immutable")
  void topLevelNullClaimIsDropped() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", "alice");
    claims.put("middle_name", null);
    claims.put("email", "a@example.com");

    UserInfoResponse response = new UserInfoResponse("alice", claims);

    assertEquals(Map.of("sub", "alice", "email", "a@example.com"), response.claims());
    assertFalse(response.claims().containsKey("middle_name"), "a null claim is an absent claim");
    assertEquals(Optional.empty(), response.claim("middle_name", Object.class));
    assertEquals(Optional.of("a@example.com"), response.claim("email", String.class));
    assertThrows(UnsupportedOperationException.class, () -> response.claims().put("x", "y"));
    assertTrue(claims.containsKey("middle_name"), "the caller's map is not changed");
  }

  @Test
  @DisplayName("a response whose only optional claims are null keeps the subject")
  void onlyNullClaims() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", "alice");
    claims.put("name", null);
    claims.put("picture", null);

    UserInfoResponse response = new UserInfoResponse("alice", claims);

    assertEquals(Map.of("sub", "alice"), response.claims());
    assertEquals("alice", response.subject());
  }

  @Test
  @DisplayName("null inside a nested object or array is kept as given - the copy is shallow and does not throw")
  void nestedNullsAreKept() {
    Map<String, Object> address = new LinkedHashMap<>();
    address.put("locality", null);
    address.put("country", "DE");
    List<Object> groups = new ArrayList<>(Arrays.asList("staff", null, "admins"));
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", "alice");
    claims.put("address", address);
    claims.put("groups", groups);

    UserInfoResponse response = new UserInfoResponse("alice", claims);

    Map<?, ?> keptAddress = response.claim("address", Map.class).orElseThrow();
    assertTrue(keptAddress.containsKey("locality"));
    assertNull(keptAddress.get("locality"));
    assertEquals("DE", keptAddress.get("country"));
    List<?> keptGroups = response.claim("groups", List.class).orElseThrow();
    assertEquals(3, keptGroups.size(), "positions in an array keep their meaning");
    assertNull(keptGroups.get(1));
  }

  @Test
  @DisplayName("a null subject, a null claim map or a null claim name is still refused")
  void nullArgumentsAreRefused() {
    assertThrows(NullPointerException.class, () -> new UserInfoResponse(null, Map.of()));
    assertThrows(NullPointerException.class, () -> new UserInfoResponse("alice", null));
    Map<String, Object> nullName = new HashMap<>();
    nullName.put(null, "value");
    assertThrows(NullPointerException.class, () -> new UserInfoResponse("alice", nullName));
  }
}
