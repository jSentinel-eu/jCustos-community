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

import com.svenruppert.functional.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-098 (RFC 6749 §3.1): the one reader of an authorisation response for the REST and the
 * Vaadin adapter — every response parameter at most once.
 */
@DisplayName("JS-SEC-098 — CallbackParams.fromMultiValued: each response parameter at most once")
class CallbackParamsFromMultiValuedTest {

  private static Map<String, List<String>> query(String... pairs) {
    Map<String, List<String>> query = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) {
      query.computeIfAbsent(pairs[i], k -> new ArrayList<>()).add(pairs[i + 1]);
    }
    return query;
  }

  private static AuthorizationCodeFlow.CallbackParams accepted(Map<String, List<String>> query) {
    Result<AuthorizationCodeFlow.CallbackParams, OAuth2Error> result =
        AuthorizationCodeFlow.CallbackParams.fromMultiValued(query);
    assertTrue(result.isSuccess(), () -> "expected acceptance: " + result);
    return result.getOrThrow();
  }

  private static OAuth2Error.StateInvalid refused(Map<String, List<String>> query) {
    Result<AuthorizationCodeFlow.CallbackParams, OAuth2Error> result =
        AuthorizationCodeFlow.CallbackParams.fromMultiValued(query);
    assertTrue(result.isFailure(), () -> "expected a refusal for " + query.keySet());
    return assertInstanceOf(OAuth2Error.StateInvalid.class, result.fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("a well-formed success response maps every parameter")
  void successResponse() {
    AuthorizationCodeFlow.CallbackParams params = accepted(query(
        "code", "c-1", "state", "s-1", "iss", "https://idp.example", "session_state", "x"));
    assertEquals(Optional.of("c-1"), params.code());
    assertEquals("s-1", params.state());
    assertEquals(Optional.of("https://idp.example"), params.iss());
    assertEquals(Optional.empty(), params.error());
    assertEquals(Optional.empty(), params.errorDescription());
  }

  @Test
  @DisplayName("a well-formed error response maps error and error_description")
  void errorResponse() {
    AuthorizationCodeFlow.CallbackParams params = accepted(query(
        "error", "access_denied", "error_description", "user said no", "state", "s-1"));
    assertEquals(Optional.of("access_denied"), params.error());
    assertEquals(Optional.of("user said no"), params.errorDescription());
    assertEquals(Optional.empty(), params.code());
  }

  @ParameterizedTest
  @ValueSource(strings = {"state", "code", "iss", "error", "error_description", "error_uri"})
  @DisplayName("a repeated response parameter refuses the whole callback, naming the parameter only")
  void repeatedParameterRefused(String name) {
    Map<String, List<String>> query = query("code", "c-1", "state", "s-1");
    query.computeIfAbsent(name, k -> new ArrayList<>()).add("attacker-value");
    if (query.get(name).size() == 1) {
      query.get(name).add("second-value");
    }
    OAuth2Error.StateInvalid refusal = refused(query);
    assertEquals("callback-parameter-repeated:" + name, refusal.detail());
    assertTrue(!refusal.toString().contains("attacker-value"), refusal.toString());
  }

  @Test
  @DisplayName("the same value twice is a repetition as well")
  void identicalRepetitionRefused() {
    refused(query("code", "c-1", "state", "s-1", "state", "s-1"));
  }

  @Test
  @DisplayName("a repeated parameter that is not a response parameter is ignored")
  void foreignRepetitionIgnored() {
    AuthorizationCodeFlow.CallbackParams params = accepted(query(
        "code", "c-1", "state", "s-1", "session_state", "a", "session_state", "b"));
    assertEquals("s-1", params.state());
  }

  @Test
  @DisplayName("a callback without state, or with a blank one, is refused")
  void missingState() {
    assertEquals("callback-without-state", refused(query("code", "c-1")).detail());
    refused(query("code", "c-1", "state", ""));
    refused(query("code", "c-1", "state", "   "));
    refused(Map.of("state", List.of()));
    refused(Map.of());
    assertEquals("callback-without-state", refusedNull().detail());
  }

  private static OAuth2Error.StateInvalid refusedNull() {
    Result<AuthorizationCodeFlow.CallbackParams, OAuth2Error> result =
        AuthorizationCodeFlow.CallbackParams.fromMultiValued(null);
    return assertInstanceOf(OAuth2Error.StateInvalid.class, result.fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("blank optional parameters count as absent, null values are skipped")
  void blankAndNullValues() {
    Map<String, List<String>> query = new LinkedHashMap<>();
    query.put("state", Arrays.asList(null, "s-1"));
    query.put("code", List.of(" "));
    query.put("iss", Arrays.asList((String) null));
    AuthorizationCodeFlow.CallbackParams params = accepted(query);
    assertEquals("s-1", params.state());
    assertEquals(Optional.empty(), params.code());
    assertEquals(Optional.empty(), params.iss());
  }
}
