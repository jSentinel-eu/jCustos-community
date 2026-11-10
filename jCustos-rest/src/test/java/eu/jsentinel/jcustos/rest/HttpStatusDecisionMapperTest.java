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
package eu.jsentinel.jcustos.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("HttpStatusDecisionMapper")
class HttpStatusDecisionMapperTest {

  private final HttpStatusDecisionMapper mapper = new HttpStatusDecisionMapper();

  @Test
  @DisplayName("Granted returns true and leaves the response untouched")
  void grantedReturnsTrue() {
    RecordingResponse response = new RecordingResponse();
    boolean result = mapper.apply(AuthorizationDecision.granted(), response);

    assertTrue(result);
    assertEquals(200, response.status);
    assertNull(response.body);
    assertTrue(response.headers.isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-086: Unauthenticated emits 401 with body 'Unauthorized' and the Bearer challenge")
  void unauthenticatedReturns401() {
    RecordingResponse response = new RecordingResponse();
    boolean result = mapper.apply(
        AuthorizationDecision.unauthenticated("no subject"), response);

    assertFalse(result);
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE),
        "a 401 without a challenge violates RFC 7235 §3.1");
  }

  @Test
  @DisplayName("Forbidden emits 403 with body 'Forbidden' and no challenge")
  void forbiddenReturns403() {
    RecordingResponse response = new RecordingResponse();
    boolean result = mapper.apply(
        AuthorizationDecision.forbidden("missing role"), response);

    assertFalse(result);
    assertEquals(403, response.status);
    assertEquals("Forbidden", response.body);
    assertFalse(response.headers.containsKey(RestHeaders.WWW_AUTHENTICATE),
        "re-authenticating does not help a forbidden subject, so a 403 carries no challenge");
  }

  @Test
  @DisplayName("StepUpRequired emits 401 + RFC-7235 'StepUp method=\"MFA\"' challenge")
  void stepUpReturns401WithChallenge() {
    RecordingResponse response = new RecordingResponse();
    boolean result = mapper.apply(
        AuthorizationDecision.stepUpRequired("needs mfa", "MFA"), response);

    assertFalse(result);
    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertEquals("StepUp method=\"MFA\"",
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @DisplayName("StepUpRequired with REAUTH method emits the REAUTH challenge")
  void stepUpReauthMethod() {
    RecordingResponse response = new RecordingResponse();
    mapper.apply(
        AuthorizationDecision.stepUpRequired("", "REAUTH"), response);

    assertEquals("StepUp method=\"REAUTH\"",
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @DisplayName("STEP_UP_SCHEME is the documented 'StepUp' constant")
  void stepUpSchemeConstant() {
    assertEquals("StepUp", HttpStatusDecisionMapper.STEP_UP_SCHEME);
  }

  @Test
  @DisplayName("JS-SEC-086: BEARER_CHALLENGE is the RFC 6750 'Bearer' scheme")
  void bearerChallengeConstant() {
    assertEquals("Bearer", HttpStatusDecisionMapper.BEARER_CHALLENGE);
  }

  @Test
  @DisplayName("JS-SEC-086: a custom body strategy changes the 401 body, never the challenge")
  void customBodiesKeepTheChallenge() {
    RecordingResponse response = new RecordingResponse();
    new HttpStatusDecisionMapper(decision -> "{\"status\":401}")
        .apply(AuthorizationDecision.unauthenticated("no subject"), response);

    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals("{\"status\":401}", response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  private static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body;
    }

    @Override
    public void header(String name, String value) {
      headers.put(name, value);
    }
  }
}
