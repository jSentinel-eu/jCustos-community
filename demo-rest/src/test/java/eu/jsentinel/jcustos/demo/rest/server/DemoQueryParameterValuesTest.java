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
package eu.jsentinel.jcustos.demo.rest.server;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * RF31 (JS-SEC-098): the demo's request adapter reports every value of a repeated query
 * parameter, as {@code RestRequest.queryParameterValues()} asks of an adapter that knows its
 * transport. Until the exit review of 00.84.00 the router collapsed the query to one value per
 * name and the request kept the lossy default, so a repeated {@code state} could not be seen.
 */
@DisplayName("RF31 — demo request: every value of a repeated query parameter")
class DemoQueryParameterValuesTest {

  @Test
  @DisplayName("the router's query parser keeps every value in wire order and decodes names and values")
  void parseQuery_keepsEveryValue() {
    Map<String, List<String>> values =
        DemoHttpRouter.parseQuery("state=first&code=c%2B1&state=second&flag&na%6De=v+w");

    assertEquals(Map.of("state", List.of("first", "second"), "code", List.of("c+1"),
        "flag", List.of(""), "name", List.of("v w")), values);
    assertEquals(Map.of(), DemoHttpRouter.parseQuery(null));
    assertEquals(Map.of(), DemoHttpRouter.parseQuery(""));
  }

  @Test
  @DisplayName("a request built from the query lines reports all of them; queryParameters keeps the last value")
  void request_reportsEveryValue() {
    DemoHttpRequest request = DemoHttpRequest.fromHeaderLines("GET", "/oauth2/callback", Map.of(),
        DemoHttpRouter.parseQuery("state=first&code=c1&state=second"), null, "127.0.0.1");

    assertEquals(List.of("first", "second"), request.queryParameterValues().get("state"),
        "until the exit review the default derived from queryParameters() showed [second] only");
    assertEquals(List.of("c1"), request.queryParameterValues().get("code"));
    assertEquals("second", request.queryParameters().get("state"), "as the router's map did before");
    assertEquals("c1", request.queryParameters().get("code"));
  }

  @Test
  @DisplayName("a request built from a single-valued map reports one value per parameter")
  void singleValuedConstructor() {
    DemoHttpRequest request = new DemoHttpRequest("GET", "/api/audit/events", Map.of(),
        Map.of("type", "LoginFailed"), new byte[0]);

    assertEquals(Map.of("type", List.of("LoginFailed")), request.queryParameterValues());
    assertEquals(Map.of("type", "LoginFailed"), request.queryParameters());
  }
}
