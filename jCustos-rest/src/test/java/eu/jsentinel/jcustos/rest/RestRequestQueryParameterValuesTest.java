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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * JS-SEC-098: {@link RestRequest#queryParameterValues()} is the multi-valued view of the query.
 * The default derives it from {@link RestRequest#queryParameters()} (lossy, one value each); an
 * adapter that knows its transport overrides it.
 */
@DisplayName("JS-SEC-098 — RestRequest.queryParameterValues: the multi-valued view of the query")
class RestRequestQueryParameterValuesTest {

  private static RestRequest withQuery(Map<String, String> query) {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/callback";
      }

      @Override public Map<String, String> headers() {
        return Map.of();
      }

      @Override public Map<String, String> queryParameters() {
        return query;
      }
    };
  }

  @Test
  @DisplayName("the default wraps every single value in a one-element list, in the map's order")
  void defaultIsDerived() {
    Map<String, String> query = new LinkedHashMap<>();
    query.put("state", "s-1");
    query.put("code", "c-1");
    Map<String, List<String>> values = withQuery(query).queryParameterValues();
    assertEquals(Map.of("state", List.of("s-1"), "code", List.of("c-1")), values);
    assertEquals(List.of("state", "code"), List.copyOf(values.keySet()));
  }

  @Test
  @DisplayName("the default skips null names and values and survives a null map")
  void defaultIsDefensive() {
    Map<String, String> query = new HashMap<>();
    query.put("state", null);
    query.put(null, "x");
    query.put("code", "c-1");
    assertEquals(Map.of("code", List.of("c-1")), withQuery(query).queryParameterValues());
    assertEquals(Map.of(), withQuery(null).queryParameterValues());
  }
}
