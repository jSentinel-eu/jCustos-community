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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JS-SEC-063: {@link RestThrottleResponses} writes {@code 429} with a {@code Retry-After} that is
 * never rounded down to a moment at which the client would be refused again.
 */
@DisplayName("RestThrottleResponses - 429 with Retry-After")
class RestThrottleResponsesTest {

  /** Records what a handler writes. */
  private static final class RecordingResponse implements RestResponse {
    int status;
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String body) {
      this.body = body;
    }

    @Override public void header(String name, String value) {
      headers.put(name, value);
    }
  }

  @Test
  @DisplayName("tooManyRequests: status 429, Retry-After in whole seconds, the generic body")
  void tooManyRequests() {
    RecordingResponse response = new RecordingResponse();
    RestThrottleResponses.tooManyRequests(response, Duration.ofSeconds(90));
    assertEquals(HttpStatus.TOO_MANY_REQUESTS.code(), response.status);
    assertEquals(Map.of("Retry-After", "90"), response.headers);
    assertEquals(RestThrottleResponses.DEFAULT_BODY, response.body);
    assertEquals(HttpStatus.TOO_MANY_REQUESTS.reason(), RestThrottleResponses.DEFAULT_BODY);
  }

  @Test
  @DisplayName("a body of the application's own format")
  void ownBody() {
    RecordingResponse response = new RecordingResponse();
    RestThrottleResponses.tooManyRequests(response, Duration.ofMillis(1), "{\"error\":\"slow down\"}");
    assertEquals(HttpStatus.TOO_MANY_REQUESTS.code(), response.status);
    assertEquals("1", response.headers.get(RestThrottleResponses.RETRY_AFTER));
    assertEquals("{\"error\":\"slow down\"}", response.body);
  }

  @Test
  @DisplayName("Retry-After rounds up to whole seconds, at least one")
  void retryAfterRoundsUp() {
    assertEquals("1", RestThrottleResponses.retryAfterValue(Duration.ZERO));
    assertEquals("1", RestThrottleResponses.retryAfterValue(Duration.ofSeconds(-5)));
    assertEquals("1", RestThrottleResponses.retryAfterValue(Duration.ofMillis(250)));
    assertEquals("1", RestThrottleResponses.retryAfterValue(Duration.ofSeconds(1)));
    assertEquals("2", RestThrottleResponses.retryAfterValue(Duration.ofMillis(1001)));
    assertEquals("2", RestThrottleResponses.retryAfterValue(Duration.ofMillis(1900)));
    assertEquals("900", RestThrottleResponses.retryAfterValue(Duration.ofMinutes(15)));
    assertEquals(Long.toString(Long.MAX_VALUE),
        RestThrottleResponses.retryAfterValue(Duration.ofSeconds(Long.MAX_VALUE, 999_999_999)));
  }

  @Test
  @DisplayName("null arguments are refused before anything is written")
  void nullsAreRefused() {
    RecordingResponse response = new RecordingResponse();
    assertThrows(NullPointerException.class,
        () -> RestThrottleResponses.tooManyRequests(null, Duration.ofSeconds(1)));
    assertThrows(NullPointerException.class,
        () -> RestThrottleResponses.tooManyRequests(response, null));
    assertThrows(NullPointerException.class,
        () -> RestThrottleResponses.tooManyRequests(response, Duration.ofSeconds(1), null));
    assertEquals(0, response.status);
    assertEquals(Map.of(), response.headers);
  }
}
