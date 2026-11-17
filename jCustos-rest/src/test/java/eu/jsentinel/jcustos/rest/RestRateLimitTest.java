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
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicy;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitStore;
import eu.jsentinel.jcustos.ratelimiting.RateLimitDecision;
import eu.jsentinel.jcustos.ratelimiting.RateLimitEscalation;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RestRateLimit} answers a rate-limit decision: nothing for an admitted
 * request, {@code 429} with a {@code Retry-After} rounded up to whole seconds for
 * a throttle and for a block, with the same body for both.
 */
@DisplayName("RestRateLimit - 429 with Retry-After for Throttled and Blocked")
class RestRateLimitTest {

  private static final Duration MINUTE = Duration.ofMinutes(1);

  /** Records what a handler writes. */
  private static final class RecordingResponse implements RestResponse {
    int status;
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

  @Test
  @DisplayName("Allowed: nothing is written, the handler proceeds")
  void allowedWritesNothing() {
    RecordingResponse response = new RecordingResponse();
    assertFalse(RestRateLimit.respond(new RateLimitDecision.Allowed(1, 5, MINUTE), response));
    assertEquals(0, response.status);
    assertNull(response.body);
    assertEquals(Map.of(), response.headers);
  }

  @Test
  @DisplayName("Throttled: 429, Retry-After rounded up - 30 s + 1 ns becomes 31")
  void throttledAnswers429() {
    RecordingResponse response = new RecordingResponse();
    assertTrue(RestRateLimit.respond(
        new RateLimitDecision.Throttled(5, 5, MINUTE, Duration.ofSeconds(30).plusNanos(1)),
        response));
    assertEquals(HttpStatus.TOO_MANY_REQUESTS.code(), response.status);
    assertEquals(Map.of(RestThrottleResponses.RETRY_AFTER, "31"), response.headers);
    assertEquals(RestThrottleResponses.DEFAULT_BODY, response.body);
  }

  @Test
  @DisplayName("Blocked: 429 with the block's remaining time and the same body as a throttle")
  void blockedAnswers429() {
    RecordingResponse response = new RecordingResponse();
    assertTrue(RestRateLimit.respond(
        new RateLimitDecision.Blocked(0, 5, MINUTE, Duration.ofMinutes(10), 3), response));
    assertEquals(HttpStatus.TOO_MANY_REQUESTS.code(), response.status);
    assertEquals(Map.of(RestThrottleResponses.RETRY_AFTER, "600"), response.headers);
    assertEquals(RestThrottleResponses.DEFAULT_BODY, response.body,
        "the client cannot tell a block from a throttle");

    RecordingResponse own = new RecordingResponse();
    assertTrue(RestRateLimit.respond(
        new RateLimitDecision.Blocked(0, 5, MINUTE, Duration.ofMillis(10), 3), own,
        "{\"error\":\"slow down\"}"));
    assertEquals("1", own.headers.get(RestThrottleResponses.RETRY_AFTER), "at least one second");
    assertEquals("{\"error\":\"slow down\"}", own.body);
  }

  @Test
  @DisplayName("through a real escalating policy: two 429 for the throttles, a 429 of ten minutes for the block")
  void throughAnEscalatingPolicy() {
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(new InMemoryRateLimitStore(),
        new NoAudit(), 1, MINUTE, Clock.fixed(t0, ZoneOffset.UTC),
        new RateLimitEscalation(3, Duration.ofMinutes(5), Duration.ofMinutes(10)));
    RateLimitKey key = new RateLimitKey(TenantId.DEFAULT, "ip:198.51.100.7");

    assertFalse(RestRateLimit.respond(policy.tryAcquire(key), new RecordingResponse()));
    for (int i = 0; i < 2; i++) {
      RecordingResponse throttled = new RecordingResponse();
      assertTrue(RestRateLimit.respond(policy.tryAcquire(key), throttled));
      assertEquals("61", throttled.headers.get(RestThrottleResponses.RETRY_AFTER),
          "the event at t0 leaves the window one nanosecond after one minute");
    }
    RateLimitDecision third = policy.tryAcquire(key);
    assertInstanceOf(RateLimitDecision.Blocked.class, third);
    RecordingResponse blocked = new RecordingResponse();
    assertTrue(RestRateLimit.respond(third, blocked));
    assertEquals(HttpStatus.TOO_MANY_REQUESTS.code(), blocked.status);
    assertEquals("600", blocked.headers.get(RestThrottleResponses.RETRY_AFTER));
  }

  @Test
  @DisplayName("null arguments are refused before anything is written")
  void nullsAreRefused() {
    RecordingResponse response = new RecordingResponse();
    RateLimitDecision throttled = new RateLimitDecision.Throttled(1, 1, MINUTE, MINUTE);
    assertThrows(NullPointerException.class, () -> RestRateLimit.respond(null, response));
    assertThrows(NullPointerException.class, () -> RestRateLimit.respond(throttled, null));
    assertThrows(NullPointerException.class,
        () -> RestRateLimit.respond(throttled, response, null));
    assertEquals(0, response.status);
    assertEquals(Map.of(), response.headers);
  }

  /** Discards audit events. */
  private static final class NoAudit implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }
}
