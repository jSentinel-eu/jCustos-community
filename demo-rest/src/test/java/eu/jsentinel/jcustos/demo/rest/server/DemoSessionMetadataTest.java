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

import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUser;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.session.SessionMetadata;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoSubjectResolver — resolveSessionMetadata + DemoTokenStore lifetime")
class DemoSessionMetadataTest {

  private static final Instant T0 = Instant.parse("2026-05-10T10:00:00Z");

  @Test
  @DisplayName("resolveMetadata returns empty for unknown / null tokens")
  void unknownToken() {
    DemoTokenStore store = new DemoTokenStore(Clock.fixed(T0, ZoneOffset.UTC));

    assertTrue(store.resolveMetadata(null).isEmpty());
    assertTrue(store.resolveMetadata("").isEmpty());
    assertTrue(store.resolveMetadata("not-a-real-token").isEmpty());
  }

  @Test
  @DisplayName("issue stamps createdAt and lastActivityAt to the current clock instant")
  void issueStampsTimestamps() {
    DemoTokenStore store = new DemoTokenStore(Clock.fixed(T0, ZoneOffset.UTC));
    DemoUser user = aUser();

    String token = store.issue(user);

    DemoTokenStore.Metadata m = store.resolveMetadata(token).orElseThrow();
    assertEquals(T0, m.createdAt());
    assertEquals(T0, m.lastActivityAt());
    assertEquals(user, m.user());
  }

  @Test
  @DisplayName("markActivity bumps lastActivityAt and reports the previous value")
  void markActivityBumpsAndReportsPrevious() {
    MutableClock clock = new MutableClock(T0);
    DemoTokenStore store = new DemoTokenStore(clock);
    String token = store.issue(aUser());

    clock.advance(Duration.ofMinutes(7));
    Optional<Instant> previous = store.markActivity(token);

    assertEquals(Optional.of(T0), previous,
        "previous lastActivityAt must be the original creation instant");
    DemoTokenStore.Metadata after = store.resolveMetadata(token).orElseThrow();
    assertEquals(T0.plus(Duration.ofMinutes(7)), after.lastActivityAt());
    assertEquals(T0, after.createdAt(),
        "createdAt is set once and must not be touched by markActivity");
  }

  @Test
  @DisplayName("markActivity is a no-op for unknown tokens")
  void markActivityNoopOnUnknown() {
    DemoTokenStore store = new DemoTokenStore(Clock.fixed(T0, ZoneOffset.UTC));

    Optional<Instant> previous = store.markActivity("not-a-token");

    assertTrue(previous.isEmpty());
  }

  @Test
  @DisplayName("DemoSubjectResolver.resolveSessionMetadata reports the *previous* lastActivity, then bumps")
  void resolverReportsPreviousActivityAndBumps() {
    MutableClock clock = new MutableClock(T0);
    DemoTokenStore tokens = new DemoTokenStore(clock);
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, new DemoRolePermissionMapping());

    DemoUser user = aUser();
    String token = tokens.issue(user);

    // Some time has elapsed before the request
    clock.advance(Duration.ofMinutes(20));

    Optional<SessionMetadata> metadata = resolver.resolveSessionMetadata(
        bearerRequest(token));

    SessionMetadata snapshot = metadata.orElseThrow();
    assertEquals(user.username(), snapshot.subjectId());
    assertEquals(T0, snapshot.createdAt());
    assertEquals(T0, snapshot.lastActivityAt(),
        "snapshot must reflect the lastActivityAt as it stood *before* this request");

    // The store has bumped lastActivity to "now" so the next request observes a fresh idle gap
    DemoTokenStore.Metadata storeAfter = tokens.resolveMetadata(token).orElseThrow();
    assertEquals(T0.plus(Duration.ofMinutes(20)), storeAfter.lastActivityAt());
  }

  @Test
  @DisplayName("resolveSessionMetadata returns empty when no Bearer token is supplied")
  void noTokenNoMetadata() {
    DemoTokenStore tokens = new DemoTokenStore(Clock.fixed(T0, ZoneOffset.UTC));
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, new DemoRolePermissionMapping());

    Optional<SessionMetadata> metadata = resolver.resolveSessionMetadata(
        new SimpleRestRequest("GET", "/api/me", Map.of(), Map.of()));

    assertTrue(metadata.isEmpty());
  }

  // ── Helpers ───────────────────────────────────────────────────

  private static DemoUser aUser() {
    DemoUserStore users = new DemoUserStore(PasswordHashingServices.defaults(),
        DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR);
    return users.authenticate("admin", "admin").orElseThrow();
  }

  private static RestRequest bearerRequest(String token) {
    return new SimpleRestRequest(
        "GET", "/api/me",
        Map.of("Authorization", "Bearer " + token),
        Map.of());
  }

  record SimpleRestRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters
  ) implements RestRequest {

    @Override
    public Map<String, String> headers() {
      return headers;
    }

    @Override
    public Map<String, String> queryParameters() {
      return queryParameters;
    }

    @Override
    public String method() {
      return method;
    }

    @Override
    public String path() {
      return path;
    }
  }

  /** Test clock whose instant can be advanced manually. */
  static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration delta) {
      this.now = now.plus(delta);
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }
  }
}
