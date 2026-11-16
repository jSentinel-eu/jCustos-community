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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-129 (CWE-294): at its bound the Eclipse-Store refresh-token store drops the record
 * stored first. When that record was rotated and has not expired, it is the anchor that makes a
 * replay of its token recognisable - dropping it is counted and logged, never silent.
 */
@DisplayName("JS-SEC-129 — an evicted replay anchor of the refresh-token store is counted and reported")
class EclipseStoreRefreshTokenReplayAnchorTest {

  private static final Instant T0 = Instant.parse("2026-11-16T10:00:00Z");
  private static final SubjectId VICTIM = new SubjectId("victim");

  /** A clock the test moves; the storage and the token service read it. */
  private static final class TestClock extends Clock {
    private Instant now = T0;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }

    void advance(Duration step) {
      now = now.plus(step);
    }
  }

  /** Keeps every audit event. */
  private static final class RecordingAudit implements JCustosAuditService {
    final List<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }
  }

  @TempDir
  Path tempDir;

  private final TestClock clock = new TestClock();
  private final AtomicLong counter = new AtomicLong();

  private TokenService tokens(EclipseStoreRefreshTokenStore store) {
    return new TokenService(store, new Sha256TokenHasher(), new RecordingAudit(),
        TenantId.DEFAULT, clock, () -> "plainvalue-" + counter.incrementAndGet(),
        Duration.ofMinutes(15), Duration.ofDays(30));
  }

  @Test
  @DisplayName("a thief who rotates a stolen token until the owner's record is evicted leaves a counted trace")
  void evictedAnchorIsCounted() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir, 4, clock)) {
      EclipseStoreRefreshTokenStore store =
          (EclipseStoreRefreshTokenStore) storage.refreshTokenStore();
      TokenService service = tokens(store);
      TokenService.TokenPair owners = service.issue(VICTIM);
      String stolen = owners.refreshToken();
      String current = stolen;
      for (int i = 0; i < 3; i++) { // owner's record + three successors: the bound of four
        clock.advance(Duration.ofSeconds(1));
        current = service.rotate(current).orElseThrow().refreshToken();
      }
      assertEquals(4, storage.tables().refreshTokens.size());
      assertEquals(0L, store.replayAnchorsEvicted(), "nothing was evicted yet");

      clock.advance(Duration.ofSeconds(1));
      current = service.rotate(current).orElseThrow().refreshToken();

      assertEquals(1L, store.replayAnchorsEvicted(), "the owner's rotated record had to go");
      assertTrue(storage.tables().refreshTokens.size() <= 4);
      // The documented residual: the owner's token is unknown now, its family is not revoked.
      assertTrue(service.rotate(stolen).isEmpty());
      assertTrue(service.rotate(current).isPresent(), "documented residual, see the class comment");
    }
  }

  @Test
  @DisplayName("evicting a live or an expired record is no lost anchor")
  void otherEvictionsAreNotCounted() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir, 2, clock)) {
      EclipseStoreRefreshTokenStore store =
          (EclipseStoreRefreshTokenStore) storage.refreshTokenStore();
      store.save(record("live-1", Duration.ofDays(1), Optional.empty()));
      store.save(record("rotated-expired", Duration.ofSeconds(5), Optional.of("elsewhere")));
      clock.advance(Duration.ofSeconds(10));

      store.save(record("live-2", Duration.ofDays(1), Optional.empty()));
      store.save(record("live-3", Duration.ofDays(1), Optional.empty()));

      assertEquals(0L, store.replayAnchorsEvicted());
      assertTrue(store.findByHash("live-1").isEmpty(), "the live record stored first went");
    }
  }

  private RefreshTokenRecord record(String hash, Duration ttl, Optional<String> replacedBy) {
    return new RefreshTokenRecord(hash, TenantId.DEFAULT, VICTIM, clock.now,
        clock.now.plus(ttl), replacedBy, Optional.empty());
  }
}
