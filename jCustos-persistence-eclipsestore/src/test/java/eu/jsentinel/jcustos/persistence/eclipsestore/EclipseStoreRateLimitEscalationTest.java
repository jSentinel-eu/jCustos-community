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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicy;
import eu.jsentinel.jcustos.ratelimiting.RateLimitDecision;
import eu.jsentinel.jcustos.ratelimiting.RateLimitEscalation;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Eclipse-Store rate-limit store under the 00.84.00 policy: the retry-after
 * of a throttle is {@code oldest + window - now} (plus one nanosecond), a block
 * is stored with the key and survives a restart, a blocked key outlives the
 * sweep for dead buckets while its block lasts, and a storage written before
 * blocks existed opens without any.
 */
@DisplayName("EclipseStoreRateLimitStore - retry-after, blocks and escalation")
class EclipseStoreRateLimitEscalationTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  private static final Duration WINDOW = Duration.ofMinutes(1);
  private static final Duration BLOCK = Duration.ofMinutes(10);
  private static final RateLimitKey KEY = new RateLimitKey(TenantId.DEFAULT, "ip:198.51.100.7");
  /** The escalation window outlasts the block, so the throttles that caused it are still in it. */
  private static final RateLimitEscalation ESCALATION =
      new RateLimitEscalation(3, Duration.ofMinutes(15), BLOCK);

  @TempDir
  Path tempDir;

  @Test
  @DisplayName("events at T0, T0+10s, T0+20s, throttled at T0+30s: retry after 30 s + 1 ns, as in memory")
  void retryAfterIsOldestPlusWindowMinusNow() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      MutableClock clock = new MutableClock(T0);
      InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
          storage.rateLimitStore(), new NoAudit(), 3, WINDOW, clock);
      for (Instant at : List.of(T0, T0.plusSeconds(10), T0.plusSeconds(20))) {
        clock.set(at);
        assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
      }
      clock.set(T0.plusSeconds(30));
      RateLimitDecision.Throttled throttled =
          assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
      assertEquals(Duration.ofSeconds(30).plusNanos(1), throttled.retryAfter());

      clock.set(T0.plusSeconds(30).plus(throttled.retryAfter()));
      assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY),
          "a client that waits exactly retryAfter finds a free slot");
    }
  }

  @Test
  @DisplayName("the third throttle blocks; the block survives a restart and ends after its duration")
  void escalationSurvivesRestart() {
    Instant third = T0.plusSeconds(3);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      MutableClock clock = new MutableClock(T0);
      InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
          storage.rateLimitStore(), new NoAudit(), 1, WINDOW, clock, ESCALATION);
      assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY));
      clock.set(T0.plusSeconds(1));
      assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
      clock.set(T0.plusSeconds(2));
      assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY));
      clock.set(third);
      RateLimitDecision.Blocked blocked =
          assertInstanceOf(RateLimitDecision.Blocked.class, policy.tryAcquire(KEY));
      assertEquals(BLOCK, blocked.retryAfter());
      assertEquals(3, blocked.throttledCount());
    }

    Instant afterRestart = third.plusSeconds(120); // the window is empty, the block is not over
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      MutableClock clock = new MutableClock(afterRestart);
      InMemoryRateLimitPolicy policy = new InMemoryRateLimitPolicy(
          reopened.rateLimitStore(), new NoAudit(), 1, WINDOW, clock, ESCALATION);
      RateLimitDecision.Blocked blocked = assertInstanceOf(RateLimitDecision.Blocked.class,
          policy.tryAcquire(KEY), "a restart must not lift the block");
      assertEquals(BLOCK.minusSeconds(120), blocked.retryAfter());

      clock.set(third.plus(BLOCK));
      assertInstanceOf(RateLimitDecision.Allowed.class, policy.tryAcquire(KEY),
          "the block ends after its duration");
      clock.set(third.plus(BLOCK).plusSeconds(1));
      assertInstanceOf(RateLimitDecision.Throttled.class, policy.tryAcquire(KEY),
          "the throttles that caused the block were spent, also on disk");
    }
  }

  @Test
  @DisplayName("block, its growth and a reset survive a close/reopen")
  void blockSurvivesRestart() {
    RateLimitKey other = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.9");
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      store.recordEvent(KEY, T0);
      store.block(KEY, T0.plusSeconds(300));
      store.block(KEY, T0.plusSeconds(600)); // changes the stored bucket in place
      store.block(other, T0.plusSeconds(60)); // a key without events
      store.block(other, T0.plusSeconds(30)); // shorter: no change
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = reopened.rateLimitStore();
      assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(KEY));
      assertEquals(1, store.countSince(KEY, T0), "the events are kept beside the block");
      assertEquals(Optional.of(T0.plusSeconds(60)), store.blockedUntil(other));
      store.reset(KEY);
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertEquals(Optional.empty(), reopened.rateLimitStore().blockedUntil(KEY),
          "the lifted block stays lifted");
    }
  }

  @Test
  @DisplayName("a purge that ends a block of a key with events survives a close/reopen")
  void purgedBlockStaysPurged() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      store.block(KEY, T0.plusSeconds(10));
      store.recordEvent(KEY, T0.plusSeconds(100));
      assertEquals(0, store.purgeOlderThan(T0.plusSeconds(50)));
      assertEquals(Optional.empty(), store.blockedUntil(KEY));
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = reopened.rateLimitStore();
      assertEquals(Optional.empty(), store.blockedUntil(KEY), "the ended block is gone on disk");
      assertEquals(1, store.countSince(KEY, T0));
    }
  }

  @Test
  @DisplayName("a blocked key without events outlives the sweep for dead buckets until its block ends")
  void blockedBucketIsNotSweptWhileTheBlockLasts() {
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir, 1_000, Clock.fixed(T0, ZoneOffset.UTC))) {
      RateLimitStore store = storage.rateLimitStore();
      store.block(KEY, T0.plusSeconds(600));
      RateLimitKey busy = new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2.1");

      Instant during = T0.plusSeconds(300); // the busy key's admissions sweep in passing
      assertTrue(store.tryAdmit(busy, during, during.minus(WINDOW), 5).admitted());
      assertEquals(2, storage.tables().rateLimitBuckets.size());
      assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(KEY),
          "a bucket without events is not dead while its block lasts");

      Instant after = T0.plusSeconds(700);
      assertTrue(store.tryAdmit(busy, after, after.minus(WINDOW), 5).admitted());
      assertEquals(1, storage.tables().rateLimitBuckets.size(),
          "once the block has ended the bucket is dead and goes in passing");
      assertEquals(Optional.empty(), store.blockedUntil(KEY));
    }
  }

  @Test
  @DisplayName("at the bound a blocked key that is being asked for is in use: the idle key goes first")
  void blockedKeyInUseIsNotTheFirstToBeEvicted() {
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir, 3, Clock.fixed(T0, ZoneOffset.UTC))) {
      RateLimitStore store = storage.rateLimitStore();
      RateLimitKey idle = new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2.1");
      RateLimitKey other = new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2.2");
      RateLimitKey fresh = new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2.3");
      store.block(KEY, T0.plusSeconds(600)); // the eldest entry
      assertTrue(store.tryAdmit(idle, T0, T0.minus(WINDOW), 5).admitted());
      assertTrue(store.tryAdmit(other, T0, T0.minus(WINDOW), 5).admitted());
      // the blocked client keeps asking: its requests reach the store through blockedUntil only
      assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(KEY));

      assertTrue(store.tryAdmit(fresh, T0, T0.minus(WINDOW), 5).admitted());
      assertEquals(3, storage.tables().rateLimitBuckets.size());
      assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(KEY),
          "the blocked key in use must not make room for a new key");
      assertEquals(0, store.countSince(idle, T0), "the key used least recently went");
    }
  }

  @Test
  @DisplayName("at the bound an idle key with a lasting block stays; the unblocked keys make room")
  void idleLastingBlockSurvivesTheBound() {
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir, 3, Clock.fixed(T0, ZoneOffset.UTC))) {
      RateLimitStore store = storage.rateLimitStore();
      store.block(KEY, T0.plusSeconds(600)); // the eldest entry, and nobody asks for it again
      for (int i = 0; i < 12; i++) {
        RateLimitKey fresh = new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2." + i);
        assertTrue(store.tryAdmit(fresh, T0, T0.minus(WINDOW), 5).admitted(), "fresh key " + i);
      }
      assertEquals(3, storage.tables().rateLimitBuckets.size(), "the bound holds");
      assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(KEY),
          "the idle blocked key was passed over");
    }
  }

  @Test
  @DisplayName("at the bound a block that has ended by the storage clock is evicted like any key")
  void endedBlockIsEvictedLikeAnyKey() {
    MutableClock clock = new MutableClock(T0);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir, 2, clock)) {
      RateLimitStore store = storage.rateLimitStore();
      RateLimitKey other = new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2.1");
      // an event under a one-hour window keeps the bucket alive after its block has ended
      assertTrue(store.tryAdmit(KEY, T0, T0.minus(Duration.ofHours(1)), 5).admitted());
      store.block(KEY, T0.plusSeconds(10));
      store.recordEvent(other, T0.plusSeconds(1)); // used after KEY

      clock.set(T0.plusSeconds(20));
      store.block(new RateLimitKey(TenantId.DEFAULT, "ip:192.0.2.2"), T0.plusSeconds(600));

      assertEquals(2, storage.tables().rateLimitBuckets.size());
      assertEquals(0, store.countSince(KEY, T0), "the key used least recently went: its block"
          + " had ended, so it protected nothing any more");
      assertEquals(1, store.countSince(other, T0));
    }
  }

  @Test
  @DisplayName("when every key has a lasting block, the block that ends first makes room")
  void onlyLastingBlocksLeftTheOneEndingFirstGoes() {
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir, 3, Clock.fixed(T0, ZoneOffset.UTC))) {
      RateLimitStore store = storage.rateLimitStore();
      RateLimitKey early = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.1");
      RateLimitKey middle = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.2");
      RateLimitKey late = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.3");
      store.block(middle, T0.plusSeconds(600));
      store.block(late, T0.plusSeconds(900));
      store.block(early, T0.plusSeconds(300));

      RateLimitKey fresh = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.4");
      assertTrue(store.tryAdmit(fresh, T0, T0.minus(WINDOW), 5).admitted(),
          "a new key is never refused - the bound makes room");
      assertEquals(3, storage.tables().rateLimitBuckets.size());
      assertEquals(Optional.empty(), store.blockedUntil(early), "the block that ends first went");
      assertEquals(Optional.of(T0.plusSeconds(600)), store.blockedUntil(middle));
      assertEquals(Optional.of(T0.plusSeconds(900)), store.blockedUntil(late));
    }
  }

  @Test
  @DisplayName("a storage written before blocks existed opens without any, and keeps a block written now")
  void storageWrittenBeforeBlocksOpensWithoutAny() throws Exception {
    LegacyStorageFixtures.copyTo(
        LegacyStorageFixtures.WRITTEN_BY_00_84_00_BEFORE_REMEMBER_ME_MARKS, tempDir);
    RateLimitKey client = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.5");
    Instant until = LegacyStorageFixtures.T0.plusSeconds(3_600);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      assertEquals(3, store.countSince(client, LegacyStorageFixtures.T0),
          "the events of the fixture are read back");
      assertEquals(Optional.empty(), store.blockedUntil(client), "a bucket stored before has none");
      assertEquals(until, store.block(client, until));
    }
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = reopened.rateLimitStore();
      assertEquals(Optional.of(until), store.blockedUntil(client));
      assertEquals(3, store.countSince(client, LegacyStorageFixtures.T0));
    }
  }

  /** Mutable clock that returns whatever instant the test set. */
  private static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    void set(Instant at) {
      this.now = at;
    }

    @Override
    public ZoneOffset getZone() {
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
