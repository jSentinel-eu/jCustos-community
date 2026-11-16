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

import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenStore;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-125 (CWE-770): the stores whose keys arrive with requests are bounded, and what a full
 * store does is defined per store. Real storages on a temp directory, opened with a small bound
 * and a clock the test moves.
 */
@DisplayName("Eclipse-Store adapters - every request-keyed store is bounded and has an expiry path")
class EclipseStoreBoundedStoresTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  private static final SubjectId ALICE = new SubjectId("alice");

  /** A clock the test sets; the storage asks it what "expired" means when a store is full. */
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
  }

  @TempDir
  Path tempDir;

  private final TestClock clock = new TestClock();

  private EclipseStoreJCustosStorage open(int bound) {
    return EclipseStoreJCustosStorage.openAt(tempDir, bound, clock);
  }

  private static SessionRecord session(String id) {
    return new SessionRecord(new SessionId(id), ALICE, TenantId.DEFAULT, T0, T0,
        JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }

  private static List<String> sessionIds(SessionStore store) {
    return store.findAll().stream().map(record -> record.sessionId().value()).toList();
  }

  @Test
  @DisplayName("sessions: at the bound the record stored first goes; an update of a known session evicts nothing")
  void sessionsAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(5)) {
      SessionStore store = storage.sessionStore();
      for (int i = 0; i < 5; i++) {
        store.save(session("s" + i));
      }
      for (int i = 0; i < 20; i++) {
        store.save(session("s2").withLastActivityAt(T0.plusSeconds(i)));
      }
      assertEquals(List.of("s0", "s1", "s2", "s3", "s4"), sessionIds(store));

      store.save(session("s5"));
      store.save(session("s6"));
      store.save(session("s7"));
      assertEquals(List.of("s3", "s4", "s5", "s6", "s7"), sessionIds(store));
    }
    try (EclipseStoreJCustosStorage reopened = open(5)) {
      assertEquals(List.of("s3", "s4", "s5", "s6", "s7"), sessionIds(reopened.sessionStore()),
          "what the bound removed is removed on disk as well");
      assertEquals(5, reopened.tables().sessions.size());
    }
  }

  @Test
  @DisplayName("a storage that holds more than the bound is trimmed by the next new entry")
  void oversizedStoreIsTrimmed() {
    try (EclipseStoreJCustosStorage generous = open(100)) {
      for (int i = 0; i < 30; i++) {
        generous.sessionStore().save(session("old-" + i));
      }
    }
    try (EclipseStoreJCustosStorage bounded = open(10)) {
      assertEquals(30, bounded.tables().sessions.size(), "opening does not drop anything");
      bounded.sessionStore().save(session("new"));
      assertEquals(10, bounded.tables().sessions.size());
      assertTrue(bounded.sessionStore().findById(new SessionId("new")).isPresent());
      assertTrue(bounded.sessionStore().findById(new SessionId("old-29")).isPresent());
      assertTrue(bounded.sessionStore().findById(new SessionId("old-0")).isEmpty());
    }
  }

  @Test
  @DisplayName("remember-me: expired tokens make room first; without one the token stored first goes")
  void rememberMeTokensAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(3)) {
      RememberMeTokenStore store = storage.rememberMeTokenStore();
      store.save(new RememberMeTokenRecord("long-1", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(1_000)));
      store.save(new RememberMeTokenRecord("short", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(10)));
      store.save(new RememberMeTokenRecord("long-2", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(1_000)));

      clock.now = T0.plusSeconds(20);
      store.save(new RememberMeTokenRecord("new-1", TenantId.DEFAULT, ALICE, clock.now, T0.plusSeconds(1_000)));
      assertTrue(store.findByHash("short").isEmpty(), "the expired token made room");
      assertTrue(store.findByHash("long-1").isPresent(), "no live token was touched");

      store.save(new RememberMeTokenRecord("new-2", TenantId.DEFAULT, ALICE, clock.now, T0.plusSeconds(1_000)));
      assertTrue(store.findByHash("long-1").isEmpty(), "nothing expired: the token stored first goes");
      assertTrue(store.findByHash("long-2").isPresent());
      assertTrue(store.findByHash("new-1").isPresent());
      assertTrue(store.findByHash("new-2").isPresent());
      assertEquals(3, storage.tables().rememberMeTokens.size());
    }
  }

  @Test
  @DisplayName("remember-me rotation trail: bounded on its own; the oldest trail goes")
  void rotationTrailIsBounded() {
    try (EclipseStoreJCustosStorage storage = open(2)) {
      RememberMeTokenStore store = storage.rememberMeTokenStore();
      for (int i = 0; i < 4; i++) {
        store.save(new RememberMeTokenRecord("t" + i, TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(1_000)));
        assertTrue(store.markRotated("t" + i, T0.plusSeconds(i)));
      }
      assertEquals(2, storage.tables().rememberMeRotated.size());
      assertTrue(store.findRotated("t0").isEmpty());
      assertTrue(store.findRotated("t1").isEmpty());
      assertTrue(store.findRotated("t2").isPresent());
      assertTrue(store.findRotated("t3").isPresent());
    }
  }

  @Test
  @DisplayName("password reset: consumed and expired records make room; a store full of open tokens refuses the next one")
  void passwordResetTokensAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(3)) {
      PasswordResetTokenStore store = storage.passwordResetTokenStore();
      store.save(resetToken("open-1", T0.plusSeconds(100)));
      store.save(resetToken("open-2", T0.plusSeconds(900)));
      store.save(resetToken("open-3", T0.plusSeconds(900)));

      IllegalStateException full = assertThrows(IllegalStateException.class,
          () -> store.save(resetToken("open-4", T0.plusSeconds(900))));
      assertTrue(full.getMessage().startsWith(
          "accountlifecycle/password-reset-token-store-capacity-exceeded"), full.getMessage());
      assertTrue(store.findByHash("open-4").isEmpty());
      assertTrue(store.findByHash("open-1").isPresent(), "an open token is never pushed out");

      // using a token at the bound is not a new entry
      assertTrue(store.markConsumed("open-2", T0.plusSeconds(5)));
      store.save(resetToken("open-4", T0.plusSeconds(900)));
      assertTrue(store.findByHash("open-2").isEmpty(), "the consumed record made room");

      clock.now = T0.plusSeconds(100);
      store.save(resetToken("open-5", T0.plusSeconds(900)));
      assertTrue(store.findByHash("open-1").isEmpty(), "the expired record made room");
      assertEquals(3, storage.tables().passwordResetTokens.size());
      assertThrows(IllegalStateException.class,
          () -> store.save(resetToken("open-6", T0.plusSeconds(900))));
    }
  }

  private static PasswordResetTokenRecord resetToken(String hash, Instant expiresAt) {
    return new PasswordResetTokenRecord(hash, TenantId.DEFAULT, ALICE, T0, expiresAt, Optional.empty());
  }

  @Test
  @DisplayName("email verification: the same rule, with its own code")
  void emailVerificationTokensAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(2)) {
      EmailVerificationTokenStore store = storage.emailVerificationTokenStore();
      store.save(verificationToken("open-1"));
      store.save(verificationToken("open-2"));
      IllegalStateException full = assertThrows(IllegalStateException.class,
          () -> store.save(verificationToken("open-3")));
      assertTrue(full.getMessage().startsWith(
          "accountlifecycle/email-verification-token-store-capacity-exceeded"), full.getMessage());
      assertTrue(store.markConsumed("open-1", T0.plusSeconds(5)));
      store.save(verificationToken("open-3"));
      assertTrue(store.findByHash("open-1").isEmpty());
      assertEquals(2, storage.tables().emailVerificationTokens.size());
    }
  }

  private static EmailVerificationTokenRecord verificationToken(String hash) {
    return new EmailVerificationTokenRecord(hash, TenantId.DEFAULT, ALICE, "alice@example.org",
        T0, T0.plusSeconds(900), Optional.empty());
  }

  @Test
  @DisplayName("refresh tokens: expired records first, then the record stored first; a rotation at the bound keeps the bound")
  void refreshTokensAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(3)) {
      RefreshTokenStore store = storage.refreshTokenStore();
      store.save(refreshToken("a", T0.plusSeconds(1_000)));
      store.save(refreshToken("short", T0.plusSeconds(10)));
      store.save(refreshToken("c", T0.plusSeconds(1_000)));

      clock.now = T0.plusSeconds(20);
      assertTrue(store.rotate("c", refreshToken("d", T0.plusSeconds(1_000)), clock.now));
      assertEquals(3, storage.tables().refreshTokens.size());
      assertTrue(store.findByHash("short").isEmpty(), "the expired record made room");
      assertEquals(Optional.of("d"), store.findByHash("c").orElseThrow().replacedByHash());
      assertTrue(store.findByHash("a").isPresent());

      assertTrue(store.rotate("d", refreshToken("e", T0.plusSeconds(1_000)), clock.now));
      assertEquals(3, storage.tables().refreshTokens.size(), "claim and successor must not exceed the bound");
      assertTrue(store.findByHash("a").isEmpty(), "nothing expired: the record stored first goes");
      assertTrue(store.findByHash("d").orElseThrow().isReplaced());
      assertTrue(store.findByHash("e").orElseThrow().isActive(clock.now));
    }
  }

  private static RefreshTokenRecord refreshToken(String hash, Instant expiresAt) {
    return new RefreshTokenRecord(hash, TenantId.DEFAULT, ALICE, T0, expiresAt,
        Optional.empty(), Optional.empty());
  }

  @Test
  @DisplayName("rate limit: at the bound the key used least recently goes - a key under throttle stays")
  void rateLimitKeysAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(3)) {
      RateLimitStore store = storage.rateLimitStore();
      RateLimitKey throttled = key("login:admin");
      Instant since = T0.minusSeconds(60);
      assertTrue(store.tryAdmit(throttled, T0, since, 1).admitted());
      store.recordEvent(key("client:b"), T0);
      store.recordEvent(key("client:c"), T0);
      for (int i = 0; i < 20; i++) {
        assertFalse(store.tryAdmit(throttled, T0.plusSeconds(1), since, 1).admitted(),
            "the throttle was lifted by spraying " + i + " new keys");
        store.recordEvent(key("spray:" + i), T0.plusSeconds(1));
        assertEquals(3, storage.tables().rateLimitBuckets.size());
      }
      assertEquals(0, store.countSince(key("client:b"), T0), "the idle keys went first");
    }
  }

  @Test
  @DisplayName("rate limit: a bucket whose events left every window applied to it is dropped in passing; one with an unknown window is not")
  void deadRateLimitBucketsExpire() {
    try (EclipseStoreJCustosStorage storage = open(1_000)) {
      RateLimitStore store = storage.rateLimitStore();
      for (int i = 0; i < 50; i++) {
        // a policy with a one-minute window
        assertTrue(store.tryAdmit(key("ip:" + i), T0, T0.minusSeconds(60), 5).admitted());
      }
      store.recordEvent(key("recorded-only"), T0);
      assertEquals(51, storage.tables().rateLimitBuckets.size());

      // 61 seconds later nothing has expired yet for a caller looking 60 seconds back from T0+60 ...
      Instant withinWindow = T0.plusSeconds(60);
      assertTrue(store.tryAdmit(key("other"), withinWindow, withinWindow.minusSeconds(60), 5).admitted());
      assertEquals(2, store.tryAdmit(key("ip:7"), withinWindow, withinWindow.minusSeconds(60), 5)
          .eventsInWindow(), "an event exactly at the window start still counts");

      // ... and ten minutes later the buckets are dead and go with the next admission
      Instant muchLater = T0.plusSeconds(600);
      assertTrue(store.tryAdmit(key("late"), muchLater, muchLater.minusSeconds(60), 5).admitted());
      assertEquals(2, storage.tables().rateLimitBuckets.size(),
          "left: the key just admitted and the key whose window nobody ever stated");
      assertEquals(1, store.countSince(key("recorded-only"), T0));
    }
    try (EclipseStoreJCustosStorage reopened = open(1_000)) {
      assertEquals(2, reopened.tables().rateLimitBuckets.size(), "the expiry is on disk");
    }
  }

  @Test
  @DisplayName("rate limit: the window a policy applied to a key survives a restart, so its bucket still expires afterwards")
  void rateLimitWindowSurvivesRestart() {
    try (EclipseStoreJCustosStorage storage = open(1_000)) {
      assertTrue(storage.rateLimitStore()
          .tryAdmit(key("ip:1"), T0, T0.minusSeconds(60), 5).admitted());
    }
    try (EclipseStoreJCustosStorage reopened = open(1_000)) {
      Instant muchLater = T0.plusSeconds(600);
      assertTrue(reopened.rateLimitStore()
          .tryAdmit(key("ip:2"), muchLater, muchLater.minusSeconds(60), 5).admitted());
      assertEquals(1, reopened.tables().rateLimitBuckets.size());
    }
  }

  @Test
  @DisplayName("rate limit: one key holds a bounded number of events; tryAdmit refuses at that bound")
  void rateLimitEventsPerKeyAreBounded() {
    try (EclipseStoreJCustosStorage storage = open(10)) {
      RateLimitStore store = new EclipseStoreRateLimitStore(storage, 5);
      RateLimitKey k = key("ip:9.9.9.9");
      for (int i = 0; i < 100; i++) {
        store.recordEvent(k, T0.plusSeconds(i));
      }
      assertEquals(5, store.countSince(k, T0));
      assertEquals(5, store.countSince(k, T0.plusSeconds(95)), "the newest events are the ones kept");
      RateLimitStore.Admission refused = store.tryAdmit(k, T0.plusSeconds(100), T0, 1_000);
      assertFalse(refused.admitted(), "a limit above the per-key bound must not be unreachable");
      assertEquals(5, refused.eventsInWindow());
    }
  }

  private static RateLimitKey key(String scope) {
    return new RateLimitKey(TenantId.DEFAULT, scope);
  }

  @Test
  @DisplayName("the bound has to be positive")
  void boundMustBePositive() {
    assertThrows(IllegalArgumentException.class,
        () -> EclipseStoreJCustosStorage.openAt(tempDir, 0));
    assertThrows(IllegalArgumentException.class,
        () -> JCustosStorageFactory.openAt(tempDir, StorageLayout.DEFAULT, 0));
  }
}
