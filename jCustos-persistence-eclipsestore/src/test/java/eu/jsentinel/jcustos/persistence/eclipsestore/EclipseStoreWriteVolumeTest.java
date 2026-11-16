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

import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import java.util.function.IntConsumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-125 (CWE-770, CWE-400, CWE-407): what the stores write to disk. Until 00.84.00 every
 * mutation rewrote the map of its store - 16 bytes per entry - so the n-th failed login with a
 * new user name wrote n entries: 2 000 of them put 32 MB on the disk, 10 000 nearly 800 MB, and
 * a full disk fails every store, revocation and lockout included. The tests measure the files of
 * a real storage directory.
 */
@DisplayName("Eclipse-Store adapters - a mutation writes the changed entry, not the store")
class EclipseStoreWriteVolumeTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  private static final int OPERATIONS = 2_000;
  /**
   * Generous for what {@value #OPERATIONS} operations really write (a few hundred bytes each),
   * and a small fraction of the 32 MB the same operations wrote before.
   */
  private static final long BYTES_ALLOWED = 3_000_000L;

  @TempDir
  Path tempDir;

  private static long bytesOnDisk(Path directory) {
    try (Stream<Path> files = Files.walk(directory)) {
      return files.filter(Files::isRegularFile).mapToLong(file -> {
        try {
          return Files.size(file);
        } catch (IOException gone) {
          return 0L; // a file the housekeeping removed meanwhile
        }
      }).sum();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Runs {@code operation} for 0..count-1 and returns by how much the storage directory grew. */
  private long growth(int from, int to, IntConsumer operation) {
    long before = bytesOnDisk(tempDir);
    for (int i = from; i < to; i++) {
      operation.accept(i);
    }
    return bytesOnDisk(tempDir) - before;
  }

  private static void assertWithinBudget(String what, long written) {
    assertTrue(written < BYTES_ALLOWED,
        what + " wrote " + written + " bytes for " + OPERATIONS + " operations");
  }

  @Test
  @DisplayName("failed logins with 2 000 different user names: the storage grows linearly, well below the old 32 MB")
  void loginAttemptsWithDistinctKeys() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      LoginAttemptStore store = storage.loginAttemptStore();
      IntConsumer failedLogin = i -> store.recordFailure(
          new LoginAttemptKey(TenantId.DEFAULT, "sprayed-user-" + i, "203.0.113.9"), T0.plusMillis(i));
      long firstHalf = growth(0, OPERATIONS / 2, failedLogin);
      long secondHalf = growth(OPERATIONS / 2, OPERATIONS, failedLogin);

      assertWithinBudget("the login-attempt store", firstHalf + secondHalf);
      assertTrue(secondHalf < 2 * firstHalf,
          "the second thousand keys must not cost a multiple of the first thousand: "
              + firstHalf + " then " + secondHalf + " bytes");
      assertEquals(OPERATIONS, storage.tables().loginAttempts.size());
    }
  }

  @Test
  @DisplayName("2 000 new sessions, then 2 000 activity updates of one of them")
  void sessions() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      SessionStore store = storage.sessionStore();
      long created = growth(0, OPERATIONS, i -> store.save(new SessionRecord(
          new SessionId("session-" + i), new SubjectId("user-" + i), TenantId.DEFAULT,
          T0, T0, JCustosVersion.INITIAL, SessionStatus.ACTIVE)));
      assertWithinBudget("creating sessions", created);

      SessionRecord one = store.findById(new SessionId("session-7")).orElseThrow();
      long updated = growth(0, OPERATIONS, i -> store.save(one.withLastActivityAt(T0.plusSeconds(i))));
      assertWithinBudget("updating one session among " + OPERATIONS, updated);
      assertEquals(T0.plusSeconds(OPERATIONS - 1),
          store.findById(new SessionId("session-7")).orElseThrow().lastActivityAt());
    }
  }

  @Test
  @DisplayName("2 000 rate-limit keys, then 2 000 admissions on one of them")
  void rateLimit() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      long keys = growth(0, OPERATIONS, i -> store.tryAdmit(
          new RateLimitKey(TenantId.DEFAULT, "ip:198.51.100." + i), T0, T0.minusSeconds(60), 5));
      assertWithinBudget("new rate-limit keys", keys);

      RateLimitKey busy = new RateLimitKey(TenantId.DEFAULT, "ip:198.51.100.7");
      long admissions = growth(0, OPERATIONS, i -> store.tryAdmit(
          busy, T0.plusSeconds(i), T0.plusSeconds(i).minusSeconds(60), 100));
      assertWithinBudget("admissions on one key", admissions);
    }
  }

  @Test
  @DisplayName("2 000 audit events and 2 000 refresh tokens")
  void auditAndRefreshTokens() {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      AuditEventStore audit = storage.auditEventStore();
      assertWithinBudget("the audit store", growth(0, OPERATIONS, i -> audit.append(TenantId.DEFAULT,
          new LoginFailed(T0.plusMillis(i), "user-" + i, "192.0.2.1", "bad-credentials"))));

      RefreshTokenStore refresh = storage.refreshTokenStore();
      assertWithinBudget("the refresh-token store", growth(0, OPERATIONS, i -> refresh.save(
          new RefreshTokenRecord("hash-" + i, TenantId.DEFAULT, new SubjectId("user-" + i),
              T0, T0.plusSeconds(3_600), Optional.empty(), Optional.empty()))));
    }
  }
}
