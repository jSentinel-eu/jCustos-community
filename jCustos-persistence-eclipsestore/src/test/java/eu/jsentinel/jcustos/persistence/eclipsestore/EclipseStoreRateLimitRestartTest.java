/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Restart-persistence tests for the rate-limit store (R002). The other contract
 * tests never close and reopen the storage, so they cannot catch an in-place
 * nested-collection mutation that {@code store(parentMap)} fails to persist.
 * These tests open, mutate, {@code close()}, reopen the same directory, and
 * assert the change survived.
 */
@DisplayName("EclipseStoreRateLimitStore — survives restart (R002)")
class EclipseStoreRateLimitRestartTest {

  @TempDir
  Path tempDir;

  private static final RateLimitKey KEY = new RateLimitKey(TenantId.DEFAULT, "login");
  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");

  @Test
  @DisplayName("multiple recorded events survive a close/reopen")
  void recordedEventsSurviveRestart() {
    // The 2nd and 3rd recordEvent mutate an already-persisted set in place.
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      store.recordEvent(KEY, T0);
      store.recordEvent(KEY, T0.plusSeconds(1));
      store.recordEvent(KEY, T0.plusSeconds(2));
      assertEquals(3, store.countSince(KEY, T0));
    }
    try (EclipseStoreJCustosStorage reopened =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertEquals(3, reopened.rateLimitStore().countSince(KEY, T0),
          "all recorded events must survive a restart");
    }
  }

  @Test
  @DisplayName("a purge survives a close/reopen")
  void purgeSurvivesRestart() {
    Instant cutoff = T0.plusSeconds(10);
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      store.recordEvent(KEY, T0);                 // before cutoff
      store.recordEvent(KEY, T0.plusSeconds(1));  // before cutoff
      store.recordEvent(KEY, T0.plusSeconds(20)); // after cutoff — survives
      assertEquals(2, store.purgeOlderThan(cutoff));
      assertEquals(1, store.countSince(KEY, T0));
    }
    try (EclipseStoreJCustosStorage reopened =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = reopened.rateLimitStore();
      assertEquals(1, store.countSince(KEY, T0),
          "exactly one event must remain after the purge survives a restart");
      // the surviving event must be the post-cutoff one, not a stale pre-purge
      // element left behind by an unpersisted in-place mutation.
      assertEquals(1, store.countSince(KEY, T0.plusSeconds(15)),
          "the surviving event must be the after-cutoff one (T0+20)");
    }
  }

  @Test
  @DisplayName("JS-SEC-118: events with one and the same instant survive a close/reopen as separate events")
  void equalInstantsSurviveRestart() {
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      store.recordEvent(KEY, T0);
      store.recordEvent(KEY, T0);
      store.recordEvent(KEY, T0);
      assertEquals(3, store.countSince(KEY, T0));
    }
    try (EclipseStoreJCustosStorage reopened =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertEquals(3, reopened.rateLimitStore().countSince(KEY, T0),
          "a set would have kept one of the three");
    }
  }

  @Test
  @DisplayName("JS-SEC-118: a limit reached before a restart is still reached after it")
  void admissionsSurviveRestart() {
    Instant since = T0.minusSeconds(60);
    try (EclipseStoreJCustosStorage storage =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore store = storage.rateLimitStore();
      for (int i = 0; i < 3; i++) {
        assertEquals(true, store.tryAdmit(KEY, T0, since, 3).admitted());
      }
      assertEquals(false, store.tryAdmit(KEY, T0, since, 3).admitted());
    }
    try (EclipseStoreJCustosStorage reopened =
             EclipseStoreJCustosStorage.openAt(tempDir)) {
      RateLimitStore.Admission refused = reopened.rateLimitStore().tryAdmit(KEY, T0, since, 3);
      assertEquals(false, refused.admitted(), "a restart must not hand out a fresh budget");
      assertEquals(3, refused.eventsInWindow());
    }
  }
}
