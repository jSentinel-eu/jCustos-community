/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.abuse;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AbusePatternMonitorTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static AbuseAttemptContext login(
      String user, String ip, Instant at) {
    return new AbuseAttemptContext(
        AbuseAttemptType.LOGIN,
        Optional.of(user), Optional.of(ip),
        TenantId.DEFAULT, at);
  }

  private static AbuseAttemptContext reset(String user, Instant at) {
    return new AbuseAttemptContext(
        AbuseAttemptType.RESET_REQUEST,
        Optional.of(user), Optional.empty(),
        TenantId.DEFAULT, at);
  }

  @Test
  @DisplayName("Password spraying: one client touches many usernames → SPRAYING signal")
  void sprayingDetected() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    for (int i = 0; i < 8; i++) {
      monitor.observe(login("user-" + i, "10.0.0.1", T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    // Threshold is 8 distinct users in 5 min.
    assertEquals(1, signals.size());
    AbusePatternSignal signal = signals.get(0);
    assertEquals(AbusePattern.PASSWORD_SPRAYING, signal.pattern());
    assertTrue(signal.distinctTargets() >= 8);
  }

  @Test
  @DisplayName("Spraying detector ignores the volume from a single repeated user")
  void singleUserDoesNotSpray() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    for (int i = 0; i < 50; i++) {
      monitor.observe(login("alice", "10.0.0.1", T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    assertFalse(signals.stream()
            .anyMatch(s -> s.pattern() == AbusePattern.PASSWORD_SPRAYING),
        "single repeated user must not trigger SPRAYING");
  }

  @Test
  @DisplayName("Credential stuffing: many clients fail against one username → STUFFING signal")
  void stuffingDetected() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    for (int i = 0; i < 5; i++) {
      monitor.observe(login("alice", "10.0.0." + i, T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    assertTrue(signals.stream()
        .anyMatch(s -> s.pattern() == AbusePattern.CREDENTIAL_STUFFING));
  }

  @Test
  @DisplayName("Stuffing detector ignores successful login mix from many clients")
  void successDoesNotStuff() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    for (int i = 0; i < 5; i++) {
      monitor.observe(login("alice", "10.0.0." + i, T0.plusSeconds(i)),
          AttemptOutcome.SUCCESS);
    }
    assertFalse(signals.stream()
        .anyMatch(s -> s.pattern() == AbusePattern.CREDENTIAL_STUFFING));
  }

  @Test
  @DisplayName("Reset abuse: many reset requests for one user → RESET_ABUSE signal")
  void resetAbuseDetected() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    for (int i = 0; i < 5; i++) {
      monitor.observe(reset("alice", T0.plusSeconds(i * 60L)),
          AttemptOutcome.SUCCESS);
    }
    assertTrue(signals.stream()
        .anyMatch(s -> s.pattern() == AbusePattern.RESET_ABUSE));
  }

  @Test
  @DisplayName("AbusePatternSignal carries minimised data (no usernames or IPs)")
  void signalIsPrivacyMinimised() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    for (int i = 0; i < 8; i++) {
      monitor.observe(login("user-" + i, "10.0.0.1", T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    assertEquals(1, signals.size());
    String text = signals.get(0).toString();
    assertFalse(text.contains("10.0.0.1"));
    for (int i = 0; i < 8; i++) {
      assertFalse(text.contains("user-" + i),
          "username must not appear in the signal");
    }
  }

  @Test
  @DisplayName("Window expiry: events older than the spraying window are discarded")
  void windowExpiryDropsOldAttempts() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    // First wave outside the eventual window.
    for (int i = 0; i < 5; i++) {
      monitor.observe(login("user-" + i, "10.0.0.1", T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    // Second wave far enough in the future to evict the first wave.
    Instant later = T0.plus(Duration.ofMinutes(10));
    for (int i = 5; i < 9; i++) {
      monitor.observe(login("user-" + i, "10.0.0.1", later.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    // No signal — only 4 distinct users inside the live window.
    assertFalse(signals.stream()
        .anyMatch(s -> s.pattern() == AbusePattern.PASSWORD_SPRAYING));
  }

  @Test
  @DisplayName("Config rejects negative thresholds and null windows")
  void configInvariants() {
    org.junit.jupiter.api.Assertions.assertThrows(
        NullPointerException.class,
        () -> new AbusePatternMonitor.Config(
            8, null, 5, Duration.ofMinutes(15), 5, Duration.ofHours(1)));
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> new AbusePatternMonitor.Config(
            -1, Duration.ofMinutes(5),
            5, Duration.ofMinutes(15),
            5, Duration.ofHours(1)));
  }

  @Test
  @DisplayName("Zero thresholds disable individual detectors")
  void zeroThresholdDisables() {
    AbusePatternMonitor.Config cfg = new AbusePatternMonitor.Config(
        0, Duration.ofMinutes(5),
        0, Duration.ofMinutes(15),
        0, Duration.ofHours(1));
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(cfg, signals::add);
    for (int i = 0; i < 50; i++) {
      monitor.observe(login("u" + i, "10.0.0.1", T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
      monitor.observe(reset("alice", T0.plusSeconds(i)),
          AttemptOutcome.SUCCESS);
    }
    assertTrue(signals.isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-078: 200 000 distinct clients stay within the per-pattern bound; idle keys are purged")
  void boundedAndPurgeable() {
    java.util.List<AbusePatternSignal> signals = new java.util.ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(AbusePatternMonitor.Config.defaults(), signals::add, 1_000);
    java.time.Instant t0 = java.time.Instant.parse("2026-06-01T12:00:00Z");
    for (int i = 0; i < 200_000; i++) {
      monitor.observe(login("user-" + i, "10.0." + (i / 256) + "." + (i % 256), t0.plusMillis(i)), AttemptOutcome.FAILURE);
    }
    assertTrue(monitor.snapshotCardinalities().get(AbusePattern.PASSWORD_SPRAYING) <= 1_000,
        "spraying keys must stay within the bound");
    assertTrue(monitor.snapshotCardinalities().get(AbusePattern.CREDENTIAL_STUFFING) <= 1_000,
        "stuffing keys must stay within the bound");

    int removed = monitor.purgeIdle(t0.plus(java.time.Duration.ofDays(1)));
    assertTrue(removed > 0, "idle keys are removed once their window has passed");
    assertEquals(0, monitor.snapshotCardinalities().get(AbusePattern.PASSWORD_SPRAYING));
    assertEquals(0, monitor.snapshotCardinalities().get(AbusePattern.CREDENTIAL_STUFFING));
    assertThrows(IllegalArgumentException.class,
        () -> new AbusePatternMonitor(AbusePatternMonitor.Config.defaults(), signals::add, 0));
  }

  @Test
  @DisplayName("snapshotCardinalities returns the number of tracked keys per pattern")
  void snapshotCardinalities() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    monitor.observe(login("alice", "10.0.0.1", T0), AttemptOutcome.FAILURE);
    monitor.observe(login("bob", "10.0.0.2", T0), AttemptOutcome.FAILURE);
    monitor.observe(reset("carol", T0), AttemptOutcome.SUCCESS);
    assertEquals(2,
        monitor.snapshotCardinalities().get(AbusePattern.PASSWORD_SPRAYING));
    assertEquals(2,
        monitor.snapshotCardinalities().get(AbusePattern.CREDENTIAL_STUFFING));
    assertEquals(1,
        monitor.snapshotCardinalities().get(AbusePattern.RESET_ABUSE));
  }

  @Test
  @DisplayName("Anonymous attempts (no client / no username) do not feed any detector")
  void anonymousIgnored() {
    List<AbusePatternSignal> signals = new ArrayList<>();
    AbusePatternMonitor monitor = new AbusePatternMonitor(
        AbusePatternMonitor.Config.defaults(), signals::add);
    AbuseAttemptContext anon = new AbuseAttemptContext(
        AbuseAttemptType.LOGIN,
        Optional.empty(), Optional.empty(),
        TenantId.DEFAULT, T0);
    monitor.observe(anon, AttemptOutcome.FAILURE);
    assertTrue(signals.isEmpty());
    assertEquals(0,
        monitor.snapshotCardinalities().get(AbusePattern.PASSWORD_SPRAYING));
  }
}
