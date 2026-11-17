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
package eu.jsentinel.jcustos.credential.lifecycle;

import eu.jsentinel.jcustos.audit.CredentialStatusChanged;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.change.PasswordChangeCommand;
import eu.jsentinel.jcustos.credential.change.PasswordChangeResult;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.emergency.EmergencyPolicyOverride;
import eu.jsentinel.jcustos.credential.emergency.MassCredentialStatusChange;
import eu.jsentinel.jcustos.credential.reset.PasswordResetConsumeResult;
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenCreationResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-161 (CWE-284, CWE-620): a credential that was declared COMPROMISED
 * returns to ACTIVE only after a new secret was written - not through
 * DISABLED, MUST_CHANGE, LOCKED or RESET_PENDING on their own. Real stores,
 * the real hashing pipeline and the real change and reset services.
 */
@DisplayName("JS-SEC-161 — a compromised secret needs a rotation before ACTIVE")
class CredentialRotationProofTest {

  private static final String LEAKED = "leaked password 1";
  private static final String FRESH = "a brand new password 2";
  private static final Duration TTL = Duration.ofMinutes(15);

  private static CredentialTestKit compromisedAlice() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", LEAKED, CredentialStatus.ACTIVE);
    kit.clock.advance(Duration.ofMinutes(1));
    kit.lifecycle().transition("alice", CredentialStatus.ACTIVE, CredentialStatus.COMPROMISED,
        "breach");
    kit.clock.advance(Duration.ofMinutes(1));
    return kit;
  }

  private static CredentialRecord alice(CredentialTestKit kit) {
    return kit.credentials.findByUsername("alice").orElseThrow();
  }

  private static PasswordChangeService changeService(CredentialTestKit kit, CredentialStore store) {
    return new PasswordChangeService(store, kit.hashing, kit.validator, kit.inputPolicy,
        kit.lifecycle(store), kit.clock);
  }

  private static PasswordResetService resetService(CredentialTestKit kit, CredentialStore store) {
    return new PasswordResetService(store, kit.resetTokens, kit.digests, kit.hashing,
        kit.validator, kit.inputPolicy, kit.lifecycle(store), kit.clock, kit.audit);
  }

  private static long statusEvents(CredentialTestKit kit, CredentialStatus to) {
    return kit.audit.events.stream()
        .filter(CredentialStatusChanged.class::isInstance)
        .map(CredentialStatusChanged.class::cast)
        .filter(event -> event.toStatus() == to)
        .count();
  }

  @Test
  @DisplayName("COMPROMISED records when it was compromised; the mark stays through DISABLED")
  void compromiseIsRecordedAndKept() {
    CredentialTestKit kit = compromisedAlice();
    Instant compromisedAt = alice(kit).updatedAt();
    assertEquals(compromisedAt, alice(kit).compromisedSince());

    kit.lifecycle().transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED,
        "incident");

    CredentialRecord disabled = alice(kit);
    assertEquals(CredentialStatus.DISABLED, disabled.status());
    assertEquals(compromisedAt, disabled.compromisedSince());
    assertTrue(disabled.secretRotationRequired());
  }

  @Test
  @DisplayName("bypass 1: COMPROMISED -> DISABLED -> ACTIVE is refused while the secret is the old one")
  void disabledDoesNotLaunderTheSecret() {
    CredentialTestKit kit = compromisedAlice();
    CredentialLifecycleService lifecycle = kit.lifecycle();
    lifecycle.transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, "x");
    long activations = statusEvents(kit, CredentialStatus.ACTIVE);

    InvalidStatusTransitionException refused = assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("alice", CredentialStatus.DISABLED, CredentialStatus.ACTIVE,
            "re-enable"));

    assertEquals(InvalidStatusTransitionException.Reason.SECRET_ROTATION_REQUIRED,
        refused.reason());
    assertFalse(refused.getMessage().contains("alice"), "no username in the message");
    assertEquals(CredentialStatus.DISABLED, kit.status("alice"));
    assertEquals(activations, statusEvents(kit, CredentialStatus.ACTIVE), "nothing audited");
    assertTrue(kit.passwordIs("alice", LEAKED));
  }

  @Test
  @DisplayName("bypass 2: COMPROMISED -> MUST_CHANGE -> ACTIVE is refused while the secret is the old one")
  void mustChangeDoesNotLaunderTheSecret() {
    CredentialTestKit kit = compromisedAlice();
    CredentialLifecycleService lifecycle = kit.lifecycle();
    lifecycle.transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE, "x");

    InvalidStatusTransitionException refused = assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("alice", CredentialStatus.MUST_CHANGE, CredentialStatus.ACTIVE,
            "admin-clears-flag"));

    assertEquals(InvalidStatusTransitionException.Reason.SECRET_ROTATION_REQUIRED,
        refused.reason());
    assertEquals(CredentialStatus.MUST_CHANGE, kit.status("alice"));
  }

  @Test
  @DisplayName("the detours over LOCKED and RESET_PENDING are refused as well")
  void otherDetoursAreRefused() {
    CredentialTestKit kit = compromisedAlice();
    CredentialLifecycleService lifecycle = kit.lifecycle();
    lifecycle.transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE, "x");
    lifecycle.transition("alice", CredentialStatus.MUST_CHANGE, CredentialStatus.LOCKED, "x");
    assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("alice", CredentialStatus.LOCKED, CredentialStatus.ACTIVE, "x"));
    lifecycle.transition("alice", CredentialStatus.LOCKED, CredentialStatus.DISABLED, "x");
    lifecycle.transition("alice", CredentialStatus.DISABLED, CredentialStatus.RESET_PENDING, "x");
    assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("alice", CredentialStatus.RESET_PENDING,
            CredentialStatus.ACTIVE, "admin-skips-the-reset"));
    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));
  }

  @Test
  @DisplayName("a rehash of the old password is no rotation")
  void rehashIsNoRotation() {
    CredentialTestKit kit = compromisedAlice();
    CredentialLifecycleService lifecycle = kit.lifecycle();
    lifecycle.transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, "x");
    CredentialRecord before = alice(kit);
    String rehashed = kit.hashing.hash(LEAKED.toCharArray()).encodedHash();

    assertInstanceOf(CredentialUpdateResult.Updated.class, kit.credentials.updateHashIfCurrent(
        "alice", before.encodedHash(), rehashed, kit.clock.instant()));

    assertEquals(before.compromisedSince(), alice(kit).compromisedSince());
    assertEquals(before.secretChangedAt(), alice(kit).secretChangedAt());
    assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("alice", CredentialStatus.DISABLED, CredentialStatus.ACTIVE,
            "x"));
  }

  @Test
  @DisplayName("SA61-D2: the leaked password cannot replace itself - a change from COMPROMISED -> MUST_CHANGE is refused")
  void passwordChangeCannotReplaceACompromisedSecret() {
    CredentialTestKit kit = compromisedAlice();
    kit.lifecycle().transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE,
        "force-change");
    CredentialRecord before = alice(kit);
    long activations = statusEvents(kit, CredentialStatus.ACTIVE);
    PasswordChangeService change = changeService(kit, kit.credentials);

    PasswordChangeResult withLeak = change.change(new PasswordChangeCommand("alice",
        SecretValue.ofString(LEAKED), SecretValue.ofString(FRESH)));
    PasswordChangeResult withGuess = change.change(new PasswordChangeCommand("alice",
        SecretValue.ofString("a wrong guess 3"), SecretValue.ofString(FRESH)));

    assertSame(PasswordChangeResult.ResetRequired.INSTANCE, withLeak);
    assertSame(PasswordChangeResult.ResetRequired.INSTANCE, withGuess,
        "checked before the verification: the answer says nothing about the password");
    assertEquals(before, alice(kit), "the store is untouched");
    assertTrue(kit.passwordIs("alice", LEAKED));
    assertEquals(CredentialStatus.MUST_CHANGE, kit.status("alice"));
    assertEquals(activations, statusEvents(kit, CredentialStatus.ACTIVE));
  }

  @Test
  @DisplayName("SA61-D2: a change while the reset out of COMPROMISED is pending is refused as well")
  void passwordChangeIsRefusedWhileTheResetIsPending() {
    CredentialTestKit kit = compromisedAlice();
    PasswordResetService reset = resetService(kit, kit.credentials);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", TTL)).token().encode();
    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));

    assertSame(PasswordChangeResult.ResetRequired.INSTANCE,
        changeService(kit, kit.credentials).change(new PasswordChangeCommand("alice",
            SecretValue.ofString(LEAKED), SecretValue.ofString(FRESH))));
    assertTrue(kit.passwordIs("alice", LEAKED));

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString(FRESH)), "the link still works");
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
  }

  @Test
  @DisplayName("allowed: a consumed reset leads COMPROMISED -> MUST_CHANGE back to ACTIVE")
  void resetIsTheWayOutOfMustChange() {
    CredentialTestKit kit = compromisedAlice();
    kit.lifecycle().transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE,
        "force-change");
    PasswordResetService reset = resetService(kit, kit.credentials);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", TTL)).token().encode();
    assertEquals(CredentialStatus.MUST_CHANGE, kit.status("alice"), "the request moves nothing");
    kit.clock.advance(Duration.ofSeconds(5));

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString(FRESH)));

    CredentialRecord after = alice(kit);
    assertEquals(CredentialStatus.ACTIVE, after.status());
    assertEquals(kit.clock.instant(), after.secretChangedAt());
    assertNull(after.compromisedSince());
    assertFalse(after.secretRotationRequired());
    assertTrue(kit.passwordIs("alice", FRESH));

    // the account is an ordinary one again: the next change and a disable/re-enable work
    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        changeService(kit, kit.credentials).change(new PasswordChangeCommand("alice",
            SecretValue.ofString(FRESH), SecretValue.ofString("yet another password 4"))));
    CredentialLifecycleService lifecycle = kit.lifecycle();
    lifecycle.transition("alice", CredentialStatus.ACTIVE, CredentialStatus.DISABLED, "x");
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        lifecycle.transition("alice", CredentialStatus.DISABLED, CredentialStatus.ACTIVE, "x"));
  }

  @Test
  @DisplayName("allowed: a consumed reset after DISABLED records the change and reaches ACTIVE")
  void resetIsTheRotation() {
    CredentialTestKit kit = compromisedAlice();
    CredentialLifecycleService lifecycle = kit.lifecycle();
    lifecycle.transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, "x");
    lifecycle.transition("alice", CredentialStatus.DISABLED, CredentialStatus.RESET_PENDING,
        "admin-starts-reset");
    PasswordResetService reset = resetService(kit, kit.credentials);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", TTL)).token().encode();
    kit.clock.advance(Duration.ofSeconds(5));

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString(FRESH)));

    CredentialRecord after = alice(kit);
    assertEquals(CredentialStatus.ACTIVE, after.status());
    assertEquals(kit.clock.instant(), after.secretChangedAt());
    assertFalse(after.secretRotationRequired());
    assertTrue(kit.passwordIs("alice", FRESH));
  }

  @Test
  @DisplayName("allowed: the reset straight out of COMPROMISED keeps working (JS-SEC-076)")
  void resetOutOfCompromisedStillWorks() {
    CredentialTestKit kit = compromisedAlice();
    PasswordResetService reset = resetService(kit, kit.credentials);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", TTL)).token().encode();
    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));
    assertTrue(alice(kit).secretRotationRequired());

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString(FRESH)));
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
  }

  @Test
  @DisplayName("a COMPROMISED record in the shape before 00.84.00 carries the mark into DISABLED")
  void legacyShapedRecordIsFailClosed() {
    CredentialTestKit kit = new CredentialTestKit();
    // six components, no rotation proof - what a store of an earlier release returns
    kit.credentials.register(new CredentialRecord("legacy",
        kit.hashing.hash(LEAKED.toCharArray()).encodedHash(), CredentialStatus.COMPROMISED, 7L,
        CredentialTestKit.T0, CredentialTestKit.T0));
    assertNull(kit.credentials.findByUsername("legacy").orElseThrow().secretChangedAt());
    CredentialLifecycleService lifecycle = kit.lifecycle();

    lifecycle.transition("legacy", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, "x");

    assertNotNull(kit.credentials.findByUsername("legacy").orElseThrow().compromisedSince());
    assertThrows(InvalidStatusTransitionException.class,
        () -> lifecycle.transition("legacy", CredentialStatus.DISABLED, CredentialStatus.ACTIVE,
            "x"));
  }

  @Test
  @DisplayName("a never-compromised credential is unaffected: DISABLED -> ACTIVE, MUST_CHANGE -> ACTIVE")
  void ordinaryCredentialIsUnaffected() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", LEAKED, CredentialStatus.DISABLED);
    kit.register("carol", LEAKED, CredentialStatus.MUST_CHANGE);
    CredentialLifecycleService lifecycle = kit.lifecycle();

    assertInstanceOf(CredentialUpdateResult.Updated.class,
        lifecycle.transition("bob", CredentialStatus.DISABLED, CredentialStatus.ACTIVE, "x"));
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        lifecycle.transition("carol", CredentialStatus.MUST_CHANGE, CredentialStatus.ACTIVE, "x"));
    assertSame(CredentialUpdateResult.Stale.INSTANCE,
        lifecycle.transition("bob", CredentialStatus.DISABLED, CredentialStatus.ACTIVE, "x"),
        "a wrong expected status stays Stale");
    assertSame(CredentialUpdateResult.NotFound.INSTANCE,
        lifecycle.transition("nobody", CredentialStatus.DISABLED, CredentialStatus.ACTIVE, "x"));
  }

  @Test
  @DisplayName("the whole record is the witness: a status that left and came back is Stale")
  void witnessIsTheWholeRecord() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", LEAKED, CredentialStatus.DISABLED);
    CredentialRecord judged = alice(kit);
    CredentialLifecycleService lifecycle = kit.lifecycle();
    // in between: disabled -> must-change -> compromised -> disabled
    lifecycle.transition("alice", CredentialStatus.DISABLED, CredentialStatus.MUST_CHANGE, "x");
    lifecycle.transition("alice", CredentialStatus.MUST_CHANGE, CredentialStatus.COMPROMISED, "x");
    lifecycle.transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, "x");

    assertSame(CredentialUpdateResult.Stale.INSTANCE, kit.credentials.updateStatusIfUnchanged(
        judged, CredentialStatus.ACTIVE, kit.clock.instant()));
    assertEquals(CredentialStatus.DISABLED, kit.status("alice"));
  }

  @Test
  @DisplayName("mass change: COMPROMISED sets the mark, a mass re-enable skips the compromised credential")
  void massChangeRespectsTheRotation() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", LEAKED, CredentialStatus.ACTIVE);
    kit.register("bob", "bobs password 1", CredentialStatus.LOCKED);
    MassCredentialStatusChange mass =
        new MassCredentialStatusChange(kit.credentials, kit.audit, kit.clock);
    EmergencyPolicyOverride override = new EmergencyPolicyOverride("INC-161",
        EmergencyPolicyOverride.Reason.MASS_ROTATION, kit.clock.instant(),
        kit.clock.instant().plus(Duration.ofHours(1)), "operator");

    assertEquals(1, mass.forceAllToStatus(List.of("alice"), CredentialStatus.COMPROMISED,
        override).changed());
    assertNotNull(alice(kit).compromisedSince());
    kit.lifecycle().transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.DISABLED,
        "x");

    MassCredentialStatusChange.Report report = mass.forceAllToStatus(
        List.of("alice", "bob"), CredentialStatus.ACTIVE, override);

    assertEquals(1, report.changed(), "bob was only locked");
    assertEquals(1, report.rotationRequired());
    assertEquals(2, report.total());
    assertEquals(CredentialStatus.DISABLED, kit.status("alice"));
    assertEquals(CredentialStatus.ACTIVE, kit.status("bob"));
  }

  // ── a store that does not keep the rotation proof ───────────────────

  /**
   * A store as it was written before 00.84.00: rows of six columns, the SPI
   * defaults for everything new. Real logic, no recording.
   */
  private static final class SixColumnStore implements CredentialStore {
    private final Map<String, CredentialRecord> rows = new ConcurrentHashMap<>();

    void put(CredentialRecord record) {
      rows.put(record.username(), sixColumns(record));
    }

    private static CredentialRecord sixColumns(CredentialRecord record) {
      return new CredentialRecord(record.username(), record.encodedHash(), record.status(),
          record.version(), record.createdAt(), record.updatedAt());
    }

    @Override
    public Optional<CredentialRecord> findByUsername(String username) {
      return Optional.ofNullable(rows.get(username));
    }

    @Override
    public synchronized CredentialUpdateResult updateHashIfCurrent(
        String username, String expected, String next, Instant when) {
      CredentialRecord current = rows.get(username);
      if (current == null) {
        return CredentialUpdateResult.NotFound.INSTANCE;
      }
      if (!current.encodedHash().equals(expected)) {
        return CredentialUpdateResult.Stale.INSTANCE;
      }
      CredentialRecord updated = sixColumns(current.withHash(next, when));
      rows.put(username, updated);
      return new CredentialUpdateResult.Updated(updated);
    }

    @Override
    public synchronized CredentialUpdateResult updateStatusIfCurrent(
        String username, CredentialStatus expected, CredentialStatus next, Instant when) {
      CredentialRecord current = rows.get(username);
      if (current == null) {
        return CredentialUpdateResult.NotFound.INSTANCE;
      }
      if (current.status() != expected) {
        return CredentialUpdateResult.Stale.INSTANCE;
      }
      CredentialRecord updated = sixColumns(current.withStatus(next, when));
      rows.put(username, updated);
      return new CredentialUpdateResult.Updated(updated);
    }
  }

  @Test
  @DisplayName("a store without the proof: COMPROMISED leaves only through the reset")
  void storeWithoutProofKeepsTheResetAsTheOnlyWayOut() {
    CredentialTestKit kit = new CredentialTestKit();
    SixColumnStore store = new SixColumnStore();
    store.put(CredentialRecord.initial("alice",
        kit.hashing.hash(LEAKED.toCharArray()).encodedHash(), CredentialStatus.COMPROMISED,
        CredentialTestKit.T0));
    CredentialLifecycleService lifecycle = kit.lifecycle(store);
    assertFalse(store.recordsSecretRotation());

    for (CredentialStatus target : List.of(CredentialStatus.DISABLED,
        CredentialStatus.MUST_CHANGE)) {
      InvalidStatusTransitionException refused = assertThrows(
          InvalidStatusTransitionException.class,
          () -> lifecycle.transition("alice", CredentialStatus.COMPROMISED, target, "x"));
      assertEquals(InvalidStatusTransitionException.Reason.ROTATION_NOT_RECORDED,
          refused.reason());
    }
    assertEquals(CredentialStatus.COMPROMISED,
        store.findByUsername("alice").orElseThrow().status());

    PasswordResetService reset = resetService(kit, store);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", TTL)).token().encode();
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString(FRESH)));
    assertEquals(CredentialStatus.ACTIVE, store.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("a store that keeps the mark but not the change: the reset succeeds, the credential stays MUST_CHANGE")
  void storeThatCannotRecordTheChangeFailsClosed() {
    CredentialTestKit kit = compromisedAlice();
    kit.lifecycle().transition("alice", CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE,
        "force-change");
    // the real store behind a wrapper that knows only the four methods before 00.84.00
    CredentialStore partial = new CredentialStore() {
      @Override
      public Optional<CredentialRecord> findByUsername(String username) {
        return kit.credentials.findByUsername(username);
      }

      @Override
      public CredentialUpdateResult updateHashIfCurrent(
          String username, String expected, String next, Instant when) {
        return kit.credentials.updateHashIfCurrent(username, expected, next, when);
      }

      @Override
      public CredentialUpdateResult updateStatusIfCurrent(
          String username, CredentialStatus expected, CredentialStatus next, Instant when) {
        return kit.credentials.updateStatusIfCurrent(username, expected, next, when);
      }
    };
    assertSame(PasswordChangeResult.ResetRequired.INSTANCE,
        changeService(kit, partial).change(new PasswordChangeCommand(
            "alice", SecretValue.ofString(LEAKED), SecretValue.ofString(FRESH))));
    PasswordResetService reset = resetService(kit, partial);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", TTL)).token().encode();

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString(FRESH)), "no exception reaches the user");

    assertTrue(kit.passwordIs("alice", FRESH));
    assertEquals(CredentialStatus.MUST_CHANGE, kit.status("alice"),
        "without a recorded rotation the credential does not become ACTIVE");
  }
}
