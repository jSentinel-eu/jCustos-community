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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.audit.CredentialStatusChanged;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.abuse.AbuseLimitsPolicy;
import eu.jsentinel.jcustos.credential.abuse.InMemoryAbuseDetectionService;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleDecision;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-121 (CWE-645, CWE-640, CWE-799): an unauthenticated reset request
 * must not lock the owner out of the password login, and a throttled request
 * must not retire the link the owner holds.
 */
@DisplayName("JS-SEC-121 — a reset request does not lock the account")
class ResetRequestLockoutTest {

  private static final Duration TTL = Duration.ofMinutes(15);

  private static PasswordResetService service(CredentialTestKit kit) {
    return service(kit, kit.credentials, kit.lifecycle());
  }

  private static PasswordResetService service(
      CredentialTestKit kit, CredentialStore store, CredentialLifecycleService lifecycle) {
    return new PasswordResetService(store, kit.resetTokens, kit.digests, kit.hashing,
        kit.validator, kit.inputPolicy, lifecycle, kit.clock, kit.audit);
  }

  private static String wire(ResetTokenCreationResult result) {
    return assertInstanceOf(ResetTokenCreationResult.Created.class, result).token().encode();
  }

  private static SecretValue secret(String value) {
    return SecretValue.ofString(value);
  }

  @Test
  @DisplayName("after issue the credential stays ACTIVE, the lifecycle decision stays Proceed and the password still verifies")
  void issueLeavesActiveCredentialUsable() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit);

    wire(reset.issue("alice", TTL));
    reset.issue("alice", TTL); // the attacker asks again, knowing only the username

    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
    assertSame(CredentialLifecycleDecision.Proceed.INSTANCE,
        kit.lifecycle().decide(kit.status("alice")),
        "the password login must stay open while a reset link is outstanding");
    assertTrue(kit.passwordIs("alice", "correct horse battery"));
    assertTrue(kit.audit.events.stream().noneMatch(CredentialStatusChanged.class::isInstance),
        "a reset request must not write a status transition for a usable credential");
  }

  @Test
  @DisplayName("thirty days later, with every link expired, the account is still usable")
  void expiredLinksLeaveNoTrace() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit);
    String link = wire(reset.issue("alice", TTL));

    kit.clock.advance(Duration.ofDays(30));
    assertInstanceOf(PasswordResetConsumeResult.Failed.class,
        reset.consume(link, secret("too late password")));

    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
    assertSame(CredentialLifecycleDecision.Proceed.INSTANCE,
        kit.lifecycle().decide(kit.status("alice")));
  }

  @ParameterizedTest(name = "{0} is not moved by a reset request")
  @EnumSource(value = CredentialStatus.class,
      names = {"ACTIVE", "MUST_CHANGE", "LOCKED", "REHASH_REQUIRED", "DEPRECATED_ALGORITHM"})
  @DisplayName("no usable status is changed by issue")
  void issueKeepsEveryUsableStatus(CredentialStatus status) {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", status);

    wire(service(kit).issue("alice", TTL));

    assertEquals(status, kit.status("alice"));
  }

  @Test
  @DisplayName("the reset runs alongside the login: consume replaces the password and the status stays ACTIVE")
  void consumeReplacesPasswordOfActiveCredential() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit);
    String link = wire(reset.issue("alice", TTL));

    kit.clock.advance(Duration.ofSeconds(1));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, secret("a brand new password")));

    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
    assertTrue(kit.passwordIs("alice", "a brand new password"));
    assertFalse(kit.passwordIs("alice", "correct horse battery"));
  }

  @Test
  @DisplayName("JS-SEC-076 is kept: a COMPROMISED credential stays blocked from issue until consume")
  void compromisedStaysBlockedUntilConsume() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "leaked password 1", CredentialStatus.COMPROMISED);
    PasswordResetService reset = service(kit);
    CredentialLifecycleService lifecycle = kit.lifecycle();

    String link = wire(reset.issue("alice", TTL));

    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));
    assertSame(CredentialLifecycleDecision.ResetInProgress.INSTANCE,
        lifecycle.decide(kit.status("alice")),
        "the compromised password must not open the login while the reset is pending");

    kit.clock.advance(Duration.ofSeconds(1));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, secret("a brand new password")));
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
    assertTrue(kit.resetTokens.statusBeforeReset("alice").isEmpty(),
        "a consumed reset leaves no status to return to");
  }

  @Test
  @DisplayName("a COMPROMISED credential returns to COMPROMISED when its last open link lapses")
  void lapsedResetReturnsToCompromised() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "leaked password 1", CredentialStatus.COMPROMISED);
    PasswordResetService reset = service(kit);
    wire(reset.issue("alice", TTL));

    assertEquals(Optional.of(CredentialStatus.RESET_PENDING), reset.releaseLapsedReset("alice"),
        "an open link keeps the reset pending");

    kit.clock.advance(TTL);
    assertEquals(Optional.of(CredentialStatus.COMPROMISED), reset.releaseLapsedReset("alice"));
    assertSame(CredentialLifecycleDecision.BlockedPermanent.INSTANCE,
        kit.lifecycle().decide(kit.status("alice")));
    assertTrue(kit.audit.events.stream()
            .filter(CredentialStatusChanged.class::isInstance)
            .map(CredentialStatusChanged.class::cast)
            .anyMatch(e -> e.fromStatus() == CredentialStatus.RESET_PENDING
                && e.toStatus() == CredentialStatus.COMPROMISED),
        "the way back is an audited lifecycle transition");

    // The way out of COMPROMISED is still a reset.
    String second = wire(reset.issue("alice", TTL));
    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(second, secret("a brand new password")));
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
  }

  @Test
  @DisplayName("presenting the lapsed link is enough to return the credential to COMPROMISED")
  void consumeOfLapsedLinkReleases() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "leaked password 1", CredentialStatus.COMPROMISED);
    PasswordResetService reset = service(kit);
    String link = wire(reset.issue("alice", TTL));

    kit.clock.advance(TTL.plusSeconds(1));
    assertInstanceOf(PasswordResetConsumeResult.Failed.class,
        reset.consume(link, secret("a brand new password")));

    assertEquals(CredentialStatus.COMPROMISED, kit.status("alice"));
  }

  @Test
  @DisplayName("RESET_PENDING without a recorded origin — set by an administrator or an older version — is left alone")
  void resetPendingOfUnknownOriginIsNotTouched() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.RESET_PENDING);
    PasswordResetService reset = service(kit);

    assertEquals(Optional.of(CredentialStatus.RESET_PENDING), reset.releaseLapsedReset("alice"));

    // ... and it leaves the state through a consumed reset, as before.
    String link = wire(reset.issue("alice", TTL));
    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, secret("a brand new password")));
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
  }

  @Test
  @DisplayName("a new link stored while the lapsed reset is being released is not stranded")
  void releaseRacingWithIssueKeepsTheNewLinkUsable() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "leaked password 1", CredentialStatus.COMPROMISED);
    AtomicReference<Runnable> beforeRelease = new AtomicReference<>();
    // Real store; the wrapper only lets a second request run at one chosen point:
    // after release decided "no open link", before it writes COMPROMISED.
    CredentialStore interleaving = new CredentialStore() {
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
        if (expected == CredentialStatus.RESET_PENDING && next == CredentialStatus.COMPROMISED) {
          Runnable hook = beforeRelease.getAndSet(null);
          if (hook != null) {
            hook.run();
          }
        }
        return kit.credentials.updateStatusIfCurrent(username, expected, next, when);
      }
    };
    PasswordResetService reset = service(kit, interleaving, kit.lifecycle(interleaving));
    wire(reset.issue("alice", TTL));
    kit.clock.advance(TTL);

    AtomicReference<String> fresh = new AtomicReference<>();
    beforeRelease.set(() -> fresh.set(wire(reset.issue("alice", TTL))));
    reset.releaseLapsedReset("alice");

    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"),
        "the link issued during the release must find the credential in RESET_PENDING");
    kit.clock.advance(Duration.ofSeconds(1));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(fresh.get(), secret("a brand new password")));
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
  }

  @Test
  @DisplayName("an accepted request still retires the older link (JS-SEC-074 is kept)")
  void acceptedRequestRetiresSibling() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit).withAbuseDetection(
        new InMemoryAbuseDetectionService(AbuseLimitsPolicy.defaults(), kit.audit));

    String first = wire(reset.issue("alice", TTL, "203.0.113.7"));
    kit.clock.advance(Duration.ofSeconds(1));
    String second = wire(reset.issue("alice", TTL, "203.0.113.7"));

    kit.clock.advance(Duration.ofSeconds(1));
    assertInstanceOf(PasswordResetConsumeResult.Failed.class,
        reset.consume(first, secret("a brand new password")));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(second, secret("a brand new password")));
  }

  @Test
  @DisplayName("a throttled request issues nothing and does not retire the link the owner holds")
  void throttledRequestDoesNotRetireTheOpenLink() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit).withAbuseDetection(
        new InMemoryAbuseDetectionService(AbuseLimitsPolicy.defaults(), kit.audit));

    // Default per-username limit for RESET_REQUEST: block from the 6th request per hour.
    String newest = null;
    for (int i = 0; i < 6; i++) {
      newest = wire(reset.issue("alice", TTL, "2001:db8::" + (i + 1)));
      kit.clock.advance(Duration.ofSeconds(1));
    }
    int stored = kit.resetTokens.size();

    for (int i = 0; i < 50; i++) {
      assertSame(ResetTokenCreationResult.Blocked.INSTANCE,
          reset.issue("alice", TTL, "2001:db8::ff" + i),
          "request " + (7 + i) + " within the hour must be refused");
      kit.clock.advance(Duration.ofSeconds(1));
    }

    assertEquals(stored, kit.resetTokens.size(), "a refused request must not mint a token");
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(newest, secret("a brand new password")),
        "the last delivered link must survive the flood");
    assertEquals(CredentialStatus.ACTIVE, kit.status("alice"));
  }

  @Test
  @DisplayName("the throttle answers alike for unknown usernames")
  void throttleDoesNotRevealWhetherTheUserExists() {
    CredentialTestKit kit = new CredentialTestKit();
    PasswordResetService reset = service(kit).withAbuseDetection(
        new InMemoryAbuseDetectionService(AbuseLimitsPolicy.defaults(), kit.audit));

    for (int i = 0; i < 6; i++) {
      assertSame(ResetTokenCreationResult.UnknownUser.INSTANCE,
          reset.issue("nobody", TTL, "2001:db8::" + (i + 1)));
      kit.clock.advance(Duration.ofSeconds(1));
    }
    assertSame(ResetTokenCreationResult.Blocked.INSTANCE,
        reset.issue("nobody", TTL, "2001:db8::99"));
  }
}
