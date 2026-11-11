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
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenCreationResult;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JS-SEC-123 (CWE-178): the per-username budgets of the abuse detection are
 * keyed on the canonical user name, so every spelling of a name draws on the
 * budget of the one account behind it.
 */
@DisplayName("JS-SEC-123 — abuse detection keeps one username budget per account, not per spelling")
class AbuseSubjectKeyTest {

  private static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");

  /** Spellings {@code InMemoryCredentialStore} resolves to the record "alice". */
  private static final List<String> SPELLINGS = List.of(
      "alice", "ALICE", "Alice", " alice ", "aLiCe", "ALICe", "ａlice", "alicE");

  private static InMemoryAbuseDetectionService service() {
    return new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new CredentialTestKit.RecordingAudit());
  }

  private static AbuseAttemptContext attempt(
      AbuseAttemptType type, String username, int sequence) {
    // every attempt from another address, so only the USERNAME dimension can react
    return new AbuseAttemptContext(type, Optional.of(username),
        Optional.of("2001:db8::" + Integer.toHexString(sequence + 1)),
        TenantId.DEFAULT, T0.plusSeconds(sequence));
  }

  @Test
  @DisplayName("reset requests under seven spellings of one name: delayed from the fourth, blocked at the seventh")
  void spellingsShareOneResetRequestBudget() {
    InMemoryAbuseDetectionService service = service();
    for (int i = 0; i < 6; i++) {
      AbuseAttemptContext request = attempt(AbuseAttemptType.RESET_REQUEST, SPELLINGS.get(i), i);
      AbuseDecision decision = service.evaluate(request);
      if (i < 3) {
        assertSame(AbuseDecision.Allow.INSTANCE, decision, "request " + (i + 1));
      } else {
        AbuseDecision.Delay delay = assertInstanceOf(AbuseDecision.Delay.class, decision,
            "request " + (i + 1) + " as '" + SPELLINGS.get(i) + "' must be delayed");
        assertEquals(AbuseDimension.USERNAME, delay.dimension());
      }
      service.recordOutcome(request, AttemptOutcome.SUCCESS);
    }

    AbuseDecision seventh = service.evaluate(
        attempt(AbuseAttemptType.RESET_REQUEST, SPELLINGS.get(6), 6));

    AbuseDecision.Block block = assertInstanceOf(AbuseDecision.Block.class, seventh,
        "the seventh request must be blocked whatever its spelling");
    assertEquals(AbuseDimension.USERNAME, block.dimension());
  }

  @Test
  @DisplayName("login failures under different spellings add up; a success under another spelling clears them")
  void spellingsShareOneLoginFailureCounter() {
    InMemoryAbuseDetectionService service = service();
    int blockAt = AbuseLimitsPolicy.defaults()
        .limit(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME).orElseThrow().blockAt();
    for (int i = 0; i < blockAt; i++) {
      service.recordOutcome(
          attempt(AbuseAttemptType.LOGIN, SPELLINGS.get(i % SPELLINGS.size()), i),
          AttemptOutcome.FAILURE);
    }
    assertInstanceOf(AbuseDecision.Block.class,
        service.evaluate(attempt(AbuseAttemptType.LOGIN, "alice", blockAt)),
        blockAt + " failures spread over the spellings of one name must block that name");

    service.recordOutcome(attempt(AbuseAttemptType.LOGIN, "ALICE", blockAt + 1),
        AttemptOutcome.SUCCESS);

    assertSame(AbuseDecision.Allow.INSTANCE,
        service.evaluate(attempt(AbuseAttemptType.LOGIN, "alice", blockAt + 2)));
  }

  @Test
  @DisplayName("with SubjectKeyCanonicalizer.exact() every spelling is an account of its own")
  void exactCanonicalizerKeepsSpellingsApart() {
    InMemoryAbuseDetectionService service = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new CredentialTestKit.RecordingAudit(),
        InMemoryAbuseDetectionService.DEFAULT_MAX_ENTRIES, SubjectKeyCanonicalizer.exact());
    for (int i = 0; i < 6; i++) {
      service.recordOutcome(attempt(AbuseAttemptType.RESET_REQUEST, "alice", i),
          AttemptOutcome.SUCCESS);
    }

    assertInstanceOf(AbuseDecision.Block.class,
        service.evaluate(attempt(AbuseAttemptType.RESET_REQUEST, "alice", 6)));
    assertSame(AbuseDecision.Allow.INSTANCE,
        service.evaluate(attempt(AbuseAttemptType.RESET_REQUEST, "ALICE", 7)));
  }

  @Test
  @DisplayName("the canonicaliser is mandatory")
  void canonicalizerMustNotBeNull() {
    assertThrows(NullPointerException.class, () -> new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new CredentialTestKit.RecordingAudit(), 10, null));
  }

  @Test
  @DisplayName("through the reset service: the seventh request for one account is refused although every request spells the name differently")
  void resetServiceThrottlesPerAccount() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = new PasswordResetService(kit.credentials, kit.resetTokens,
        kit.digests, kit.hashing, kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock,
        kit.audit)
        .withAbuseDetection(new InMemoryAbuseDetectionService(
            AbuseLimitsPolicy.defaults(), kit.audit));

    for (int i = 0; i < 6; i++) {
      assertInstanceOf(ResetTokenCreationResult.Created.class,
          reset.issue(SPELLINGS.get(i), Duration.ofMinutes(15), "2001:db8::" + (i + 1)),
          "request " + (i + 1) + " as '" + SPELLINGS.get(i) + "'");
      kit.clock.advance(Duration.ofSeconds(1));
    }

    assertSame(ResetTokenCreationResult.Blocked.INSTANCE,
        reset.issue(SPELLINGS.get(6), Duration.ofMinutes(15), "2001:db8::7"));
  }
}
