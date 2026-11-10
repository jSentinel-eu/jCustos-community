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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-121 (CWE-799, CWE-307): the per-username counter of
 * {@code RESET_REQUEST} counts accepted requests and is not cleared by them.
 */
@DisplayName("JS-SEC-121 — reset requests are counted per username whatever their outcome")
class ResetRequestVolumeCounterTest {

  private static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");

  private static InMemoryAbuseDetectionService service() {
    return new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new CredentialTestKit.RecordingAudit());
  }

  private static AbuseAttemptContext attempt(
      AbuseAttemptType type, String username, String address, Instant at) {
    return new AbuseAttemptContext(type, Optional.of(username), Optional.ofNullable(address),
        TenantId.DEFAULT, at);
  }

  @Test
  @DisplayName("accepted requests within the hour: delayed from the fourth, blocked from the seventh")
  void acceptedRequestsReachTheDocumentedLimit() {
    InMemoryAbuseDetectionService service = service();
    for (int i = 0; i < 6; i++) {
      // every request from another address, so only the USERNAME dimension can react
      AbuseAttemptContext request = attempt(AbuseAttemptType.RESET_REQUEST, "alice",
          "2001:db8::" + (i + 1), T0.plusSeconds(i));
      AbuseDecision decision = service.evaluate(request);
      if (i < 3) {
        assertSame(AbuseDecision.Allow.INSTANCE, decision, "request " + (i + 1));
      } else {
        AbuseDecision.Delay delay = assertInstanceOf(AbuseDecision.Delay.class, decision,
            "request " + (i + 1) + " must be delayed");
        assertEquals(AbuseDimension.USERNAME, delay.dimension());
      }
      service.recordOutcome(request, AttemptOutcome.SUCCESS); // the link was issued
    }

    AbuseDecision seventh = service.evaluate(
        attempt(AbuseAttemptType.RESET_REQUEST, "alice", "2001:db8::7", T0.plusSeconds(6)));
    AbuseDecision.Block block = assertInstanceOf(AbuseDecision.Block.class, seventh);
    assertEquals(AbuseDimension.USERNAME, block.dimension());
  }

  @Test
  @DisplayName("200 accepted requests in 200 seconds from changing addresses are throttled from the fourth on")
  void floodFromManyAddressesIsThrottled() {
    InMemoryAbuseDetectionService service = service();
    int notAllowed = 0;
    for (int i = 0; i < 200; i++) {
      AbuseAttemptContext request = attempt(AbuseAttemptType.RESET_REQUEST, "alice",
          "2001:db8::" + Integer.toHexString(i + 1), T0.plusSeconds(i));
      if (!(service.evaluate(request) instanceof AbuseDecision.Allow)) {
        notAllowed++;
      }
      service.recordOutcome(request, AttemptOutcome.SUCCESS);
    }
    assertEquals(197, notAllowed);
  }

  @Test
  @DisplayName("the window slides: after an hour the account may ask again")
  void windowExpires() {
    InMemoryAbuseDetectionService service = service();
    for (int i = 0; i < 6; i++) {
      service.recordOutcome(attempt(AbuseAttemptType.RESET_REQUEST, "alice", null,
          T0.plusSeconds(i)), AttemptOutcome.SUCCESS);
    }
    assertInstanceOf(AbuseDecision.Block.class, service.evaluate(
        attempt(AbuseAttemptType.RESET_REQUEST, "alice", null, T0.plusSeconds(60))));
    assertSame(AbuseDecision.Allow.INSTANCE, service.evaluate(
        attempt(AbuseAttemptType.RESET_REQUEST, "alice", null, T0.plusSeconds(3600 + 6))));
  }

  @Test
  @DisplayName("LOGIN keeps its failure counter: a success clears it, successes are not counted")
  void loginStillResetsOnSuccess() {
    InMemoryAbuseDetectionService service = service();
    for (int i = 0; i < 4; i++) {
      service.recordOutcome(attempt(AbuseAttemptType.LOGIN, "alice", null, T0.plusSeconds(i)),
          AttemptOutcome.FAILURE);
    }
    service.recordOutcome(attempt(AbuseAttemptType.LOGIN, "alice", null, T0.plusSeconds(5)),
        AttemptOutcome.SUCCESS);
    for (int i = 0; i < 50; i++) {
      service.recordOutcome(attempt(AbuseAttemptType.LOGIN, "alice", null, T0.plusSeconds(6 + i)),
          AttemptOutcome.SUCCESS);
    }
    assertSame(AbuseDecision.Allow.INSTANCE, service.evaluate(
        attempt(AbuseAttemptType.LOGIN, "alice", null, T0.plusSeconds(60))));
  }

  @Test
  @DisplayName("the counting rule per (attempt type, dimension)")
  void countingRule() {
    for (AbuseDimension dimension : AbuseDimension.values()) {
      assertTrue(InMemoryAbuseDetectionService.countsEveryAttempt(
          AbuseAttemptType.RESET_REQUEST, dimension), "RESET_REQUEST/" + dimension);
    }
    assertFalse(InMemoryAbuseDetectionService.countsEveryAttempt(
        AbuseAttemptType.LOGIN, AbuseDimension.USERNAME));
    assertFalse(InMemoryAbuseDetectionService.countsEveryAttempt(
        AbuseAttemptType.PASSWORD_CHANGE, AbuseDimension.USERNAME));
    assertFalse(InMemoryAbuseDetectionService.countsEveryAttempt(
        AbuseAttemptType.RESET_CONSUME, AbuseDimension.USERNAME));
    assertTrue(InMemoryAbuseDetectionService.countsEveryAttempt(
        AbuseAttemptType.LOGIN, AbuseDimension.CLIENT_ADDRESS));
  }
}
