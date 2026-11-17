package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.KeyId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static eu.jsentinel.jcustos.events.bus.ConsumeFailureAction.REJECT;
import static eu.jsentinel.jcustos.events.bus.ConsumeFailureAction.REJECT_AND_DEAD_LETTER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ConsumeFailurePolicy — reject vs dead-letter per failure kind")
class ConsumeFailurePolicyTest {

  private static final List<JCustosEventVerificationResult> ALL_FAILURES = List.of(
      new JCustosEventVerificationResult.InvalidSignature("bad"),
      new JCustosEventVerificationResult.PayloadHashMismatch(EventEnvelopeId.of("e")),
      new JCustosEventVerificationResult.UnknownKey(KeyId.of("k")),
      new JCustosEventVerificationResult.KeyRevoked(KeyId.of("k")),
      new JCustosEventVerificationResult.KeyExpired(KeyId.of("k")),
      new JCustosEventVerificationResult.Expired(Instant.parse("2026-07-19T10:15:30Z")),
      new JCustosEventVerificationResult.AcceptanceWindowExceeded(EventEnvelopeId.of("e"),
          Instant.parse("2026-07-19T10:15:30Z"), Instant.parse("2126-07-19T10:15:30Z"),
          ConsumePipeline.DEFAULT_MAX_ACCEPTANCE_WINDOW),
      new JCustosEventVerificationResult.ReplayDetected(EventEnvelopeId.of("e")),
      new JCustosEventVerificationResult.SequenceViolation(TenantId.DEFAULT,
          EventProducerId.of("p"), EventSequence.of(2), EventSequence.of(5)),
      new JCustosEventVerificationResult.ProducerNotAllowed(EventProducerId.of("p"),
          EventType.of("LoginSucceeded"), TenantId.DEFAULT));

  @Test
  @DisplayName("strict() rejects every kind and dead-letters nothing")
  void strictProfile() {
    ConsumeFailurePolicy strict = ConsumeFailurePolicy.strict();
    for (JCustosEventVerificationResult failure : ALL_FAILURES) {
      assertEquals(REJECT, strict.actionFor(failure), failure.getClass().getSimpleName());
    }
    assertFalse(strict.deadLettersAnything());
  }

  @Test
  @DisplayName("operationalDefaults() dead-letters sequence violations and the two time-window failures only")
  void operationalProfile() {
    ConsumeFailurePolicy operational = ConsumeFailurePolicy.operationalDefaults();
    for (JCustosEventVerificationResult failure : ALL_FAILURES) {
      ConsumeFailureAction expected =
          failure instanceof JCustosEventVerificationResult.SequenceViolation
              || failure instanceof JCustosEventVerificationResult.Expired
              || failure instanceof JCustosEventVerificationResult.AcceptanceWindowExceeded
              ? REJECT_AND_DEAD_LETTER
              : REJECT;
      assertEquals(expected, operational.actionFor(failure),
          failure.getClass().getSimpleName());
    }
    assertTrue(operational.deadLettersAnything());
  }

  @Test
  @DisplayName("custom() starts fail-closed and applies per-kind overrides")
  void customBuilder() {
    ConsumeFailurePolicy custom = ConsumeFailurePolicy.custom()
        .with(ConsumeFailurePolicy.FailureKind.REPLAY_DETECTED, REJECT_AND_DEAD_LETTER)
        .build();
    assertEquals(REJECT_AND_DEAD_LETTER, custom.actionFor(
        new JCustosEventVerificationResult.ReplayDetected(EventEnvelopeId.of("e"))));
    assertEquals(REJECT, custom.actionFor(
        new JCustosEventVerificationResult.InvalidSignature("bad")));
  }

  @Test
  @DisplayName("Valid is not a failure")
  void validRejected() {
    ConsumeFailurePolicy policy = ConsumeFailurePolicy.strict();
    assertThrows(IllegalArgumentException.class, () -> policy.actionFor(
        new JCustosEventVerificationResult.Valid(
            ConsumeFailureFixtures.envelope())));
  }
}
