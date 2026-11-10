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
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-105: a validly signed first envelope with an arbitrary sequence must
 * not become the baseline of its scope, and {@code verify()} must stay total
 * whatever the stored sequence is. Real pipelines and in-memory stores; the
 * poisoned envelopes are signed with the real key. No mocks.
 */
@DisplayName("ConsumePipeline — first sequence and overflow (JS-SEC-105)")
class SequencePoisoningTest {

  private final BusFixtures fx = new BusFixtures();

  /** A genuinely signed envelope carrying the given sequence. */
  private SignedJCustosEventEnvelope signedWithSequence(long sequence) {
    SignedJCustosEventEnvelope template = fx.publishPipeline().toEnvelope(BusFixtures.event());
    return SignedEnvelopes.sign(
        BusFixtures.rebuild(template)
            .envelopeId(EventEnvelopeId.random())
            .sequence(EventSequence.of(sequence)),
        fx.keyManagement);
  }

  @Test
  @DisplayName("a first envelope with Long.MAX_VALUE is a SequenceViolation and leaves the store empty")
  void poisonedFirstSequenceIsRejected() {
    SignedJCustosEventEnvelope poison = signedWithSequence(Long.MAX_VALUE);

    JCustosEventVerificationResult result = fx.consumePipeline().verify(poison, BusFixtures.T0);

    JCustosEventVerificationResult.SequenceViolation violation = assertInstanceOf(
        JCustosEventVerificationResult.SequenceViolation.class, result);
    assertEquals(EventSequence.FIRST, violation.expected());
    assertEquals(Long.MAX_VALUE, violation.actual().value());
    assertTrue(fx.consumeSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).isEmpty(),
        "the poisoned sequence must not become the baseline");
    assertFalse(fx.consumeReplay.hasSeen(poison.envelopeId()));

    // the scope is still usable: the producer's real first envelope is accepted
    assertTrue(fx.consumePipeline().verify(signedWithSequence(1L), BusFixtures.T0).isValid());
  }

  @Test
  @DisplayName("with a stored Long.MAX_VALUE verify returns a result instead of throwing")
  void storedMaxValueKeepsVerifyTotal() {
    fx.consumeSequence.updateSequence(TenantId.DEFAULT, BusFixtures.PRODUCER,
        EventSequence.of(Long.MAX_VALUE));
    SignedJCustosEventEnvelope legit = signedWithSequence(1L);
    ConsumePipeline consumer = fx.consumePipeline();

    JCustosEventVerificationResult result =
        assertDoesNotThrow(() -> consumer.verify(legit, BusFixtures.T0));

    JCustosEventVerificationResult.SequenceViolation violation = assertInstanceOf(
        JCustosEventVerificationResult.SequenceViolation.class, result);
    assertEquals(Long.MAX_VALUE, violation.expected().value(),
        "a stored Long.MAX_VALUE has no successor — it is reported as the expectation itself");
    assertEquals(1L, violation.actual().value());
  }

  @Test
  @DisplayName("an administrative reset makes a poisoned scope usable again")
  void resetHealsAPoisonedScope() {
    fx.consumeSequence.updateSequence(TenantId.DEFAULT, BusFixtures.PRODUCER,
        EventSequence.of(Long.MAX_VALUE));
    ConsumePipeline consumer = fx.consumePipeline();
    assertFalse(consumer.verify(signedWithSequence(1L), BusFixtures.T0).isValid());

    fx.consumeSequence.resetSequence(TenantId.DEFAULT, BusFixtures.PRODUCER);

    assertTrue(consumer.verify(signedWithSequence(1L), BusFixtures.T0).isValid());
    assertTrue(consumer.verify(signedWithSequence(2L), BusFixtures.T0).isValid());
  }
}
