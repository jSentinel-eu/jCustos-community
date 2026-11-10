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

import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.store.InMemoryDeadLetterStore;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetter;
import eu.jsentinel.jcustos.events.store.RejectionReason;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * JS-SEC-109: one captured, validly signed but expired envelope is submitted
 * over and over — no key needed. Real consume pipeline, real failure handler
 * with the operational policy, real in-memory dead-letter store. No mocks.
 */
@DisplayName("Dead-letter store — replayed rejection (JS-SEC-109)")
class DeadLetterFloodTest {

  // 1 000 submissions, not the 10 000 of the analysis: the handler writes one
  // operator log line per rejected authenticated envelope, and the property
  // does not depend on the count. DeadLetterRecorderTest repeats 10 000 times.
  private static final int SUBMISSIONS = 1_000;

  @Test
  @DisplayName("the same expired envelope dead-lettered over and over leaves exactly one open record")
  void replayedExpiredEnvelopeIsStoredOnce() {
    BusFixtures fx = new BusFixtures();
    SignedJCustosEventEnvelope captured = fx.publishPipeline().toEnvelope(BusFixtures.event());
    Instant afterExpiry = BusFixtures.T0.plus(Duration.ofMinutes(6));
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    List<EventBusSelfObservabilityEvent> deadLettered = new ArrayList<>();
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.operationalDefaults(), store,
        event -> {
          if (event instanceof DeadLetteredEvent) {
            deadLettered.add(event);
          }
        },
        () -> afterExpiry);
    ConsumePipeline consumer = fx.consumePipeline();

    for (int i = 0; i < SUBMISSIONS; i++) {
      JCustosEventVerificationResult result = consumer.verify(captured, afterExpiry);
      assertInstanceOf(JCustosEventVerificationResult.Expired.class, result);
      assertEquals(ConsumeFailureAction.REJECT_AND_DEAD_LETTER,
          handler.handle(captured, result));
    }

    List<JCustosEventDeadLetter> open = store.findOpen(Integer.MAX_VALUE);
    assertEquals(1, open.size(), "one captured envelope must retain one record");
    assertEquals(RejectionReason.EXPIRED, open.get(0).reason());
    assertEquals(captured, open.get(0).envelope());
    assertEquals((long) SUBMISSIONS, store.occurrences(open.get(0).id()),
        "the repeats are counted on the record instead");
    assertEquals(1, deadLettered.size(), "and announced once");
  }
}
