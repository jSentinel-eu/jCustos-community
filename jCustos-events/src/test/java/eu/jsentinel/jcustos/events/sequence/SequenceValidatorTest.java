package eu.jsentinel.jcustos.events.sequence;

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

import eu.jsentinel.jcustos.events.api.EventSequence;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SequenceValidator")
class SequenceValidatorTest {

  private final SequenceValidator validator = new SequenceValidator();

  @Test
  @DisplayName("a fresh scope accepts the first sequence as baseline")
  void freshScopeInOrder() {
    SequenceDecision d = validator.decide(Optional.empty(), EventSequence.FIRST,
        SequenceViolationStrategy.REJECT);
    assertEquals(SequenceState.IN_ORDER, d.state());
    assertEquals(SequenceOutcome.ACCEPT, d.outcome());
    assertTrue(d.accepted());
  }

  @Test
  @DisplayName("JS-SEC-105: a fresh scope rejects a baseline above the first sequence")
  void freshScopeRejectsAnArbitraryBaseline() {
    for (long poisoned : new long[]{2L, 7L, Long.MAX_VALUE}) {
      SequenceDecision d = validator.decide(Optional.empty(), EventSequence.of(poisoned),
          SequenceViolationStrategy.REJECT);
      assertEquals(SequenceState.GAP, d.state(), "sequence " + poisoned);
      assertEquals(SequenceOutcome.REJECT, d.outcome(), "sequence " + poisoned);
      assertFalse(d.accepted(), "sequence " + poisoned);
    }
  }

  @Test
  @DisplayName("JS-SEC-105: the accepted baseline of a fresh scope is configurable")
  void freshScopeBaselineIsConfigurable() {
    SequenceValidator joining = new SequenceValidator(5_000L,
        SequenceValidator.DEFAULT_MAX_TOLERABLE_GAP);
    assertEquals(5_000L, joining.maxInitialSequence());
    assertTrue(joining.decide(Optional.empty(), EventSequence.of(5_000L),
        SequenceViolationStrategy.REJECT).accepted());
    assertFalse(joining.decide(Optional.empty(), EventSequence.of(5_001L),
        SequenceViolationStrategy.REJECT).accepted());
    assertThrows(IllegalArgumentException.class, () -> new SequenceValidator(-1L, 0L));
    assertThrows(IllegalArgumentException.class, () -> new SequenceValidator(1L, -1L));
  }

  @Test
  @DisplayName("JS-SEC-105: classification does not overflow at Long.MAX_VALUE")
  void classificationIsOverflowFree() {
    Optional<EventSequence> poisoned = Optional.of(EventSequence.of(Long.MAX_VALUE));
    // previous + 1 wrapped to Long.MIN_VALUE, so every lower sequence was a GAP.
    assertEquals(SequenceState.ROLLBACK, validator.classify(poisoned, EventSequence.FIRST));
    assertEquals(SequenceState.ROLLBACK,
        validator.classify(poisoned, EventSequence.of(Long.MAX_VALUE - 1)));
    assertEquals(SequenceState.DUPLICATE,
        validator.classify(poisoned, EventSequence.of(Long.MAX_VALUE)));
    assertEquals(SequenceState.IN_ORDER,
        validator.classify(Optional.of(EventSequence.of(Long.MAX_VALUE - 1)),
            EventSequence.of(Long.MAX_VALUE)));
    assertEquals(SequenceState.GAP,
        validator.classify(Optional.of(EventSequence.of(0)), EventSequence.of(Long.MAX_VALUE)));
  }

  @Test
  @DisplayName("JS-SEC-108: a gap within the tolerance is accepted with a warning, a wider one is not")
  void gapToleranceIsBounded() {
    SequenceValidator tolerant = new SequenceValidator(
        SequenceValidator.DEFAULT_MAX_INITIAL_SEQUENCE, 2L);
    Optional<EventSequence> last = Optional.of(EventSequence.of(5));

    SequenceDecision skippedTwo = tolerant.decide(last, EventSequence.of(8),
        SequenceViolationStrategy.REJECT);
    assertEquals(SequenceState.GAP, skippedTwo.state());
    assertEquals(SequenceOutcome.ACCEPT_WITH_WARNING, skippedTwo.outcome());

    SequenceDecision skippedThree = tolerant.decide(last, EventSequence.of(9),
        SequenceViolationStrategy.REJECT);
    assertEquals(SequenceOutcome.REJECT, skippedThree.outcome());

    // The tolerance heals gaps only: repeats and roll-backs stay violations,
    // and a fresh scope does not get a head start from it.
    assertFalse(tolerant.decide(last, EventSequence.of(5),
        SequenceViolationStrategy.REJECT).accepted());
    assertFalse(tolerant.decide(last, EventSequence.of(4),
        SequenceViolationStrategy.REJECT).accepted());
    assertFalse(tolerant.decide(Optional.empty(), EventSequence.of(3),
        SequenceViolationStrategy.REJECT).accepted());
  }

  @Test
  @DisplayName("JS-SEC-108: without a configured tolerance every gap stays a violation")
  void defaultToleratesNoGap() {
    assertEquals(0L, validator.maxTolerableGap());
    assertFalse(validator.decide(Optional.of(EventSequence.of(5)), EventSequence.of(7),
        SequenceViolationStrategy.REJECT).accepted());
  }

  @Test
  @DisplayName("the next sequence is in order")
  void nextIsInOrder() {
    assertEquals(SequenceState.IN_ORDER,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(6)));
  }

  @Test
  @DisplayName("a higher-than-expected sequence is a GAP")
  void gapDetected() {
    assertEquals(SequenceState.GAP,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(8)));
  }

  @Test
  @DisplayName("a repeated sequence is a DUPLICATE")
  void duplicateDetected() {
    assertEquals(SequenceState.DUPLICATE,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(5)));
  }

  @Test
  @DisplayName("a lower sequence is a ROLLBACK")
  void rollbackDetected() {
    assertEquals(SequenceState.ROLLBACK,
        validator.classify(Optional.of(EventSequence.of(5)), EventSequence.of(3)));
  }

  @Test
  @DisplayName("each strategy maps a violation to its outcome")
  void strategyOutcomes() {
    Optional<EventSequence> last = Optional.of(EventSequence.of(5));
    EventSequence gap = EventSequence.of(8);

    SequenceDecision reject = validator.decide(last, gap, SequenceViolationStrategy.REJECT);
    assertEquals(SequenceOutcome.REJECT, reject.outcome());
    assertFalse(reject.accepted());

    SequenceDecision dead = validator.decide(last, gap, SequenceViolationStrategy.DEAD_LETTER);
    assertEquals(SequenceOutcome.DEAD_LETTER, dead.outcome());
    assertFalse(dead.accepted());

    SequenceDecision warn = validator.decide(last, gap,
        SequenceViolationStrategy.ACCEPT_WITH_WARNING);
    assertEquals(SequenceOutcome.ACCEPT_WITH_WARNING, warn.outcome());
    assertTrue(warn.accepted());
  }
}
