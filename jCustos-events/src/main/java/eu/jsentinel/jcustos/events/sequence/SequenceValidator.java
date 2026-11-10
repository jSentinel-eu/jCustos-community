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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventSequence;

import java.util.Objects;
import java.util.Optional;

/**
 * Pure validator that classifies an incoming sequence against the last accepted
 * one and maps the result to an outcome under a {@link
 * SequenceViolationStrategy} (Konzept §658-§674).
 *
 * <p>Two limits are configurable (JS-SEC-105, JS-SEC-108); the no-argument
 * constructor uses the strict defaults:
 * <ul>
 *   <li>{@code maxInitialSequence} — the highest sequence a <em>fresh</em>
 *       scope accepts as its baseline. Default
 *       {@link #DEFAULT_MAX_INITIAL_SEQUENCE}: a producer starts at
 *       {@link EventSequence#FIRST}, so nothing above it is a credible first
 *       envelope. Before 00.84.00 any value was accepted, which let a single
 *       envelope with {@code Long.MAX_VALUE} make the scope unusable for
 *       good.</li>
 *   <li>{@code maxTolerableGap} — how many skipped sequences an established
 *       scope accepts. Default {@link #DEFAULT_MAX_TOLERABLE_GAP}: every gap
 *       is a violation. A positive value lets the stream continue after a
 *       loss; the envelope behind the gap is then accepted with the outcome
 *       {@link SequenceOutcome#ACCEPT_WITH_WARNING} whatever the strategy.</li>
 * </ul>
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class SequenceValidator {

  /**
   * Default for the highest sequence a fresh scope accepts: the value of
   * {@link EventSequence#FIRST}.
   *
   * @since 00.84.00
   */
  public static final long DEFAULT_MAX_INITIAL_SEQUENCE = EventSequence.FIRST.value();

  /**
   * Default for the number of skipped sequences an established scope
   * tolerates: none.
   *
   * @since 00.84.00
   */
  public static final long DEFAULT_MAX_TOLERABLE_GAP = 0L;

  private final long maxInitialSequence;
  private final long maxTolerableGap;

  /** Creates a validator with the strict defaults. */
  public SequenceValidator() {
    this(DEFAULT_MAX_INITIAL_SEQUENCE, DEFAULT_MAX_TOLERABLE_GAP);
  }

  /**
   * @param maxInitialSequence the highest sequence a fresh scope accepts as
   *     its baseline; at least {@code 0}. Raise it only for a consumer that
   *     joins a running producer without a persisted sequence state, and keep
   *     it as low as that producer's counter allows
   * @param maxTolerableGap the number of skipped sequences an established
   *     scope accepts; at least {@code 0}
   * @since 00.84.00
   */
  public SequenceValidator(long maxInitialSequence, long maxTolerableGap) {
    if (maxInitialSequence < 0) {
      throw new IllegalArgumentException(
          "maxInitialSequence must be >= 0, was " + maxInitialSequence);
    }
    if (maxTolerableGap < 0) {
      throw new IllegalArgumentException(
          "maxTolerableGap must be >= 0, was " + maxTolerableGap);
    }
    this.maxInitialSequence = maxInitialSequence;
    this.maxTolerableGap = maxTolerableGap;
  }

  /**
   * @return the highest sequence a fresh scope accepts as its baseline
   * @since 00.84.00
   */
  public long maxInitialSequence() {
    return maxInitialSequence;
  }

  /**
   * @return the number of skipped sequences an established scope accepts
   * @since 00.84.00
   */
  public long maxTolerableGap() {
    return maxTolerableGap;
  }

  /**
   * Classifies an incoming sequence. An empty {@code last} (fresh scope)
   * accepts the incoming sequence as the baseline only up to
   * {@link #maxInitialSequence()}; anything above it is a
   * {@link SequenceState#GAP} — the beginning of the stream is missing.
   *
   * <p>The comparison works on the difference of the two non-negative values
   * and therefore cannot overflow, whatever the stored state is.
   *
   * @param last the last accepted sequence, if any
   * @param incoming the sequence being validated
   * @return the classification
   */
  public SequenceState classify(Optional<EventSequence> last, EventSequence incoming) {
    Objects.requireNonNull(last, "last");
    Objects.requireNonNull(incoming, "incoming");
    if (last.isEmpty()) {
      return incoming.value() <= maxInitialSequence
          ? SequenceState.IN_ORDER
          : SequenceState.GAP;
    }
    // Both values are >= 0, so the difference is exact; previous + 1 would
    // overflow for a stored Long.MAX_VALUE (JS-SEC-105).
    long distance = incoming.value() - last.get().value();
    if (distance == 1) {
      return SequenceState.IN_ORDER;
    }
    if (distance > 1) {
      return SequenceState.GAP;
    }
    if (distance == 0) {
      return SequenceState.DUPLICATE;
    }
    return SequenceState.ROLLBACK;
  }

  /**
   * Classifies and maps to an outcome under the given strategy. A gap in an
   * established scope that skips at most {@link #maxTolerableGap()} sequences
   * is accepted with {@link SequenceOutcome#ACCEPT_WITH_WARNING} under every
   * strategy; a fresh scope never benefits from the tolerance.
   *
   * @param last the last accepted sequence, if any
   * @param incoming the sequence being validated
   * @param strategy how to treat a violation
   * @return the decision
   */
  public SequenceDecision decide(Optional<EventSequence> last, EventSequence incoming,
      SequenceViolationStrategy strategy) {
    Objects.requireNonNull(strategy, "strategy");
    SequenceState state = classify(last, incoming);
    if (state == SequenceState.IN_ORDER) {
      return new SequenceDecision(state, SequenceOutcome.ACCEPT);
    }
    if (state == SequenceState.GAP && last.isPresent()
        && incoming.value() - last.get().value() - 1 <= maxTolerableGap) {
      return new SequenceDecision(state, SequenceOutcome.ACCEPT_WITH_WARNING);
    }
    SequenceOutcome outcome = switch (strategy) {
      case REJECT -> SequenceOutcome.REJECT;
      case DEAD_LETTER -> SequenceOutcome.DEAD_LETTER;
      case ACCEPT_WITH_WARNING -> SequenceOutcome.ACCEPT_WITH_WARNING;
    };
    return new SequenceDecision(state, outcome);
  }
}
