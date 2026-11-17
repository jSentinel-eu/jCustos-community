/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.ratelimiting;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Persistent event store for sliding-window rate-limiting policies
 * (V00.70 Phase 7c).
 * <p>
 * The store is intentionally <em>event-based</em> rather than a
 * counter + window-start pair: a {@link RateLimitStore} records one
 * timestamp per event, and the policy decides how to interpret that
 * stream — a fixed window, a sliding window, a leaky bucket, or a
 * token bucket are all expressible on top of the same primitives.
 *
 * <p>Lifecycle:
 *
 * <ol>
 *   <li>{@link #recordEvent(RateLimitKey, Instant)} appends one
 *       timestamp.</li>
 *   <li>{@link #countSince(RateLimitKey, Instant)} returns how many
 *       events the key holds at or after the cutoff — the policy
 *       picks {@code cutoff = now - window}.</li>
 *   <li>{@link #reset(RateLimitKey)} drops everything under a key
 *       (typically called on a successful authentication that
 *       cancels the throttle).</li>
 *   <li>{@link #purgeOlderThan(Instant)} is the retention sweep —
 *       runs on a schedule, drops events the policy would no longer
 *       count anyway.</li>
 * </ol>
 *
 * <p>Since 00.84.00 a store can also keep a <em>block</em> per key
 * ({@link #block}, {@link #blockedUntil}) - the state of an opt-in
 * {@link RateLimitEscalation}. A block is no event: it is not counted, and
 * {@link #tryAdmit} does not look at it; the policy does. {@link #reset} lifts
 * it, {@link #purgeOlderThan} drops it once it has ended. The defaults of both
 * methods refuse with {@link UnsupportedOperationException}, so a store written
 * before 00.84.00 keeps compiling and {@link InMemoryRateLimitPolicy} refuses an
 * escalation over it at construction instead of losing every block.
 *
 * <p>Implementations must be thread-safe; concurrent recordEvent
 * and countSince happen on every protected endpoint. Events are a
 * multiset: two events recorded with the same instant count as two
 * (JS-SEC-118) — a clock with a coarse tick must not switch a limit off.
 */
@ExperimentalJCustosApi
public interface RateLimitStore {

  /**
   * Appends one event timestamp under {@code key}.
   *
   * @param key key the event belongs to; must not be {@code null}
   * @param at  event instant; must not be {@code null}
   */
  void recordEvent(RateLimitKey key, Instant at);

  /**
   * Returns the number of events under {@code key} whose timestamp
   * is at or after {@code since}.
   *
   * @param key   key to query; must not be {@code null}
   * @param since inclusive lower bound; events at exactly this
   *              instant count; must not be {@code null}
   * @return non-negative event count
   */
  int countSince(RateLimitKey key, Instant since);

  /**
   * Drops every recorded event under {@code key} and, in a store that keeps
   * blocks (since 00.84.00), the key's block.
   *
   * @param key key to clear; must not be {@code null}
   */
  void reset(RateLimitKey key);

  /**
   * Across every key, drops events whose timestamp is strictly
   * before {@code cutoff}. Intended as a retention sweep. A store that keeps
   * blocks (since 00.84.00) also drops every block that ended strictly before
   * {@code cutoff}; a key is forgotten once it holds neither.
   *
   * @param cutoff retention boundary; must not be {@code null}
   * @return number of events purged
   */
  int purgeOlderThan(Instant cutoff);

  /**
   * The most events this store keeps under one key. {@link #tryAdmit} refuses
   * once a key holds this many, whatever {@code limit} the caller asks for, so a
   * policy whose limit is larger would be capped silently -
   * {@link InMemoryRateLimitPolicy} refuses such a limit at construction
   * instead. The default declares no bound; a store that has one overrides it.
   *
   * @return the per-key bound, {@link Integer#MAX_VALUE} for none
   * @since 00.84.00
   */
  default int maxEventsPerKey() {
    return Integer.MAX_VALUE;
  }

  /**
   * Outcome of {@link #tryAdmit}: whether the event was recorded, how many
   * events the key holds in the window afterwards, and the oldest of them.
   *
   * <p>The oldest event in the window is the one whose departure frees the
   * next slot; {@link InMemoryRateLimitPolicy} derives
   * {@link RateLimitDecision.Throttled#retryAfter()} from it. A store that does
   * not report it - the {@linkplain #Admission(boolean, int) two-argument
   * constructor}, the default {@link #tryAdmit} - leaves it empty, and the
   * policy then answers with the whole window.</p>
   *
   * @param admitted       {@code true} when the event was recorded
   * @param eventsInWindow events at or after {@code since}, including this one when admitted
   * @param oldestInWindow the earliest event at or after {@code since} after the decision;
   *                       empty when the window holds none or the store does not report it;
   *                       never {@code null}
   * @since 00.84.00
   */
  record Admission(boolean admitted, int eventsInWindow, Optional<Instant> oldestInWindow) {

    /** Validates the components. */
    public Admission {
      requireNonNull(oldestInWindow, "oldestInWindow must not be null - use Optional.empty()");
    }

    /**
     * An admission that does not report the oldest event in the window - the
     * shape before the oldest event was part of it.
     *
     * @param admitted       {@code true} when the event was recorded
     * @param eventsInWindow events at or after {@code since}, including this one when admitted
     */
    public Admission(boolean admitted, int eventsInWindow) {
      this(admitted, eventsInWindow, Optional.empty());
    }
  }

  /**
   * Counts the key's events at or after {@code since} and records {@code at}
   * only when fewer than {@code limit} are present — the check and the
   * record as one step (JS-SEC-078, CWE-367).
   *
   * <p><strong>Implementations must override this method</strong> with an
   * operation that is atomic in their backing store (JS-SEC-118). The default
   * is {@link #countSince} followed by {@link #recordEvent}; it serialises its
   * callers on the store instance, which makes concurrent admissions through
   * one instance in one JVM atomic, and nothing more: it does not cover a
   * second instance over the same data, another node, or a caller that uses
   * {@link #recordEvent} directly. The shipped in-memory and Eclipse-Store
   * implementations override it, count events with equal instants separately,
   * drop events older than {@code since} on the way and report the oldest event
   * left in the window; the contract in {@code jCustos-persistence-testkit}
   * checks the admission under real concurrency. The default reports no oldest
   * event.</p>
   *
   * @param key   bucket key
   * @param at    event instant
   * @param since window start; events before it do not count
   * @param limit maximum events in the window including this one
   * @return the admission outcome
   * @since 00.84.00
   */
  default Admission tryAdmit(RateLimitKey key, Instant at, Instant since, int limit) {
    synchronized (this) {
      int current = countSince(key, since);
      if (current >= limit) {
        return new Admission(false, current);
      }
      recordEvent(key, at);
      return new Admission(true, current + 1);
    }
  }

  /**
   * The end of the block {@link #block} recorded for {@code key}. The key is
   * blocked while the clock reads earlier than this instant. The store has no
   * clock of its own, so a block that has ended is still reported until
   * {@link #reset} or {@link #purgeOlderThan} removes it - the caller compares
   * it with its own time.
   *
   * <p>The default throws {@link UnsupportedOperationException}: a store that
   * does not implement blocks says so instead of reporting none.
   * {@link InMemoryRateLimitPolicy} asks once at construction when it is given
   * a {@link RateLimitEscalation} and refuses such a store.</p>
   *
   * @param key key to query; must not be {@code null}
   * @return the end of the key's block; empty when none is recorded
   * @throws UnsupportedOperationException when the store keeps no blocks
   * @since 00.84.00
   */
  default Optional<Instant> blockedUntil(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    throw noBlocks();
  }

  /**
   * Blocks {@code key} until {@code until} - or keeps the key's block when it
   * already lasts longer - as one step: a block only ever grows, so of two
   * concurrent calls the later end wins whatever order they run in.
   * <p>
   * <strong>Implementations that keep blocks must make this atomic</strong> in
   * their backing store, as {@link InMemoryRateLimitStore} and the Eclipse-Store
   * adapter do; the contract in {@code jCustos-persistence-testkit} checks it
   * with real threads. A store that persists its data persists the block with
   * it, so a restart does not lift it. A key that has no events yet is tracked
   * like any other key, inside the store's bound. A store with a bound on its keys
   * evicts a key whose block lasts only when no other key is left to evict - a
   * client that mints fresh keys must not lift its own block (since 00.84.00; the
   * contract checks it through {@code newBoundedStore}). The default throws
   * {@link UnsupportedOperationException}.</p>
   *
   * @param key   key to block; must not be {@code null}
   * @param until end of the block, exclusive; must not be {@code null}
   * @return the end of the key's block after the call - the later of the end
   *         recorded before and {@code until}
   * @throws UnsupportedOperationException when the store keeps no blocks
   * @since 00.84.00
   */
  default Instant block(RateLimitKey key, Instant until) {
    requireNonNull(key, "key must not be null");
    requireNonNull(until, "until must not be null");
    throw noBlocks();
  }

  /** @return the refusal of the defaults of {@link #blockedUntil} and {@link #block} */
  private static UnsupportedOperationException noBlocks() {
    return new UnsupportedOperationException("this RateLimitStore keeps no blocks: implement"
        + " blockedUntil and block (atomically) to use it with a RateLimitEscalation");
  }
}
