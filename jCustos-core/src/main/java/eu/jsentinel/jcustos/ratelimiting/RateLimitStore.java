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
 * <p>Implementations must be thread-safe; concurrent recordEvent
 * and countSince happen on every protected endpoint.
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
   * Drops every recorded event under {@code key}.
   *
   * @param key key to clear; must not be {@code null}
   */
  void reset(RateLimitKey key);

  /**
   * Across every key, drops events whose timestamp is strictly
   * before {@code cutoff}. Intended as a retention sweep.
   *
   * @param cutoff retention boundary; must not be {@code null}
   * @return number of events purged
   */
  int purgeOlderThan(Instant cutoff);

  /**
   * Outcome of {@link #tryAdmit}: whether the event was recorded and how many
   * events the key holds in the window afterwards.
   *
   * @param admitted       {@code true} when the event was recorded
   * @param eventsInWindow events at or after {@code since}, including this one when admitted
   * @since 00.84.00
   */
  record Admission(boolean admitted, int eventsInWindow) {
  }

  /**
   * Counts the key's events at or after {@code since} and records {@code at}
   * only when fewer than {@code limit} are present — the check and the
   * record as one step (JS-SEC-078, CWE-367). The default is the non-atomic
   * {@link #countSince} + {@link #recordEvent} sequence for stores that
   * cannot do better; {@code InMemoryRateLimitStore} performs it atomically
   * per key and drops events older than {@code since} on the way.
   *
   * @param key   bucket key
   * @param at    event instant
   * @param since window start; events before it do not count
   * @param limit maximum events in the window including this one
   * @return the admission outcome
   * @since 00.84.00
   */
  default Admission tryAdmit(RateLimitKey key, Instant at, Instant since, int limit) {
    int current = countSince(key, since);
    if (current >= limit) {
      return new Admission(false, current);
    }
    recordEvent(key, at);
    return new Admission(true, current + 1);
  }
}
