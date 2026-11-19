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
package eu.jsentinel.jcustos.audit;

import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Emitted by {@code RateLimitPolicy.tryAcquire} when an event was
 * refused because the per-key event count within the configured
 * window equals or exceeds the limit.
 *
 * @param timestamp   UTC throttle time; non-null
 * @param scope       the {@code RateLimitKey.scope()} value that was
 *                    throttled; non-blank
 * @param subjectId   subject id when the scope is per-subject;
 *                    may be empty for IP / endpoint scopes
 * @param limit       configured per-window event limit; positive
 * @param window      configured window duration; non-null, positive
 * @param eventsInWindow events counted within the window at decision
 *                       time; non-negative. Two producers publish at
 *                       most one event a second - per gate, per key - and
 *                       record here how many refusals the event stands
 *                       for: those counted since the previous event of
 *                       the same gate or key, including the refusal that
 *                       publishes it (since 00.84.00, exit review RF11).
 *                       They are the credential-check gate (scope
 *                       {@code login:credential-check}) and
 *                       {@code InMemoryRateLimitPolicy} for a key that is
 *                       already blocked (and for its aggregate scope
 *                       {@code #throttled:untracked-keys})
 */
public record RateLimitExceeded(
    Instant timestamp,
    String scope,
    String subjectId,
    int limit,
    Duration window,
    int eventsInWindow
) implements AuditEvent {

  /** Validates the record components. */
  public RateLimitExceeded {
    requireNonNull(timestamp, "timestamp must not be null");
    if (scope == null || scope.isBlank()) {
      throw new IllegalArgumentException("scope must not be blank");
    }
    subjectId = subjectId == null ? "" : subjectId;
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be strictly positive");
    }
    requireNonNull(window, "window must not be null");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be strictly positive");
    }
    if (eventsInWindow < 0) {
      throw new IllegalArgumentException("eventsInWindow must not be negative");
    }
  }
}
