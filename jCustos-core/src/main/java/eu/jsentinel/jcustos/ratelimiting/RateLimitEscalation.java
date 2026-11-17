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

import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * Opt-in escalation of an {@link InMemoryRateLimitPolicy}: a key that keeps
 * hitting its limit is blocked for a while instead of being throttled request
 * by request.
 * <p>
 * Once a key has been throttled {@code throttleThreshold} times within
 * {@code escalationWindow}, the throttle that reaches the threshold blocks the
 * key for {@code blockDuration}. While the block lasts the policy answers
 * {@link RateLimitDecision.Blocked} without recording anything; a throttle
 * counted against the key before the block does not count towards the next
 * one. When the block ends the key starts afresh: its window applies as
 * before, and another {@code throttleThreshold} throttles block it again.
 * <pre>{@code
 *   // 20 logins a minute per address; ten refusals within 15 minutes block it for an hour
 *   RateLimitPolicy policy = new InMemoryRateLimitPolicy(store, audit, 20,
 *       Duration.ofMinutes(1), Clock.systemUTC(),
 *       new RateLimitEscalation(10, Duration.ofMinutes(15), Duration.ofHours(1)));
 * }</pre>
 * <p>
 * The policy keeps the throttles and the block in its {@link RateLimitStore}
 * - the throttles under a key of their own
 * ({@link InMemoryRateLimitPolicy#THROTTLE_SCOPE_PREFIX}), the block through
 * {@link RateLimitStore#block} - so a persistent store carries both across a
 * restart. Without an escalation the policy never blocks.
 *
 * @param throttleThreshold throttles within {@code escalationWindow} that block
 *                          the key; at least 1
 * @param escalationWindow  how far back throttles count; strictly positive
 * @param blockDuration     how long a block lasts; strictly positive
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public record RateLimitEscalation(int throttleThreshold, Duration escalationWindow,
                                  Duration blockDuration) {

  /** Validates the components. */
  public RateLimitEscalation {
    if (throttleThreshold < 1) {
      throw new IllegalArgumentException("throttleThreshold must be at least 1");
    }
    requirePositive(escalationWindow, "escalationWindow");
    requirePositive(blockDuration, "blockDuration");
  }

  private static void requirePositive(Duration value, String name) {
    requireNonNull(value, name + " must not be null");
    if (value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(name + " must be strictly positive");
    }
  }
}
