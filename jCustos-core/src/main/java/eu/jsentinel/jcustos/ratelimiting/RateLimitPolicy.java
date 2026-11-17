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

/**
 * Pluggable rate-limiting decision point — separate from
 * {@link eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy
 * LoginAttemptPolicy} (which is purpose-built for password-guessing
 * detection) and from
 * {@link eu.jsentinel.jcustos.session.SessionPolicy
 * SessionPolicy} (which is about session lifetime).
 * <p>
 * Callers wrap the protected operation and refuse every decision that is not
 * {@link RateLimitDecision.Allowed} - a throttle as well as a block
 * (since 00.84.00):
 * <pre>{@code
 *   switch (policy.tryAcquire(key)) {
 *     case RateLimitDecision.Allowed allowed -> { } // proceed
 *     case RateLimitDecision.Throttled throttled -> {
 *       // 429 Too Many Requests + Retry-After from throttled.retryAfter(), rounded up
 *       return;
 *     }
 *     case RateLimitDecision.Blocked blocked -> {
 *       // the same answer, with blocked.retryAfter()
 *       return;
 *     }
 *   }
 * }</pre>
 * A REST handler writes that answer with
 * {@code eu.jsentinel.jcustos.rest.RestRateLimit.respond(decision, response)}.
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
@FunctionalInterface
public interface RateLimitPolicy {

  /**
   * Attempts to record one event under {@code key} against the
   * policy's configured per-window limit. The default behaviour
   * mirrors a leaky bucket: an admitted event is counted, a
   * throttled event is not. Concrete implementations document
   * their semantics.
   *
   * @param key non-null key; the scope is the application's
   *            choice — IP, subject, endpoint, or composed
   * @return admit / throttle / block decision, never {@code null}
   */
  RateLimitDecision tryAcquire(RateLimitKey key);
}
