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
package eu.jsentinel.jcustos.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.ratelimiting.RateLimitDecision;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;

import java.util.Objects;

/**
 * Answers a {@link RateLimitDecision} in a REST handler: nothing for
 * {@link RateLimitDecision.Allowed}, {@link HttpStatus#TOO_MANY_REQUESTS} with a
 * {@code Retry-After} header for {@link RateLimitDecision.Throttled} and
 * {@link RateLimitDecision.Blocked} alike.
 *
 * <p>The REST adapter wires no {@link RateLimitPolicy} itself; the handler that
 * protects an operation asks the policy and lets this class answer, so that a
 * block is refused like a throttle and cannot slip through a check that only
 * knows {@code Throttled}:
 *
 * <pre>{@code
 * if (RestRateLimit.respond(policy.tryAcquire(key), response)) {
 *   return; // 429 written
 * }
 * // proceed
 * }</pre>
 *
 * <p>The response is written by {@link RestThrottleResponses}: the
 * {@code Retry-After} value is the decision's retry-after in whole seconds,
 * rounded up and at least {@link RestThrottleResponses#MIN_RETRY_AFTER_SECONDS},
 * and the body is the same for a throttle and a block, so a client cannot tell
 * which one it met.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestRateLimit {

  private RestRateLimit() {
  }

  /**
   * Writes the answer to {@code decision} with the generic
   * {@link RestThrottleResponses#DEFAULT_BODY}.
   *
   * @param decision the policy's decision; non-null
   * @param response the response to write; non-null
   * @return {@code true} when the request was refused and the {@code 429} written - the
   *         handler returns; {@code false} for an admitted request, nothing written
   */
  public static boolean respond(RateLimitDecision decision, RestResponse response) {
    return respond(decision, response, RestThrottleResponses.DEFAULT_BODY);
  }

  /**
   * Writes the answer to {@code decision} with {@code body}, for an application whose
   * error bodies have a format of their own.
   *
   * @param decision the policy's decision; non-null
   * @param response the response to write; non-null
   * @param body     the body of a refusal; non-null, and it must not tell a throttle from a
   *                 block
   * @return {@code true} when the request was refused and the {@code 429} written;
   *         {@code false} for an admitted request, nothing written
   */
  public static boolean respond(RateLimitDecision decision, RestResponse response, String body) {
    Objects.requireNonNull(decision, "decision");
    Objects.requireNonNull(response, "response");
    Objects.requireNonNull(body, "body");
    switch (decision) {
      case RateLimitDecision.Allowed allowed -> {
        return false;
      }
      case RateLimitDecision.Throttled throttled ->
          RestThrottleResponses.tooManyRequests(response, throttled.retryAfter(), body);
      case RateLimitDecision.Blocked blocked ->
          RestThrottleResponses.tooManyRequests(response, blocked.retryAfter(), body);
    }
    return true;
  }
}
