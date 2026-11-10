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
package eu.jsentinel.jcustos.bruteforce;

import java.time.Instant;
import java.util.Objects;

/**
 * Adapter-neutral input to a {@link LoginAttemptPolicy} decision.
 * <p>
 * The username and client address are normalised before throttling — the
 * caller is expected to pass them as-is; the policy applies its
 * {@link eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer} to the
 * username and trims and lower-cases the client address, so identical
 * user / client pairs collapse into the same counter.
 *
 * @param username      the username being attempted; may be {@code null}
 *                      if not yet known (e.g. raw form submission)
 * @param clientAddress the remote client address as observed by the
 *                      adapter; may be {@code null} if unavailable
 * @param sessionId     session identifier, or {@code null} if there is no
 *                      session yet
 * @param timestamp     when the attempt is observed; defaults to "now"
 *                      via {@link #now(String, String, String)}
 */
public record LoginAttemptContext(
    String username,
    String clientAddress,
    String sessionId,
    Instant timestamp
) {

  public LoginAttemptContext {
    Objects.requireNonNull(timestamp, "timestamp");
  }

  /**
   * Factory for the common case — the policy supplies the timestamp.
   *
   * @param username      attempted username (may be {@code null} for
   *                      anonymous flows; throttling does not apply)
   * @param clientAddress remote client address (may be {@code null})
   * @param sessionId     bound session id, if available (may be {@code null})
   * @return a context with {@link Instant#now()} as the timestamp
   */
  public static LoginAttemptContext now(String username, String clientAddress, String sessionId) {
    return new LoginAttemptContext(username, clientAddress, sessionId, Instant.now());
  }
}
