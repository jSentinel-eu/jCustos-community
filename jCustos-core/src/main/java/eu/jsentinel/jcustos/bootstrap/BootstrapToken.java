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
package eu.jsentinel.jcustos.bootstrap;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * One-time bootstrap token.
 * <p>
 * The token authorizes the creation of the very first administrator while
 * the system is uninitialized. It is not an administrator credential and
 * must not be confused with one.
 *
 * @param value     the opaque token value
 * @param createdAt the instant the token was generated, used to evaluate
 *                  expiry against a configurable validity window
 */
public record BootstrapToken(String value, Instant createdAt) {

  /**
   * How far {@link #createdAt} may lie ahead of the reference instant before
   * the token is treated as invalid (JS-SEC-130, CWE-613). It absorbs a clock
   * that was set back a little between two starts; anything beyond it is not a
   * token this installation issued.
   *
   * @since 00.84.00
   */
  public static final Duration FUTURE_TOLERANCE = Duration.ofMinutes(5);

  /** Defensive constructor — rejects null / blank values. */
  public BootstrapToken {
    Objects.requireNonNull(value, "value must not be null");
    if (value.isBlank()) throw new IllegalArgumentException("value must not be blank");
    Objects.requireNonNull(createdAt, "createdAt must not be null");
  }

  /**
   * Constant-time comparison against a candidate string. Safe against
   * timing attacks.
   *
   * @param candidate the candidate token value to compare against this token
   * @return {@code true} if the candidate matches this token's value
   */
  public boolean matches(String candidate) {
    if (candidate == null) return false;
    byte[] a = value.getBytes(StandardCharsets.UTF_8);
    byte[] b = candidate.getBytes(StandardCharsets.UTF_8);
    return MessageDigest.isEqual(a, b);
  }

  /**
   * @param now      the reference instant to evaluate expiry against
   * @param validity the validity duration since {@link #createdAt}
   * @return {@code true} when {@code now} is after {@code createdAt + validity},
   *     or when {@code createdAt} lies more than {@link #FUTURE_TOLERANCE}
   *     ahead of {@code now}
   */
  public boolean isExpired(Instant now, Duration validity) {
    Objects.requireNonNull(now, "now");
    Objects.requireNonNull(validity, "validity");
    // JS-SEC-130 (CWE-613): a creation instant in the future never reaches
    // createdAt + validity, so a token file carrying one would never expire.
    // The generator stamps tokens with the current time; a token from the
    // future was not generated here and is treated as expired.
    if (createdAt.isAfter(now.plus(FUTURE_TOLERANCE))) {
      return true;
    }
    return now.isAfter(createdAt.plus(validity));
  }

  /**
   * Redacts the secret {@code value} — the compiler-generated record
   * {@code toString()} would otherwise print the one-time admin token into any
   * log or diagnostic that stringifies the token (V00.75.20, R021).
   *
   * @return a value-free description
   */
  @Override
  public String toString() {
    return "BootstrapToken[value=***, createdAt=" + createdAt + "]";
  }
}
