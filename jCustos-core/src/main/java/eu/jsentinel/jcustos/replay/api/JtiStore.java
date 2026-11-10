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
package eu.jsentinel.jcustos.replay.api;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Instant;

/**
 * A single-use {@code jti} (JWT id) store for replay protection (V00.79) — the
 * backing for DPoP-proof single-use (RFC 9449 §11.1) and any other one-time-token
 * check. {@link #record(String, Instant)} atomically records a {@code jti} that has
 * not been seen; a second record of the same {@code jti} within its validity window
 * fails with {@link ReplayError}. Default impl is in-memory; production consumers
 * plug a shared store (JDBC / Redis). Implementations MUST be thread-safe.
 *
 * <p><strong>Size contract (JS-SEC-148, CWE-770):</strong> a {@code jti} is chosen by the party
 * that presents the token, so its length is not under the control of the store's owner. An
 * implementation MUST therefore keep an entry of bounded size whatever the length of the
 * {@code jti} — the reference implementation records the SHA-256 digest (32 bytes) and never the
 * value itself; a JDBC / Redis implementation should do the same or declare a fixed-width key
 * column. Callers bound the value as well: the DPoP validator rejects a {@code jti} longer than
 * {@link eu.jsentinel.jcustos.jwt.api.JoseLimits#MAX_JTI_CHARS} characters before it reaches the
 * store. A capacity bound that counts entries is not a memory bound unless both hold.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public interface JtiStore {

  /**
   * Atomically records {@code jti} as seen until {@code expiresAt}.
   *
   * @param jti       the one-time identifier; of any length — the implementation must not let
   *                  the stored entry grow with it (see the size contract above)
   * @param expiresAt when this {@code jti} may be evicted (its proof's iat + skew)
   * @return success if newly recorded, or {@link ReplayError} if already seen
   */
  Result<Boolean, ReplayError> record(String jti, Instant expiresAt);
}
