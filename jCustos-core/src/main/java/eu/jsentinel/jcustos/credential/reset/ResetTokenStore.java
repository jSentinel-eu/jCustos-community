/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.reset;

import java.util.List;
import java.util.Optional;

/**
 * Persistence-neutral storage of password-reset tokens.
 *
 * <p>The store never logs verifier values or digests (CWE-209). It
 * supports CAS transitions on the {@link ResetTokenStatus} field so
 * tokens are guaranteed to be single-use even under concurrent
 * consume attempts (CWE-362, CWE-640).</p>
 */
public interface ResetTokenStore {

  /**
   * Inserts a freshly issued token. Implementations may throw when a
   * record with the same selector already exists; in practice the
   * selector entropy makes that impossible to hit by accident.
   */
  void save(ResetTokenRecord record);

  /**
   * Looks up a token by selector. Verifier digests are never compared
   * here; that is the reset service's job.
   */
  Optional<ResetTokenRecord> findBySelector(String selector);

  /**
   * Lists every token issued for {@code username}, regardless of status.
   * The reset service uses it to retire open siblings when a new token is
   * issued and when one is consumed (JS-SEC-074, CWE-640): an intercepted
   * older link must not reset the password a second time.
   *
   * @param username the credential's username; non-blank
   * @return the records in no particular order, empty when none exist
   * @since 00.84.00
   */
  List<ResetTokenRecord> findByUsername(String username);

  /**
   * Atomically marks the token CONSUMED if its current status still
   * matches {@code expectedStatus}.
   */
  ResetTokenUpdateResult markConsumedIfCurrent(
      String selector, ResetTokenStatus expectedStatus);

  /**
   * Atomically marks the token EXPIRED if its current status still
   * matches {@code expectedStatus}. Called lazily when verification
   * notices the expiry, so audit timelines stay accurate.
   */
  ResetTokenUpdateResult markExpiredIfCurrent(
      String selector, ResetTokenStatus expectedStatus);
}
