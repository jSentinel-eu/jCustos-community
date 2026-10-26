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
package eu.jsentinel.jcustos.oidc.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Optional;
import java.util.Set;

/**
 * Maps an OIDC session — keyed by ({@code issuer}, {@code subject}, optional
 * {@code sid}) — to the relying party's own session identifiers, so a Back-Channel or
 * Front-Channel Logout can terminate exactly the right sessions (V00.79). Adapter
 * modules back this with the Vaadin / REST session registry. Implementations MUST be
 * thread-safe.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public interface SessionRegistry {

  /** Binds the RP's {@code sessionId} to the OP session ({@code issuer}, {@code subject}, {@code sid}). */
  void register(String issuer, String subject, Optional<String> sid, String sessionId);

  /**
   * Terminates and returns the RP session ids matching ({@code issuer}, {@code subject}
   * / {@code sid}): by {@code sid} when present, otherwise every session of the subject.
   */
  Set<String> terminate(String issuer, Optional<String> subject, Optional<String> sid);

  /**
   * Forgets one RP session id, for example when the servlet container destroys
   * the session (JS-SEC-078, CWE-770): without it every registered session
   * stays in the registry until a logout for its subject or sid arrives, and
   * the registry grows with every login. The Vaadin adapter wires this through
   * {@code VaadinSessionRegistryCleanup}.
   *
   * @param sessionId the RP session id passed to {@link #register}
   * @since 00.84.00
   */
  void unregister(String sessionId);
}
