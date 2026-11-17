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
package eu.jsentinel.jcustos.credential.password.pepper;

import java.util.Optional;

/**
 * Supplies the pepper keys of the credential pipeline: the secret that
 * {@link PepperApplicator} mixes into every new password hash after the KDF
 * ({@code HMAC-SHA-256(key, kdfOutput)}), and the keys that verify hashes peppered
 * earlier. A stolen password database is of no use for offline guessing without the
 * pepper, which therefore must never be stored next to it (CWE-916, CWE-522).
 *
 * <p>The envelope of a peppered hash records the key id, never the key. The pipeline
 * asks {@link #activeKeyId()} which key peppers a new hash and {@link #resolve(String)}
 * for the key a stored hash names. A key id that does not resolve fails the verification
 * through the pipeline's dummy path, at the cost and with the public answer of a wrong
 * password ({@code VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY} internally, CWE-203); a hash
 * whose key id is not the active one still verifies, and {@code needsRehash} reports
 * {@code RehashReason.PEPPER_KEY_ROTATED} for it.</p>
 *
 * <p>Shipped implementations:</p>
 * <ul>
 *   <li>{@link KeyStorePepperService} — secret-key entries of a JDK {@code KeyStore}: a
 *       PKCS12 file or a PKCS#11 token (since 00.84.00);</li>
 *   <li>{@link FilePepperService} — one Base64 file per key id, for example container
 *       secrets under {@code /run/secrets} (since 00.84.00);</li>
 *   <li>{@link InMemoryPepperService} — keys handed over in code, for tests and demos;</li>
 *   <li>{@link NoOpPepperService} — no pepper, the default of every factory.</li>
 * </ul>
 *
 * <p>Wiring: {@code BouncyCastleHashingServices.modern(policy, limiter, pepper)} or
 * {@code modern(pepper)} (jCustos-crypto-bc, since 00.84.00),
 * {@code PasswordHashingServices.defaults(policy, limiter, pepper)}, or in the DX
 * bootstrap {@code .credentials(c -> c.modern().pepper(pepper))}.</p>
 *
 * <p>Contract for implementations: {@link #resolve(String)} is called on every
 * verification and hands out a fresh copy that the caller zeroes, so it must not block
 * on I/O — load the keys up front; a key has at least
 * {@link PepperReference#MIN_KEY_BYTES} bytes; an unknown key id is
 * {@link Optional#empty()}, never an exception; neither key material nor anything
 * derived from it appears in a log line, an exception message or {@code toString()}.</p>
 */
public interface PepperService {

  /**
   * Currently active pepper key id used by the policy when producing
   * new hashes. {@link Optional#empty()} signals that no pepper is
   * applied to new hashes.
   */
  Optional<String> activeKeyId();

  /**
   * Resolves the pepper material for a previously stored hash.
   *
   * @return the pepper bytes, or {@link Optional#empty()} when no
   *         pepper service knows about this key id
   */
  Optional<byte[]> resolve(String keyId);
}
