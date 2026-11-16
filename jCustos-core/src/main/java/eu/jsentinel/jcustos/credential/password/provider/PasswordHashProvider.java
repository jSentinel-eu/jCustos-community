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
package eu.jsentinel.jcustos.credential.password.provider;

import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.ProviderVerificationResult;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Service-provider contract for a concrete password hashing
 * implementation.
 *
 * <p>Providers are discovered through Java's {@link java.util.ServiceLoader}
 * or registered explicitly by the bootstrap layer. Phase 1a ships a
 * single PBKDF2 provider in {@code security-core}; the optional
 * {@code security-crypto-bc} module adds Argon2id, bcrypt and scrypt.</p>
 *
 * <p>Providers must <strong>not</strong>:</p>
 * <ul>
 *   <li>change the global JCA provider order through
 *       {@code Security.insertProviderAt} or equivalent;</li>
 *   <li>log password material, derived key material or secret salts;</li>
 *   <li>throw on a genuine credential mismatch &mdash; return
 *       {@link ProviderVerificationResult.NotMatched} instead.</li>
 * </ul>
 *
 * <p>Pepper material is threaded through as an {@link Optional} byte
 * array; Phase 1a always supplies {@link Optional#empty()} (the
 * {@code NoOpPepperService}).</p>
 */
public interface PasswordHashProvider {

  /**
   * Logical provider identifier, stable across releases. Stored in the
   * envelope so that verification can resolve the same implementation
   * regardless of the active policy.
   */
  String providerId();

  /**
   * Canonical algorithm identifier this provider handles by default.
   */
  String algorithm();

  /**
   * Returns whether this provider can serve the given combination. The
   * default implementation requires an exact match on both identifiers;
   * providers that handle multiple algorithms or migration aliases
   * override this.
   */
  default boolean supports(String providerId, String algorithm) {
    Objects.requireNonNull(providerId, "providerId");
    Objects.requireNonNull(algorithm, "algorithm");
    return providerId().equals(providerId) && algorithm().equals(algorithm);
  }

  /**
   * Derives a fresh hash for the supplied password under the active
   * policy.
   *
   * @param password   caller-owned character array; the provider
   *                   must <em>not</em> zero or modify it
   * @param policy     active policy from which to read parameters
   * @param pepper     resolved active pepper key, or
   *                   {@link Optional#empty()} when peppering is off;
   *                   the provider applies the pepper as
   *                   {@code HMAC-SHA-256(pepper.key, KDF(password,salt))}
   *                   and writes the {@code pepper.keyId} into the
   *                   envelope
   */
  PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<PepperReference> pepper);

  /**
   * Verifies the supplied password against the parsed envelope.
   *
   * <p>Implementations must use a constant-time comparison and must
   * never throw on a genuine mismatch. Provider-level failures (missing
   * JCA service, unsupported parameter combination) collapse onto
   * {@link ProviderVerificationResult.ProviderError} so the pipeline can
   * keep public messaging generic.</p>
   *
   * @param pepper resolved pepper key matching
   *               {@code envelope.pepperKeyId()}, or
   *               {@link Optional#empty()} when the envelope has no
   *               pepper field
   */
  ProviderVerificationResult verify(
      char[] password,
      PasswordHashEnvelope envelope,
      Optional<PepperReference> pepper);

  /**
   * A rehash this provider requires for a stored envelope whatever the
   * active policy says (JS-SEC-133, CWE-327, CWE-521).
   *
   * <p>The rehash engine compares an envelope with the policy: algorithm,
   * provider, format and policy version, and the policy's default
   * parameters. Some weaknesses are known only to the provider - a bcrypt
   * hash derived without the terminating NUL byte is weak at any cost - and
   * a policy that assembles its defaults by hand does not name them. A
   * provider reports such an envelope here; {@code needsRehash} of the
   * default hashing service then answers {@code Required} with this reason
   * under every policy. Called only for envelopes this provider
   * {@linkplain #supports(String, String) serves}; must not run the KDF and
   * must not throw for a well-formed envelope.
   *
   * @param envelope parsed envelope written by this provider; non-null
   * @return the reason to rehash, or empty when the envelope is current as
   *         far as the provider is concerned (the default)
   * @since 00.84.00
   */
  default Optional<RehashReason> rehashHint(PasswordHashEnvelope envelope) {
    Objects.requireNonNull(envelope, "envelope");
    return Optional.empty();
  }

  /**
   * Optional resource estimate for the supplied parameter map. Default:
   * {@link ResourceEstimate#UNKNOWN}.
   */
  default ResourceEstimate resourceEstimate(Map<String, String> parameters) {
    Objects.requireNonNull(parameters, "parameters");
    return ResourceEstimate.UNKNOWN;
  }
}
