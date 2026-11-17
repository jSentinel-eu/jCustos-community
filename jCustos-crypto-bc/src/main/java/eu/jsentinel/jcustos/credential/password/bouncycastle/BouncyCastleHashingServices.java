/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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
package eu.jsentinel.jcustos.credential.password.bouncycastle;

import eu.jsentinel.jcustos.credential.password.DefaultPasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idDefaults;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idParameterValidator;
import eu.jsentinel.jcustos.credential.password.bouncycastle.argon2.Argon2idPasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt.BcryptDefaults;
import eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt.BcryptParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt.BcryptParameterValidator;
import eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt.BcryptPasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt.ScryptDefaults;
import eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt.ScryptParameterNames;
import eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt.ScryptParameterValidator;
import eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt.ScryptPasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;

import java.util.List;
import java.util.Objects;

/**
 * Wiring helpers for the Phase-1b <em>modern</em> profile.
 *
 * <p>The modern profile prefers Argon2id for new hashes while still
 * accepting bcrypt, scrypt and PBKDF2 envelopes for verification. The
 * rehash engine flags non-Argon2id envelopes as
 * {@code ALGORITHM_DEPRECATED} so successful logins under the modern
 * profile transparently migrate their stored hashes (CWE-916).</p>
 *
 * <p>The profile is strictly opt-in: calling
 * {@link #modern()} requires this module to be on the classpath. The
 * core
 * {@link eu.jsentinel.jcustos.credential.password.PasswordHashingServices}
 * helper keeps emitting plain PBKDF2 envelopes.</p>
 *
 * <p><strong>Pepper.</strong> {@link #modern(PepperService)} and
 * {@link #modern(PasswordHashPolicy, KdfExecutionLimiter, PepperService)}
 * build the same profile with a {@link PepperService}: new hashes are
 * peppered with its active key ({@code HMAC-SHA-256} after Argon2id), stored
 * hashes verify with the key their envelope names, and {@code needsRehash}
 * reports {@code PEPPER_KEY_ROTATED} for a hash under another key. Until
 * 00.84.00 every factory of this class set {@link NoOpPepperService}, so
 * peppered Argon2id required the raw
 * {@link DefaultPasswordHashingService} constructor. The overloads without
 * a pepper service still use {@link NoOpPepperService}.</p>
 */
public final class BouncyCastleHashingServices {

  private BouncyCastleHashingServices() { }

  /**
   * Returns a fully wired modern profile using the
   * {@link #modernPolicy() reference modern policy} and the default
   * {@link KdfResourceBudget#defaults() KDF resource budget}.
   */
  public static PasswordHashingService modern() {
    return modern(modernPolicy(),
        new SemaphoreKdfExecutionLimiter(KdfResourceBudget.defaults()));
  }

  /**
   * Returns a fully wired modern profile under the supplied policy.
   * The policy must list {@code Argon2id} / {@code argon2id-bc} as
   * preferred (so the modern profile remains the explicit operator
   * decision the Konzept calls for).
   */
  public static PasswordHashingService modern(PasswordHashPolicy policy) {
    return modern(policy,
        new SemaphoreKdfExecutionLimiter(KdfResourceBudget.defaults()));
  }

  /**
   * Returns the modern profile of {@link #modern()} — reference policy,
   * default KDF budget — peppered by {@code pepperService}.
   *
   * @param pepperService the pepper keys, for example a
   *                      {@link eu.jsentinel.jcustos.credential.password.pepper.KeyStorePepperService}
   *                      or a
   *                      {@link eu.jsentinel.jcustos.credential.password.pepper.FilePepperService}
   * @since 00.84.00
   */
  public static PasswordHashingService modern(PepperService pepperService) {
    return modern(modernPolicy(),
        new SemaphoreKdfExecutionLimiter(KdfResourceBudget.defaults()), pepperService);
  }

  /**
   * Returns a fully wired modern profile with a caller-supplied limiter and
   * no pepper ({@link NoOpPepperService}).
   *
   * @see #modern(PasswordHashPolicy, KdfExecutionLimiter, PepperService)
   */
  public static PasswordHashingService modern(
      PasswordHashPolicy policy, KdfExecutionLimiter limiter) {
    return modern(policy, limiter, NoOpPepperService.INSTANCE);
  }

  /**
   * Returns a fully wired modern profile with a caller-supplied limiter and
   * pepper service.
   *
   * <p>All four Phase-1a/1b providers (Argon2id, bcrypt, scrypt,
   * PBKDF2-HMAC-SHA-256) are registered so that stored hashes from
   * any of these algorithms remain verifiable while new hashes are
   * produced through the preferred provider declared by {@code policy}.
   * Construction fails fast through {@link DefaultPasswordHashingService}
   * if the preferred provider does not match a registered one.</p>
   *
   * <p>{@code pepperService} peppers every new hash with its active key and
   * verifies stored hashes with the key their envelope names; a key id it
   * does not know fails the verification through the dummy path, like a
   * wrong password. {@link NoOpPepperService#INSTANCE} switches peppering
   * off.</p>
   *
   * @since 00.84.00
   */
  public static PasswordHashingService modern(
      PasswordHashPolicy policy, KdfExecutionLimiter limiter, PepperService pepperService) {
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(limiter, "limiter");
    Objects.requireNonNull(pepperService, "pepperService");
    PasswordHashProviderRegistry providerRegistry =
        new PasswordHashProviderRegistry(List.of(
            new Argon2idPasswordHashProvider(),
            new BcryptPasswordHashProvider(),
            new ScryptPasswordHashProvider(),
            new Pbkdf2PasswordHashProvider()));
    PasswordHashParameterValidatorRegistry validatorRegistry =
        new PasswordHashParameterValidatorRegistry(List.of(
            new Argon2idParameterValidator(),
            new BcryptParameterValidator(),
            new ScryptParameterValidator(),
            new Pbkdf2ParameterValidator()));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(validatorRegistry),
        providerRegistry,
        pepperService,
        policy,
        new RehashDecisionEngine(),
        limiter,
        new DefaultDummyVerificationService(
            providerRegistry, policy, PasswordHashCodec.DEFAULT));
  }

  /**
   * Reference modern policy: Argon2id preferred; bcrypt, scrypt and
   * PBKDF2 accepted for verification only (the rehash engine flags
   * each as deprecated).
   */
  public static PasswordHashPolicy modernPolicy() {
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(BcryptParameterNames.ALGORITHM)
        .addAcceptableProviderId(BcryptParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(ScryptParameterNames.ALGORITHM)
        .addAcceptableProviderId(ScryptParameterNames.PROVIDER_ID)
        .addAcceptableAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .addAcceptableProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM,
            Argon2idDefaults.defaultParameters())
        .minimumParameters(Argon2idParameterNames.ALGORITHM,
            Argon2idDefaults.minimumParameters())
        .maximumParameters(Argon2idParameterNames.ALGORITHM,
            Argon2idDefaults.maximumParameters())
        .defaultParameters(BcryptParameterNames.ALGORITHM,
            BcryptDefaults.defaultParameters())
        .minimumParameters(BcryptParameterNames.ALGORITHM,
            BcryptDefaults.minimumParameters())
        .maximumParameters(BcryptParameterNames.ALGORITHM,
            BcryptDefaults.maximumParameters())
        .defaultParameters(ScryptParameterNames.ALGORITHM,
            ScryptDefaults.defaultParameters())
        .minimumParameters(ScryptParameterNames.ALGORITHM,
            ScryptDefaults.minimumParameters())
        .maximumParameters(ScryptParameterNames.ALGORITHM,
            ScryptDefaults.maximumParameters())
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.maximumParameters())
        .build();
  }
}
