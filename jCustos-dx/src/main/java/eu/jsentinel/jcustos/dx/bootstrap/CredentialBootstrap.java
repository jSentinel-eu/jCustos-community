/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperService;
import eu.jsentinel.jcustos.credential.store.CredentialStore;

/**
 * Credential sub-builder of the fluent bootstrap.
 *
 * <p><strong>V00.73 status:</strong> typed surface — the two
 * credential worlds are kept rigorously separate (Konzept §10):
 * <ul>
 *   <li>{@link #passwordHasher(PasswordHasher)} is the legacy V00.70
 *       resolver path — wired through
 *       {@code JCustosServiceResolver.setPasswordHashingService(...)}.</li>
 *   <li>{@link #hashing(PasswordHashingService)} is the V00.71
 *       credential-pipeline path — stored in DX state and reported
 *       in {@code JCustosRuntime}; <strong>never</strong> stuffed
 *       into the legacy setter.</li>
 *   <li>{@link #pbkdf2Defaults()} sets BOTH worlds; {@link #modern()}
 *       sets only the V00.71 pipeline and requires
 *       {@code security-crypto-bc} on the classpath.</li>
 * </ul>
 *
 * <p>{@link #passwordReset(eu.jsentinel.jcustos.credential.reset.PasswordResetService)}
 * references the V00.71 {@code credential.reset.PasswordResetService},
 * NOT the V00.70 {@code accountlifecycle.PasswordResetService}
 * (same simple name; different package). Pick the
 * V00.71 type when importing.
 *
 * @since 00.72.00
 */
public interface CredentialBootstrap {

  CredentialBootstrap passwordHasher(PasswordHasher hasher);

  /**
   * Registers the V00.71 credential pipeline. Since 00.84.00 (JS-SEC-073)
   * {@code install()} wires it through
   * {@code JCustosServiceResolver.setCredentialHashingService(...)}, so
   * {@code JCustosServiceResolver.credentialHashingService()} returns this
   * instance; the legacy {@code PasswordHasher} slot is untouched.
   */
  CredentialBootstrap hashing(PasswordHashingService service);

  /**
   * Convenience: sets both the legacy {@code Pbkdf2PasswordHasher}
   * AND the V00.71 {@code PasswordHashingServices.defaults()}.
   * {@code JCustosRuntime} reports them as two separate entries —
   * legacy under {@link PasswordHasher}, pipeline under
   * {@link PasswordHashingService}. Since 00.84.00 the pipeline is peppered
   * by {@link #pepper(PepperService)} when one is recorded; the legacy hasher
   * is not.
   */
  CredentialBootstrap pbkdf2Defaults();

  /**
   * Configures the V00.71 modern (BouncyCastle) password-hashing
   * pipeline. Requires {@code jCustos-crypto-bc} on the classpath;
   * records an ERROR with code {@code credentials/modern-without-bc}
   * when the module is missing (a {@code JCustosBootstrapException} in
   * STRICT). Never silently falls back to PBKDF2. Since 00.84.00
   * (JS-SEC-073) the loaded Argon2id pipeline is wired like
   * {@link #hashing(PasswordHashingService)}, peppered by
   * {@link #pepper(PepperService)} when one is recorded.
   */
  CredentialBootstrap modern();

  /**
   * Peppers the pipeline that {@link #modern()} or {@link #pbkdf2Defaults()}
   * builds. Since 00.84.00 {@code install()} composes the service into that
   * pipeline — {@code BouncyCastleHashingServices.modern(pepper)} or
   * {@code PasswordHashingServices.defaults(policy, limiter, pepper)} with the
   * defaults of the call without a pepper — and lists it in
   * {@code JCustosRuntime.services()}. An active key id that does not resolve
   * to a usable key is reported as {@code credentials/pepper-active-key-unresolvable}
   * (ERROR), because every new hash would fail.
   *
   * <p>A finished pipeline passed to {@link #hashing(PasswordHashingService)}
   * cannot be peppered afterwards: next to {@code .hashing(...)}, and without
   * any pipeline, the pepper stays inert and is reported as
   * {@code dx/credential-pepper-recorded-not-wired} (WARNING; STRICT → ERROR,
   * JS-SEC-073) — build that pipeline with the pepper instead. The legacy
   * {@code PasswordHasher} that {@code .pbkdf2Defaults()} also sets is never
   * peppered.
   *
   * @param service the pepper keys, for example a
   *                {@code KeyStorePepperService} or a {@code FilePepperService}
   */
  CredentialBootstrap pepper(PepperService service);

  /**
   * Records a credential store for the application's own wiring; the
   * bootstrap does not consume it. Reported as
   * {@code dx/credential-store-recorded-not-wired} (WARNING; STRICT → ERROR)
   * since 00.84.00 (JS-SEC-073).
   */
  CredentialBootstrap credentialStore(CredentialStore store);

  /**
   * Records a password-change service for the application's own wiring; the
   * bootstrap does not consume it. Reported as
   * {@code dx/credential-change-recorded-not-wired} (WARNING; STRICT → ERROR)
   * since 00.84.00 (JS-SEC-073). Still requires {@link #hashing} (or
   * {@link #pbkdf2Defaults()}) — see {@code credentials/missing-hashing}.
   */
  CredentialBootstrap passwordChange(PasswordChangeService service);

  /**
   * Records a password-reset service for the application's own wiring; the
   * bootstrap does not consume it. Reported as
   * {@code dx/credential-reset-recorded-not-wired} (WARNING; STRICT → ERROR)
   * since 00.84.00 (JS-SEC-073).
   *
   * @param service the V00.71
   *                {@code eu.jsentinel.jcustos.credential.reset.PasswordResetService}
   *                (NOT the V00.70
   *                {@code eu.jsentinel.jcustos.accountlifecycle.PasswordResetService}
   *                — same simple name, different package)
   */
  CredentialBootstrap passwordReset(
      eu.jsentinel.jcustos.credential.reset.PasswordResetService service);
}
