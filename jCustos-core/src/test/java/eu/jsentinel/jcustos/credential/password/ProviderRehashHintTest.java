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
package eu.jsentinel.jcustos.credential.password;


import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * JS-SEC-133 (CWE-327, CWE-521): {@link DefaultPasswordHashingService#needsRehash(String)}
 * consults {@link PasswordHashProvider#rehashHint} of the envelope's provider, so a weakness
 * only the provider knows is rehashed under a policy whose defaults do not name it. The
 * provider is the real PBKDF2 provider behind a hand-written delegate that adds the hint.
 */
@DisplayName("JS-SEC-133 — the provider's rehash hint reaches needsRehash")
class ProviderRehashHintTest {

  @Test
  @DisplayName("a provider hint turns a current envelope into Required with the provider's reason")
  void hintIsApplied() {
    DefaultPasswordHashingService plain = service(envelope -> Optional.empty());
    String encoded = plain.hash("Correct-Horse-1".toCharArray()).encodedHash();
    assertSame(RehashDecision.NotRequired.INSTANCE, plain.needsRehash(encoded));

    DefaultPasswordHashingService hinted =
        service(envelope -> Optional.of(RehashReason.PARAMETERS_OUTDATED));
    assertEquals(new RehashDecision.Required(RehashReason.PARAMETERS_OUTDATED, 1),
        hinted.needsRehash(encoded));
  }

  @Test
  @DisplayName("a hint that fails is logged and treated as none; needsRehash does not throw")
  void failingHintIsNoHint() {
    DefaultPasswordHashingService failing = service(envelope -> {
      throw new IllegalStateException("synthetic hint failure");
    });
    String encoded = failing.hash("Correct-Horse-1".toCharArray()).encodedHash();

    assertSame(RehashDecision.NotRequired.INSTANCE, failing.needsRehash(encoded));
  }

  private static DefaultPasswordHashingService service(
      Function<PasswordHashEnvelope, Optional<RehashReason>> hint) {
    PasswordHashPolicy policy = fastPolicy();
    PasswordHashProviderRegistry registry =
        new PasswordHashProviderRegistry(List.of(new HintingProvider(hint)));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(
            new PasswordHashParameterValidatorRegistry(List.of(new Pbkdf2ParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        policy,
        new RehashDecisionEngine(),
        NoLimitKdfExecutionLimiter.INSTANCE,
        new DefaultDummyVerificationService(registry, policy, PasswordHashCodec.DEFAULT));
  }

  private static PasswordHashPolicy fastPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  /** The real PBKDF2 provider with a rehash hint of the test's choosing. */
  private static final class HintingProvider implements PasswordHashProvider {
    private final Pbkdf2PasswordHashProvider delegate = new Pbkdf2PasswordHashProvider();
    private final Function<PasswordHashEnvelope, Optional<RehashReason>> hint;

    HintingProvider(Function<PasswordHashEnvelope, Optional<RehashReason>> hint) {
      this.hint = hint;
    }

    @Override
    public String providerId() {
      return delegate.providerId();
    }

    @Override
    public String algorithm() {
      return delegate.algorithm();
    }

    @Override
    public PasswordHashResult hash(char[] password, PasswordHashPolicy policy,
                                   Optional<PepperReference> pepper) {
      return delegate.hash(password, policy, pepper);
    }

    @Override
    public ProviderVerificationResult verify(char[] password, PasswordHashEnvelope envelope,
                                             Optional<PepperReference> pepper) {
      return delegate.verify(password, envelope, pepper);
    }

    @Override
    public Optional<RehashReason> rehashHint(PasswordHashEnvelope envelope) {
      return hint.apply(envelope);
    }
  }
}
