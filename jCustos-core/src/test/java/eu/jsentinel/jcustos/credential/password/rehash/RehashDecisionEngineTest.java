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
package eu.jsentinel.jcustos.credential.password.rehash;

import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class RehashDecisionEngineTest {

  private final RehashDecisionEngine engine = new RehashDecisionEngine();

  private static Map<String, String> currentParams() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.DEFAULT_ITERATIONS));
    m.put(Pbkdf2ParameterNames.KEY_LENGTH,
        Integer.toString(Pbkdf2Defaults.DEFAULT_KEY_LENGTH));
    m.put(Pbkdf2ParameterNames.SALT, "ZGVhZGJlZWY=");
    return m;
  }

  private static PasswordHashEnvelope envelope(
      String algorithm, String providerId,
      int policyVersion, Map<String, String> params) {
    return new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        algorithm,
        providerId,
        policyVersion,
        Optional.empty(),
        params,
        "ZGVyaXZlZA=="
    );
  }

  @Test
  @DisplayName("Envelope matching the active policy needs no rehash")
  void noRehashWhenAligned() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    PasswordHashEnvelope env = envelope(
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        policy.policyVersion(),
        currentParams());
    assertSame(RehashDecision.NotRequired.INSTANCE, engine.decide(env, policy));
  }

  @Test
  @DisplayName("Deprecated algorithm wins precedence over other rehash triggers")
  void algorithmDeprecatedHasHighestPrecedence() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    Map<String, String> oldParams = new LinkedHashMap<>(currentParams());
    oldParams.put(Pbkdf2ParameterNames.ITERATIONS, "210000");
    PasswordHashEnvelope env = envelope(
        "OldAlg", Pbkdf2ParameterNames.PROVIDER_ID, 1, oldParams);
    RehashDecision.Required r = assertInstanceOf(
        RehashDecision.Required.class, engine.decide(env, policy));
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, r.reason());
    assertEquals(policy.policyVersion(), r.targetPolicyVersion());
  }

  @Test
  @DisplayName("Same algorithm but different provider id triggers PROVIDER_DEPRECATED")
  void differentProviderTriggersProviderDeprecated() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    PasswordHashEnvelope env = envelope(
        Pbkdf2ParameterNames.ALGORITHM, "other-provider",
        policy.policyVersion(), currentParams());
    RehashDecision.Required r = assertInstanceOf(
        RehashDecision.Required.class, engine.decide(env, policy));
    assertEquals(RehashReason.PROVIDER_DEPRECATED, r.reason());
  }

  @Test
  @DisplayName("Older policy version triggers POLICY_VERSION_OUTDATED")
  void olderPolicyVersionRequiresRehash() {
    PasswordHashPolicy policy = DefaultPasswordHashPolicy.builder()
        .policyVersion(5)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM,
            Pbkdf2Defaults.maximumParameters())
        .build();
    PasswordHashEnvelope env = envelope(
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        2, currentParams());
    RehashDecision.Required r = assertInstanceOf(
        RehashDecision.Required.class, engine.decide(env, policy));
    assertEquals(RehashReason.POLICY_VERSION_OUTDATED, r.reason());
    assertEquals(5, r.targetPolicyVersion());
  }

  @Test
  @DisplayName("Iterations below the policy default trigger PARAMETERS_OUTDATED")
  void iterationsBelowDefaultRequireRehash() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    Map<String, String> params = new LinkedHashMap<>(currentParams());
    params.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.DEFAULT_ITERATIONS - 1));
    PasswordHashEnvelope env = envelope(
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        policy.policyVersion(), params);
    RehashDecision.Required r = assertInstanceOf(
        RehashDecision.Required.class, engine.decide(env, policy));
    assertEquals(RehashReason.PARAMETERS_OUTDATED, r.reason());
  }

  @Test
  @DisplayName("Decision is deterministic across repeated calls")
  void decisionIsDeterministic() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    Map<String, String> params = new LinkedHashMap<>(currentParams());
    params.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(Pbkdf2Defaults.DEFAULT_ITERATIONS - 1));
    PasswordHashEnvelope env = envelope(
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        policy.policyVersion(), params);
    assertEquals(engine.decide(env, policy), engine.decide(env, policy));
  }

  @Test
  @DisplayName("JS-SEC-133: a provider hint makes an envelope that matches the policy Required, with the provider's reason")
  void providerHintRequiresRehash() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    PasswordHashEnvelope env = envelope(
        Pbkdf2ParameterNames.ALGORITHM, Pbkdf2ParameterNames.PROVIDER_ID,
        policy.policyVersion(), currentParams());

    assertSame(RehashDecision.NotRequired.INSTANCE,
        engine.decide(env, policy, Optional.empty(), Optional.empty()));
    RehashDecision.Required r = assertInstanceOf(RehashDecision.Required.class,
        engine.decide(env, policy, Optional.empty(), Optional.of(RehashReason.PARAMETERS_OUTDATED)));
    assertEquals(RehashReason.PARAMETERS_OUTDATED, r.reason());
    assertEquals(policy.policyVersion(), r.targetPolicyVersion());
  }

  @Test
  @DisplayName("JS-SEC-133: the policy's own reasons keep precedence over a provider hint, which precedes pepper rotation")
  void providerHintPrecedence() {
    PasswordHashPolicy policy = Pbkdf2Defaults.referencePolicy();
    PasswordHashEnvelope deprecated = envelope(
        "OldAlg", Pbkdf2ParameterNames.PROVIDER_ID, policy.policyVersion(), currentParams());
    assertEquals(RehashReason.ALGORITHM_DEPRECATED, assertInstanceOf(RehashDecision.Required.class,
        engine.decide(deprecated, policy, Optional.empty(),
            Optional.of(RehashReason.PARAMETERS_OUTDATED))).reason());

    PasswordHashEnvelope current = envelope(
        Pbkdf2ParameterNames.ALGORITHM, Pbkdf2ParameterNames.PROVIDER_ID,
        policy.policyVersion(), currentParams());
    assertEquals(RehashReason.FORMAT_VERSION_OUTDATED, assertInstanceOf(RehashDecision.Required.class,
        engine.decide(current, policy, Optional.of("pepper-2"),
            Optional.of(RehashReason.FORMAT_VERSION_OUTDATED))).reason(),
        "the hint is reported, not the pepper rotation behind it");
  }
}
