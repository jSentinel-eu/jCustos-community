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
package eu.jsentinel.jcustos.credential.change;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.reset.PasswordResetConsumeResult;
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenCreationResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-126 (CWE-703, CWE-645): a verification of the current password that
 * the KDF limiter shed is not a wrong password. The change service reports it
 * as {@link PasswordChangeResult.VerificationUnavailable} and touches nothing.
 *
 * <p>The limiter is the real {@link SemaphoreKdfExecutionLimiter} with one
 * permit; the test holds that permit, as a flood of verifications would.</p>
 */
@DisplayName("JS-SEC-126 — a shed verification of the current password is 'try again later', not 'wrong'")
class PasswordChangeVerificationUnavailableTest {

  private final SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
      new KdfResourceBudget(1, Duration.ofMillis(20)));
  private final CredentialTestKit kit = new CredentialTestKit();
  /** Same policy as the kit's service, so both read each other's hashes; this one is limited. */
  private final PasswordHashingService limited =
      PasswordHashingServices.defaults(fastPolicy(), limiter);
  private final List<String> notified = new ArrayList<>();

  private PasswordChangeService changeService() {
    return new PasswordChangeService(kit.credentials, limited, kit.validator,
        kit.inputPolicy, kit.lifecycle(), kit.clock)
        .withResetTokenStore(kit.resetTokens)
        .withCredentialChangeListener((username, cause, at) -> notified.add(username));
  }

  private static PasswordChangeCommand command(String current, String next) {
    return new PasswordChangeCommand(
        "alice", SecretValue.ofString(current), SecretValue.ofString(next));
  }

  @Test
  @DisplayName("the correct current password while the limiter is saturated: VerificationUnavailable, nothing changed, nothing audited; the retry succeeds")
  void shedVerificationIsNotAWrongPassword() {
    String storedHash = kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = new PasswordResetService(kit.credentials, kit.resetTokens,
        kit.digests, kit.hashing, kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock,
        kit.audit);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", Duration.ofMinutes(15))).token().encode();
    List<AuditEvent> auditedBefore = List.copyOf(kit.audit.events);
    PasswordChangeService change = changeService();

    PasswordChangeResult shed;
    try (KdfExecutionLimiter.Lease held = limiter.acquire().orElseThrow()) {
      shed = change.change(command("correct horse battery", "alices second password"));
    }

    assertSame(PasswordChangeResult.VerificationUnavailable.INSTANCE, shed,
        "a verification that was not carried out must not be reported as a rejected password");
    assertEquals(storedHash, kit.credentials.findByUsername("alice").orElseThrow().encodedHash());
    assertTrue(notified.isEmpty(), "nothing changed, so nothing may be revoked");
    assertEquals(auditedBefore, kit.audit.events, "the service must not audit a rejected password");

    // The permit is free again: the same command now changes the password ...
    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        change.change(command("correct horse battery", "alices second password")));
    assertTrue(kit.passwordIs("alice", "alices second password"));
    assertEquals(List.of("alice"), notified);
    // ... and only this completed change retired the open reset link.
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(link, SecretValue.ofString("password from the link")));
  }

  @Test
  @DisplayName("the shed attempt left the open reset link alone")
  void shedVerificationRetiresNoResetLink() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = new PasswordResetService(kit.credentials, kit.resetTokens,
        kit.digests, kit.hashing, kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock,
        kit.audit);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", Duration.ofMinutes(15))).token().encode();

    try (KdfExecutionLimiter.Lease held = limiter.acquire().orElseThrow()) {
      assertSame(PasswordChangeResult.VerificationUnavailable.INSTANCE,
          changeService().change(command("correct horse battery", "alices second password")));
    }

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString("password from the link")));
  }

  @Test
  @DisplayName("a wrong current password with a free limiter is still CurrentPasswordRejected")
  void wrongPasswordIsStillRejected() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);

    assertSame(PasswordChangeResult.CurrentPasswordRejected.INSTANCE,
        changeService().change(command("not alices password", "alices second password")));
    assertTrue(kit.passwordIs("alice", "correct horse battery"));
  }

  /** The cheap PBKDF2 policy of {@link CredentialTestKit}. */
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
}
