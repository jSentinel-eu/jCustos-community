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

import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.compromised.CheckFailurePolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordPolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.input.PasswordInputViolation;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
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
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NIST SP 800-63B §5.1.1.2 (CWE-521): a password change refuses a new password
 * that the configured compromised-password check lists, before any KDF run and
 * whatever the current password is (CWE-203).
 *
 * <p>Real stores and the real hashing pipeline; the KDF limiter is a
 * hand-written counter, so the test sees whether a verification or a hash
 * ran.</p>
 */
@DisplayName("Password blocklists — the change service refuses a listed new password before the KDF")
class PasswordChangeCompromisedPasswordTest {

  private static final String CURRENT = "correct horse battery";
  private static final String LISTED = "Sommer2026!";

  /** Counts the KDF permits it hands out; never refuses. */
  private static final class CountingLimiter implements KdfExecutionLimiter {
    final AtomicInteger leases = new AtomicInteger();

    @Override
    public Optional<Lease> acquire() {
      leases.incrementAndGet();
      return Optional.of(() -> { });
    }
  }

  private final CredentialTestKit kit = new CredentialTestKit();
  private final CountingLimiter kdf = new CountingLimiter();
  /** Same policy as the kit's service, so both read each other's hashes; this one counts. */
  private final PasswordHashingService counted = PasswordHashingServices.defaults(fastPolicy(), kdf);
  private final LocalBlocklistCompromisedPasswordChecker blocklist =
      LocalBlocklistCompromisedPasswordChecker.fromLines(
          Stream.of("# synthetic list", LISTED, "password123"));
  private final List<String> notified = new ArrayList<>();

  private PasswordChangeService plainService() {
    return new PasswordChangeService(kit.credentials, counted, kit.validator,
        kit.inputPolicy, kit.lifecycle(), kit.clock)
        .withCredentialChangeListener((username, cause, at) -> notified.add(username));
  }

  private PasswordChangeService checkingService(CompromisedPasswordChecker checker,
                                                CompromisedPasswordPolicy policy) {
    return plainService().withCompromisedPasswordCheck(checker, policy);
  }

  private static PasswordChangeCommand command(String current, String next) {
    return new PasswordChangeCommand(
        "alice", SecretValue.ofString(current), SecretValue.ofString(next));
  }

  private static CompromisedPasswordChecker failing() {
    return password -> new CompromisedPasswordResult.CheckFailed(
        CompromisedPasswordResult.FailureReason.NETWORK);
  }

  @Test
  @DisplayName("a listed new password: NewPasswordRejected(COMPROMISED), store unchanged, no KDF run")
  void listedPasswordIsRefusedBeforeTheKdf() {
    String stored = kit.register("alice", CURRENT, CredentialStatus.ACTIVE);
    PasswordChangeService change =
        checkingService(blocklist, CompromisedPasswordPolicy.defaults());

    PasswordChangeResult result = change.change(command(CURRENT, LISTED));

    assertEquals(PasswordInputViolation.COMPROMISED,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class, result).violation());
    assertEquals(stored, kit.credentials.findByUsername("alice").orElseThrow().encodedHash());
    assertEquals(0, kdf.leases.get(), "neither the verification nor a hash may run");
    assertTrue(notified.isEmpty(), "nothing changed, so nothing may be revoked");
  }

  @Test
  @DisplayName("the full-width spelling of a listed password is refused as well")
  void fullWidthVariantIsRefused() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);

    PasswordChangeResult result = checkingService(blocklist, CompromisedPasswordPolicy.defaults())
        .change(command(CURRENT, "ｓｏｍｍｅｒ２０２６！"));

    assertEquals(PasswordInputViolation.COMPROMISED,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class, result).violation());
    assertTrue(kit.passwordIs("alice", CURRENT));
  }

  @Test
  @DisplayName("a wrong current password with a listed new one: the same answer - no oracle for the current password")
  void listedPasswordGivesNoOracle() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);
    PasswordChangeService change =
        checkingService(blocklist, CompromisedPasswordPolicy.defaults());

    PasswordChangeResult right = change.change(command(CURRENT, LISTED));
    PasswordChangeResult wrong = change.change(command("a guess of the password", LISTED));

    assertEquals(right, wrong, "the answer must not depend on the current password");
    assertEquals(0, kdf.leases.get());
  }

  @Test
  @DisplayName("structure first (ER56): a wrong current password with a too-short new one is TOO_SHORT, without a KDF run")
  void structuralCheckRunsBeforeTheVerification() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);

    PasswordChangeResult result = plainService().change(command("a guess of the password", "ab"));

    assertEquals(PasswordInputViolation.TOO_SHORT,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class, result).violation());
    assertEquals(0, kdf.leases.get(), "no KDF permit for a request the free check refuses");
  }

  @Test
  @DisplayName("an unlisted new password is changed: one verification, one hash")
  void unlistedPasswordIsChanged() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);

    PasswordChangeResult result = checkingService(blocklist, CompromisedPasswordPolicy.defaults())
        .change(command(CURRENT, "Glacier-Lantern-Orbit-42"));

    assertInstanceOf(PasswordChangeResult.Succeeded.class, result);
    assertTrue(kit.passwordIs("alice", "Glacier-Lantern-Orbit-42"));
    assertEquals(2, kdf.leases.get());
    assertEquals(List.of("alice"), notified);
  }

  @Test
  @DisplayName("without a configured check nothing changes: the listed password is accepted")
  void withoutACheckTheListedPasswordIsAccepted() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        plainService().change(command(CURRENT, LISTED)));
    assertTrue(kit.passwordIs("alice", LISTED));
  }

  @Test
  @DisplayName("checkOnSetOrChange=false: the checker is not asked")
  void disabledPolicyDoesNotAsk() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);
    AtomicInteger asked = new AtomicInteger();
    CompromisedPasswordChecker counting = password -> {
      asked.incrementAndGet();
      return new CompromisedPasswordResult.Pwned(1L);
    };

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        checkingService(counting, CompromisedPasswordPolicy.disabled())
            .change(command(CURRENT, "Glacier-Lantern-Orbit-42")));
    assertEquals(0, asked.get());
  }

  @Test
  @DisplayName("a check that fails under BLOCK: VerificationUnavailable, store unchanged, no KDF run")
  void failedCheckUnderBlockIsTryAgainLater() {
    String stored = kit.register("alice", CURRENT, CredentialStatus.ACTIVE);

    PasswordChangeResult result = checkingService(failing(), CompromisedPasswordPolicy.failClosed())
        .change(command(CURRENT, "Glacier-Lantern-Orbit-42"));

    assertSame(PasswordChangeResult.VerificationUnavailable.INSTANCE, result,
        "a check that was not carried out is no verdict on the password");
    assertEquals(stored, kit.credentials.findByUsername("alice").orElseThrow().encodedHash());
    assertEquals(0, kdf.leases.get());
    assertTrue(notified.isEmpty());
  }

  @Test
  @DisplayName("a check that fails under ALLOW or WARN lets the change proceed")
  void failedCheckUnderAllowProceeds() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        checkingService(failing(), CompromisedPasswordPolicy.defaults())
            .change(command(CURRENT, "Glacier-Lantern-Orbit-42")));
    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        checkingService(failing(), new CompromisedPasswordPolicy(true, false, CheckFailurePolicy.WARN))
            .change(command("Glacier-Lantern-Orbit-42", "Harbour-Quartz-Meadow-19")));
    assertTrue(kit.passwordIs("alice", "Harbour-Quartz-Meadow-19"));
  }

  @Test
  @DisplayName("the check survives the other with-copies, in either order, and they survive it")
  void checkSurvivesTheOtherCopies() {
    kit.register("alice", CURRENT, CredentialStatus.ACTIVE);
    PasswordResetService reset = new PasswordResetService(kit.credentials, kit.resetTokens,
        kit.digests, kit.hashing, kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock,
        kit.audit);
    String link = assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", Duration.ofMinutes(15))).token().encode();

    PasswordChangeService checkFirst = new PasswordChangeService(kit.credentials, counted,
        kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock)
        .withCompromisedPasswordCheck(blocklist, CompromisedPasswordPolicy.defaults())
        .withResetTokenStore(kit.resetTokens)
        .withCredentialChangeListener((username, cause, at) -> notified.add(username));
    PasswordChangeService checkLast = new PasswordChangeService(kit.credentials, counted,
        kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock)
        .withResetTokenStore(kit.resetTokens)
        .withCredentialChangeListener((username, cause, at) -> notified.add(username))
        .withCompromisedPasswordCheck(blocklist, CompromisedPasswordPolicy.defaults());

    assertEquals(PasswordInputViolation.COMPROMISED,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class,
            checkFirst.change(command(CURRENT, LISTED))).violation(),
        "the check set before the other copies is kept");
    assertEquals(PasswordInputViolation.COMPROMISED,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class,
            checkLast.change(command(CURRENT, LISTED))).violation());

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        checkLast.change(command(CURRENT, "Glacier-Lantern-Orbit-42")));
    assertEquals(List.of("alice"), notified, "the listener set before the check is kept");
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(link, SecretValue.ofString("password from the link")),
        "the reset store set before the check is kept: the change retired the open link");
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
