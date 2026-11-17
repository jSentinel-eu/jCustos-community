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

import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.compromised.CheckFailurePolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordPolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordScreen;
import eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.token.SelectorVerifierToken;
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
 * NIST SP 800-63B §5.1.1.2 (CWE-521): a password reset refuses a new password
 * that the configured compromised-password check lists - before the token is
 * claimed and before anything is hashed, so the link stays usable.
 *
 * <p>Real stores and the real hashing pipeline; the KDF limiter is a
 * hand-written counter.</p>
 */
@DisplayName("Password blocklists — the reset service refuses a listed new password and keeps the link")
class PasswordResetCompromisedPasswordTest {

  private static final String LISTED = "Sommer2026!";
  private static final String FRESH = "Glacier-Lantern-Orbit-42";

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
      LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.of(LISTED, "password123"));
  private final List<String> notified = new ArrayList<>();

  private PasswordResetService plainService() {
    return new PasswordResetService(kit.credentials, kit.resetTokens, kit.digests, counted,
        kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock, kit.audit)
        .withCredentialChangeListener((username, cause, at) -> notified.add(username));
  }

  private PasswordResetService checkingService(CompromisedPasswordChecker checker,
                                               CompromisedPasswordPolicy policy) {
    return plainService().withCompromisedPasswordCheck(checker, policy);
  }

  private static SelectorVerifierToken issue(PasswordResetService reset) {
    return assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue("alice", Duration.ofMinutes(15))).token();
  }

  private ResetTokenStatus status(SelectorVerifierToken token) {
    return kit.resetTokens.findBySelector(token.selector()).orElseThrow().status();
  }

  private static CompromisedPasswordChecker failing() {
    return password -> new CompromisedPasswordResult.CheckFailed(
        CompromisedPasswordResult.FailureReason.TIMEOUT);
  }

  @Test
  @DisplayName("a listed new password: Failed, store unchanged, no KDF run, the link stays ISSUED and works with another password")
  void listedPasswordIsRefusedAndTheLinkSurvives() {
    String stored = kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = checkingService(blocklist, CompromisedPasswordPolicy.defaults());
    SelectorVerifierToken token = issue(reset);

    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(token.encode(), SecretValue.ofString(LISTED)));

    assertEquals(stored, kit.credentials.findByUsername("alice").orElseThrow().encodedHash());
    assertEquals(0, kdf.leases.get(), "nothing may be hashed for a refused password");
    assertEquals(ResetTokenStatus.ISSUED, status(token), "the token must not be claimed");
    assertTrue(notified.isEmpty());

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(token.encode(), SecretValue.ofString(FRESH)));
    assertTrue(kit.passwordIs("alice", FRESH));
    assertEquals(List.of("alice"), notified);
  }

  @Test
  @DisplayName("the full-width spelling of a listed password is refused as well")
  void fullWidthVariantIsRefused() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = checkingService(blocklist, CompromisedPasswordPolicy.defaults());
    SelectorVerifierToken token = issue(reset);

    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(token.encode(), SecretValue.ofString("ＳＯＭＭＥＲ２０２６！")));
    assertTrue(kit.passwordIs("alice", "correct horse battery"));
    assertEquals(ResetTokenStatus.ISSUED, status(token));
  }

  @Test
  @DisplayName("the screen an adapter runs first names the reason the consume does not give")
  void adapterLearnsTheReasonFromTheScreen() {
    CompromisedPasswordScreen screen =
        new CompromisedPasswordScreen(blocklist, CompromisedPasswordPolicy.defaults());
    assertEquals(CompromisedPasswordScreen.Outcome.LISTED, screen.screen(SecretValue.ofString(LISTED)));
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED, screen.screen(SecretValue.ofString(FRESH)));
  }

  @Test
  @DisplayName("without a configured check nothing changes: the listed password is set")
  void withoutACheckTheListedPasswordIsSet() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = plainService();

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(issue(reset).encode(), SecretValue.ofString(LISTED)));
    assertTrue(kit.passwordIs("alice", LISTED));
  }

  @Test
  @DisplayName("a check that fails under BLOCK: Failed, nothing hashed, the link stays usable")
  void failedCheckUnderBlockKeepsTheLink() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService blocking = checkingService(failing(), CompromisedPasswordPolicy.failClosed());
    SelectorVerifierToken token = issue(blocking);

    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        blocking.consume(token.encode(), SecretValue.ofString(FRESH)));
    assertEquals(0, kdf.leases.get());
    assertEquals(ResetTokenStatus.ISSUED, status(token));

    // The check is back (here: a service with a list that answers): the same link works.
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        checkingService(blocklist, CompromisedPasswordPolicy.failClosed())
            .consume(token.encode(), SecretValue.ofString(FRESH)));
  }

  @Test
  @DisplayName("a check that fails under ALLOW or WARN lets the reset proceed")
  void failedCheckUnderAllowProceeds() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService allowing = checkingService(failing(), CompromisedPasswordPolicy.defaults());
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        allowing.consume(issue(allowing).encode(), SecretValue.ofString(FRESH)));

    PasswordResetService warning = checkingService(failing(),
        new CompromisedPasswordPolicy(true, false, CheckFailurePolicy.WARN));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        warning.consume(issue(warning).encode(), SecretValue.ofString("Harbour-Quartz-Meadow-19")));
    assertTrue(kit.passwordIs("alice", "Harbour-Quartz-Meadow-19"));
  }

  @Test
  @DisplayName("the check survives the other with-copies, and they survive it")
  void checkSurvivesTheOtherCopies() {
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService checkFirst = new PasswordResetService(kit.credentials, kit.resetTokens,
        kit.digests, counted, kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock,
        kit.audit)
        .withCompromisedPasswordCheck(blocklist, CompromisedPasswordPolicy.defaults())
        .withCredentialChangeListener((username, cause, at) -> notified.add(username));

    SelectorVerifierToken token = issue(checkFirst);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        checkFirst.consume(token.encode(), SecretValue.ofString(LISTED)),
        "the check set before the listener is kept");
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        checkFirst.consume(token.encode(), SecretValue.ofString(FRESH)));
    assertEquals(List.of("alice"), notified);

    // plainService() sets the listener first; the check comes last.
    PasswordResetService checkLast = checkingService(blocklist, CompromisedPasswordPolicy.defaults());
    SelectorVerifierToken second = issue(checkLast);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        checkLast.consume(second.encode(), SecretValue.ofString("password123")));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        checkLast.consume(second.encode(), SecretValue.ofString("Harbour-Quartz-Meadow-19")));
    assertEquals(List.of("alice", "alice"), notified, "the listener set before the check is kept");
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
