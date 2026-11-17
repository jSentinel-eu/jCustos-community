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
package eu.jsentinel.jcustos.credential.compromised;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CompromisedPasswordScreen}: the step the password services run for a
 * new password - the checker's verdict under the {@link CompromisedPasswordPolicy}.
 */
@DisplayName("CompromisedPasswordScreen — listed, accepted, or unavailable under BLOCK")
class CompromisedPasswordScreenTest {

  private final LocalBlocklistCompromisedPasswordChecker local =
      LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.of("password"));

  private static final CompromisedPasswordChecker FAILING = password ->
      new CompromisedPasswordResult.CheckFailed(CompromisedPasswordResult.FailureReason.TIMEOUT);

  private static SecretValue secret(String value) {
    return SecretValue.ofString(value);
  }

  @Test
  @DisplayName("a listed password is LISTED, an unlisted one ACCEPTED")
  void listedAndAccepted() {
    CompromisedPasswordScreen screen =
        new CompromisedPasswordScreen(local, CompromisedPasswordPolicy.defaults());
    assertEquals(CompromisedPasswordScreen.Outcome.LISTED, screen.screen(secret("PASSWORD")));
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED,
        screen.screen(secret("Glacier-Lantern-Orbit-42")));
  }

  @Test
  @DisplayName("a failed check: ALLOW and WARN accept, BLOCK is UNAVAILABLE - never LISTED")
  void failedCheckFollowsThePolicy() {
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED,
        new CompromisedPasswordScreen(FAILING, CompromisedPasswordPolicy.defaults())
            .screen(secret("password")));
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED,
        new CompromisedPasswordScreen(FAILING,
            new CompromisedPasswordPolicy(true, false, CheckFailurePolicy.WARN))
            .screen(secret("password")));
    assertEquals(CompromisedPasswordScreen.Outcome.UNAVAILABLE,
        new CompromisedPasswordScreen(FAILING, CompromisedPasswordPolicy.failClosed())
            .screen(secret("password")));
  }

  @Test
  @DisplayName("a checker that throws or answers null counts as a failed check")
  void throwingOrSilentChecker() {
    CompromisedPasswordChecker throwing = password -> {
      throw new IllegalStateException("boom");
    };
    assertEquals(CompromisedPasswordScreen.Outcome.UNAVAILABLE,
        new CompromisedPasswordScreen(throwing, CompromisedPasswordPolicy.failClosed())
            .screen(secret("x")));
    assertEquals(CompromisedPasswordScreen.Outcome.UNAVAILABLE,
        new CompromisedPasswordScreen(password -> null, CompromisedPasswordPolicy.failClosed())
            .screen(secret("x")));
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED,
        new CompromisedPasswordScreen(throwing, CompromisedPasswordPolicy.defaults())
            .screen(secret("x")));
  }

  @Test
  @DisplayName("checkOnSetOrChange=false and the NoOp checker never ask; none() is inactive")
  void inactiveScreensDoNotAsk() {
    AtomicInteger calls = new AtomicInteger();
    CompromisedPasswordChecker counting = password -> {
      calls.incrementAndGet();
      return new CompromisedPasswordResult.Pwned(1L);
    };
    CompromisedPasswordScreen disabled =
        new CompromisedPasswordScreen(counting, CompromisedPasswordPolicy.disabled());
    assertFalse(disabled.isActive());
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED, disabled.screen(secret("password")));
    assertEquals(0, calls.get());

    assertFalse(new CompromisedPasswordScreen(NoOpCompromisedPasswordChecker.INSTANCE,
        CompromisedPasswordPolicy.failClosed()).isActive());
    assertFalse(CompromisedPasswordScreen.none().isActive());
    assertEquals(CompromisedPasswordScreen.Outcome.ACCEPTED,
        CompromisedPasswordScreen.none().screen(secret("password")));
    assertTrue(new CompromisedPasswordScreen(counting, CompromisedPasswordPolicy.defaults())
        .isActive());
  }
}
