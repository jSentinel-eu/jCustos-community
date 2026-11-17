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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link CompositeCompromisedPasswordChecker}: the local list first, the online
 * service second; the first hit wins, a failure counts as its
 * {@link CheckFailurePolicy} says. The second checker is a hand-written fake
 * standing in for the network service; the HIBP checker itself is exercised
 * against a loopback server in {@code jCustos-credentials-hibp}.
 */
@DisplayName("CompositeCompromisedPasswordChecker — local first, first hit wins, failures per policy")
class CompositeCompromisedPasswordCheckerTest {

  private final LocalBlocklistCompromisedPasswordChecker local =
      LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.of("password", "letmein"));

  /** Answers a fixed verdict and counts the calls. */
  private static final class FixedChecker implements CompromisedPasswordChecker {
    private final CompromisedPasswordResult verdict;
    private final AtomicInteger calls = new AtomicInteger();

    FixedChecker(CompromisedPasswordResult verdict) {
      this.verdict = verdict;
    }

    @Override
    public CompromisedPasswordResult check(SecretValue password) {
      calls.incrementAndGet();
      return verdict;
    }
  }

  private static CompromisedPasswordResult.CheckFailed failed() {
    return new CompromisedPasswordResult.CheckFailed(
        CompromisedPasswordResult.FailureReason.NETWORK);
  }

  private static SecretValue secret(String value) {
    return SecretValue.ofString(value);
  }

  @Test
  @DisplayName("a hit in the local list is returned at once; the online checker is not asked")
  void localHitShortCircuits() {
    FixedChecker online = new FixedChecker(CompromisedPasswordResult.Clean.INSTANCE);
    CompositeCompromisedPasswordChecker composite =
        CompositeCompromisedPasswordChecker.of(CheckFailurePolicy.BLOCK, local, online);

    assertInstanceOf(CompromisedPasswordResult.Pwned.class, composite.check(secret("LetMeIn")));
    assertEquals(0, online.calls.get(), "a common password must not reach the network");
  }

  @Test
  @DisplayName("a password the local list does not know is asked online; the online hit wins")
  void onlineHitWins() {
    FixedChecker online = new FixedChecker(new CompromisedPasswordResult.Pwned(42L));
    CompromisedPasswordResult verdict = CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.ALLOW, local, online).check(secret("Tangerine-Harbour-Kite-77"));

    assertEquals(42L, assertInstanceOf(CompromisedPasswordResult.Pwned.class, verdict).occurrences());
    assertEquals(1, online.calls.get());
  }

  @Test
  @DisplayName("an online failure: ALLOW and WARN count it as clean, BLOCK returns the failure")
  void onlineFailureFollowsThePolicy() {
    FixedChecker online = new FixedChecker(failed());

    assertSame(CompromisedPasswordResult.Clean.INSTANCE, CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.ALLOW, local, online).check(secret("Glacier-Lantern-Orbit-42")));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE, CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.WARN, local, online).check(secret("Glacier-Lantern-Orbit-42")));
    CompromisedPasswordResult blocked = CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.BLOCK, local, online).check(secret("Glacier-Lantern-Orbit-42"));
    assertEquals(CompromisedPasswordResult.FailureReason.NETWORK,
        assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, blocked).reason());
  }

  @Test
  @DisplayName("a failure does not stop the chain: a later hit outweighs it")
  void laterHitOutweighsAnEarlierFailure() {
    FixedChecker failing = new FixedChecker(failed());
    FixedChecker listing = new FixedChecker(new CompromisedPasswordResult.Pwned(7L));

    assertInstanceOf(CompromisedPasswordResult.Pwned.class, CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.BLOCK, failing, listing).check(secret("anything-unlisted")));
    assertEquals(1, listing.calls.get());
  }

  @Test
  @DisplayName("a checker that throws or answers null gave no verdict")
  void throwingOrSilentCheckerCountsAsFailed() {
    CompromisedPasswordChecker throwing = password -> {
      throw new IllegalStateException("boom");
    };
    CompromisedPasswordChecker silent = password -> null;

    CompromisedPasswordResult afterThrow = CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.BLOCK, local, throwing).check(secret("unlisted-and-long"));
    assertEquals(CompromisedPasswordResult.FailureReason.UNKNOWN,
        assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, afterThrow).reason());
    assertInstanceOf(CompromisedPasswordResult.CheckFailed.class, CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.BLOCK, local, silent).check(secret("unlisted-and-long")));
    assertSame(CompromisedPasswordResult.Clean.INSTANCE, CompositeCompromisedPasswordChecker
        .of(CheckFailurePolicy.ALLOW, local, throwing).check(secret("unlisted-and-long")));
  }

  @Test
  @DisplayName("a composite needs at least one checker and no null element")
  void invariants() {
    assertThrows(IllegalArgumentException.class,
        () -> CompositeCompromisedPasswordChecker.of(CheckFailurePolicy.ALLOW, List.of()));
    assertThrows(NullPointerException.class,
        () -> CompositeCompromisedPasswordChecker.of(null, local));
    assertThrows(NullPointerException.class,
        () -> CompositeCompromisedPasswordChecker.of(CheckFailurePolicy.ALLOW, local,
            (CompromisedPasswordChecker) null));
    assertEquals(CheckFailurePolicy.WARN,
        CompositeCompromisedPasswordChecker.of(CheckFailurePolicy.WARN, local).onFailure());
  }
}
