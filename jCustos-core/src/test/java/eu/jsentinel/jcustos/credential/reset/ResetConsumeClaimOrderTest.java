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
import eu.jsentinel.jcustos.credential.change.CredentialChangeListener;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-128 (CWE-367, CWE-640): {@code consume} claims the token before it
 * writes the password, so one link writes at most one password.
 */
@DisplayName("JS-SEC-128 — a reset link is claimed before the password is written")
class ResetConsumeClaimOrderTest {

  private static final Duration TTL = Duration.ofMinutes(15);

  /**
   * The real credential store behind a wrapper that counts successful hash
   * writes and runs a hook at chosen points of the store protocol — the
   * deterministic stand-in for a second request scheduled exactly there.
   */
  private static final class InterleavingCredentialStore implements CredentialStore {
    final CredentialStore real;
    final AtomicInteger hashWrites = new AtomicInteger();
    final AtomicReference<Runnable> afterHashWrite = new AtomicReference<>();
    volatile boolean refuseHashWrite;

    InterleavingCredentialStore(CredentialStore real) {
      this.real = real;
    }

    @Override
    public Optional<CredentialRecord> findByUsername(String username) {
      return real.findByUsername(username);
    }

    @Override
    public CredentialUpdateResult updateHashIfCurrent(
        String username, String expected, String next, Instant when) {
      if (refuseHashWrite) {
        return CredentialUpdateResult.Stale.INSTANCE;
      }
      CredentialUpdateResult result = real.updateHashIfCurrent(username, expected, next, when);
      if (result instanceof CredentialUpdateResult.Updated) {
        hashWrites.incrementAndGet();
        Runnable hook = afterHashWrite.getAndSet(null);
        if (hook != null) {
          hook.run();
        }
      }
      return result;
    }

    @Override
    public CredentialUpdateResult updateStatusIfCurrent(
        String username, CredentialStatus expected, CredentialStatus next, Instant when) {
      return real.updateStatusIfCurrent(username, expected, next, when);
    }
  }

  private static PasswordResetService service(CredentialTestKit kit, CredentialStore store) {
    return new PasswordResetService(store, kit.resetTokens, kit.digests, kit.hashing,
        kit.validator, kit.inputPolicy, kit.lifecycle(store), kit.clock, kit.audit);
  }

  private static String issue(PasswordResetService reset, String username) {
    return assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue(username, TTL)).token().encode();
  }

  @Test
  @DisplayName("a second consume running right after the first hash write fails; exactly one password is written")
  void oneTokenWritesOnePassword() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("carol", "carols old password", CredentialStatus.ACTIVE);
    InterleavingCredentialStore store = new InterleavingCredentialStore(kit.credentials);
    PasswordResetService reset = service(kit, store);
    String link = issue(reset, "carol");

    AtomicReference<PasswordResetConsumeResult> second = new AtomicReference<>();
    store.afterHashWrite.set(() -> second.set(
        reset.consume(link, SecretValue.ofString("second callers password"))));
    PasswordResetConsumeResult first =
        reset.consume(link, SecretValue.ofString("first callers password"));

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE, first);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE, second.get());
    assertEquals(1, store.hashWrites.get(), "one link must write exactly one password");
    assertTrue(kit.passwordIs("carol", "first callers password"));
    assertFalse(kit.passwordIs("carol", "second callers password"));
  }

  @Test
  @DisplayName("when the hash write fails after the claim, the link stays consumed")
  void failedWriteDoesNotReviveTheToken() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("carol", "carols old password", CredentialStatus.ACTIVE);
    InterleavingCredentialStore store = new InterleavingCredentialStore(kit.credentials);
    PasswordResetService reset = service(kit, store);
    String link = issue(reset, "carol");
    String selector = kit.digests.parse(link).orElseThrow().selector();

    store.refuseHashWrite = true;
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(link, SecretValue.ofString("a brand new password")));
    assertEquals(ResetTokenStatus.CONSUMED,
        kit.resetTokens.findBySelector(selector).orElseThrow().status());

    store.refuseHashWrite = false;
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(link, SecretValue.ofString("a brand new password")),
        "a link whose claim succeeded must not become usable again");
    assertTrue(kit.passwordIs("carol", "carols old password"));
  }

  @Test
  @DisplayName("a rejected new password does not spend the link")
  void policyViolationKeepsTheLink() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("carol", "carols old password", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit, kit.credentials);
    String link = issue(reset, "carol");

    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(link, SecretValue.ofString("short")));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString("a brand new password")),
        "validation runs before the claim; a typo must not cost the user the link");
  }

  @Test
  @DisplayName("the change listener is told about a consumed reset, once, and not about a failed one")
  void listenerIsCalledAfterConsume() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("carol", "carols old password", CredentialStatus.ACTIVE);
    List<String> calls = new ArrayList<>();
    PasswordResetService reset = service(kit, kit.credentials)
        .withCredentialChangeListener((username, cause, at) ->
            calls.add(username + "/" + cause + "/" + at));
    String link = issue(reset, "carol");

    reset.consume("not.a-token", SecretValue.ofString("a brand new password"));
    assertTrue(calls.isEmpty());

    kit.clock.advance(Duration.ofSeconds(2));
    reset.consume(link, SecretValue.ofString("a brand new password"));
    reset.consume(link, SecretValue.ofString("yet another password"));

    assertEquals(List.of("carol/" + CredentialChangeListener.Cause.PASSWORD_RESET + "/"
        + CredentialTestKit.T0.plusSeconds(2)), calls);
  }

  @Test
  @DisplayName("a throwing listener does not turn a completed reset into a failure")
  void throwingListenerDoesNotFailTheReset() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("carol", "carols old password", CredentialStatus.ACTIVE);
    PasswordResetService reset = service(kit, kit.credentials)
        .withCredentialChangeListener((username, cause, at) -> {
          throw new IllegalStateException("revocation backend down");
        });
    String link = issue(reset, "carol");

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString("a brand new password")));
    assertTrue(kit.passwordIs("carol", "a brand new password"));
  }
}
