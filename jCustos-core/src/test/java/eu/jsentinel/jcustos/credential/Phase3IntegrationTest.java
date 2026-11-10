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
package eu.jsentinel.jcustos.credential;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.change.PasswordChangeCommand;
import eu.jsentinel.jcustos.credential.change.PasswordChangeResult;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.change.SessionHandlingDecision;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.reset.InMemoryResetTokenStore;
import eu.jsentinel.jcustos.credential.reset.PasswordResetConsumeResult;
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenCreationResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import eu.jsentinel.jcustos.credential.token.TokenDigestService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end Phase-3 wiring: PasswordHashingService + CredentialStore +
 * LifecycleService + PasswordChangeService + PasswordResetService +
 * TokenDigestService working together exactly as a demo adapter would.
 *
 * <p>Demonstrates the integration pattern security-core expects from
 * the Vaadin / REST / Standalone demos. The demo modules themselves
 * stay on the existing in-memory shortcut for now; the architectural
 * proof lives here.</p>
 */
class Phase3IntegrationTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");
  private static final Duration TTL = Duration.ofMinutes(15);

  private static final class RecordingAudit implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void publish(AuditEvent event) { events.add(event); }
    @Override public List<AuditEvent> query(AuditQuery q) { return List.copyOf(events); }
  }

  private static PasswordHashPolicy fastTestPolicy() {
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

  /** A complete Phase-3 wiring exactly as a demo adapter would assemble it. */
  private static final class DemoWiring {
    final InMemoryCredentialStore credentials = new InMemoryCredentialStore();
    final InMemoryResetTokenStore resetTokens = new InMemoryResetTokenStore();
    final PasswordHashingService hashingService = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    final PasswordInputValidator validator = new PasswordInputValidator();
    final PasswordInputPolicy inputPolicy = PasswordInputPolicy.defaults();
    final RecordingAudit audit = new RecordingAudit();
    final Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
    final CredentialLifecycleService lifecycle =
        new CredentialLifecycleService(credentials, audit, clock);
    final PasswordChangeService changeService = new PasswordChangeService(
        credentials, hashingService, validator, inputPolicy, lifecycle, clock);
    final TokenDigestService tokens = new TokenDigestService();
    final PasswordResetService resetService = new PasswordResetService(
        credentials, resetTokens, tokens, hashingService, validator,
        inputPolicy, lifecycle, clock);

    void register(String username, String password) {
      String encoded = hashingService.hash(password.toCharArray()).encodedHash();
      credentials.register(new CredentialRecord(
          username, encoded, CredentialStatus.ACTIVE, 1L, T0, T0));
    }

    boolean login(String username, String password) {
      return credentials.findByUsername(username)
          .map(r -> hashingService.verify(password.toCharArray(), r.encodedHash())
              instanceof CredentialVerificationResult.Verified)
          .orElse(false);
    }
  }

  @Test
  @DisplayName("Login succeeds against a freshly registered credential")
  void loginAfterRegister() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    assertTrue(d.login("alice", "hunter222"));
    assertEquals(false, d.login("alice", "wrong-password"));
  }

  @Test
  @DisplayName("Password change flow: old password no longer works, new password does")
  void passwordChangeFlow() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");

    PasswordChangeResult result = d.changeService.change(new PasswordChangeCommand(
        "alice",
        SecretValue.ofString("hunter222"),
        SecretValue.ofString("hunter222-new")));
    PasswordChangeResult.Succeeded ok = assertInstanceOf(
        PasswordChangeResult.Succeeded.class, result);
    assertEquals(SessionHandlingDecision.INVALIDATE_OTHER_SESSIONS,
        ok.sessionDecision());

    assertEquals(false, d.login("alice", "hunter222"));
    assertTrue(d.login("alice", "hunter222-new"));
  }

  @Test
  @DisplayName("Password change with wrong current password returns CurrentPasswordRejected")
  void passwordChangeRejectsWrongCurrent() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    assertSame(PasswordChangeResult.CurrentPasswordRejected.INSTANCE,
        d.changeService.change(new PasswordChangeCommand(
            "alice",
            SecretValue.ofString("not-the-password"),
            SecretValue.ofString("hunter222-new"))));
    // Original password still works.
    assertTrue(d.login("alice", "hunter222"));
  }

  @Test
  @DisplayName("Reset flow: issue token, consume, login with new password")
  void resetHappyPath() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");

    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        d.resetService.issue("alice", TTL);
    // JS-SEC-121 (CWE-645): an unauthenticated reset request no longer moves a
    // usable credential to RESET_PENDING; the reset runs alongside the login.
    assertEquals(CredentialStatus.ACTIVE,
        d.credentials.findByUsername("alice").orElseThrow().status());

    PasswordResetConsumeResult consume = d.resetService.consume(
        created.token().encode(), SecretValue.ofString("hunter222-reset"));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE, consume);

    assertEquals(false, d.login("alice", "hunter222"));
    assertTrue(d.login("alice", "hunter222-reset"));
    assertEquals(CredentialStatus.ACTIVE,
        d.credentials.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("Reset issue for unknown user returns UnknownUser; adapter must still surface a generic message")
  void resetUnknownUser() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    assertSame(ResetTokenCreationResult.UnknownUser.INSTANCE,
        d.resetService.issue("ghost", TTL));
  }

  @Test
  @DisplayName("Concurrent consume of the same reset token has exactly one winner (CWE-362 / CWE-640)")
  void concurrentResetConsumeSingleWinner() throws InterruptedException {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        d.resetService.issue("alice", TTL);
    String wire = created.token().encode();

    int threads = 6;
    CountDownLatch start = new CountDownLatch(1);
    AtomicInteger winners = new AtomicInteger();
    AtomicInteger losers = new AtomicInteger();
    Thread[] workers = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      workers[i] = new Thread(() -> {
        try {
          start.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          return;
        }
        PasswordResetConsumeResult r = d.resetService.consume(
            wire, SecretValue.ofString("hunter222-rotated"));
        if (r instanceof PasswordResetConsumeResult.Succeeded) {
          winners.incrementAndGet();
        } else {
          losers.incrementAndGet();
        }
      });
      workers[i].setDaemon(true);
      workers[i].start();
    }
    start.countDown();
    for (Thread w : workers) {
      w.join(10_000);
    }
    assertEquals(1, winners.get(), "exactly one consume must succeed");
    assertEquals(threads - 1, losers.get(),
        "every other attempt must surface the generic Failed");
    assertTrue(d.login("alice", "hunter222-rotated"));
  }

  @Test
  @DisplayName("MUST_CHANGE → ACTIVE transition runs after a successful password change")
  void mustChangeClearedAfterChange() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    d.lifecycle.transition("alice",
        CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE, "force-change");

    PasswordChangeResult result = d.changeService.change(new PasswordChangeCommand(
        "alice",
        SecretValue.ofString("hunter222"),
        SecretValue.ofString("hunter222-renewed")));
    assertInstanceOf(PasswordChangeResult.Succeeded.class, result);
    assertEquals(CredentialStatus.ACTIVE,
        d.credentials.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("Reset against a DISABLED account returns Blocked; credential stays DISABLED")
  void resetBlockedByDisabled() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    d.lifecycle.transition("alice",
        CredentialStatus.ACTIVE, CredentialStatus.DISABLED, "admin-disable");

    assertSame(ResetTokenCreationResult.Blocked.INSTANCE,
        d.resetService.issue("alice", TTL));
    assertEquals(CredentialStatus.DISABLED,
        d.credentials.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("Issuing a reset does NOT change the stored hash before the user consumes the token")
  void issueDoesNotChangeHash() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    String before = d.credentials.findByUsername("alice").orElseThrow().encodedHash();
    d.resetService.issue("alice", TTL);
    String after = d.credentials.findByUsername("alice").orElseThrow().encodedHash();
    assertEquals(before, after);
  }

  @Test
  @DisplayName("Replay of a stale token (after consumption) is rejected generically")
  void resetReplayRejected() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        d.resetService.issue("alice", TTL);
    String wire = created.token().encode();
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        d.resetService.consume(wire, SecretValue.ofString("hunter222-once")));
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        d.resetService.consume(wire, SecretValue.ofString("hunter222-twice")));
  }

  @Test
  @DisplayName("All Phase-3 result types redact secrets in toString")
  void noSecretsInToString() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        d.resetService.issue("alice", TTL);
    String tokenText = created.token().toString();
    char[] verifierChars = created.token().verifier().asChars();
    try {
      assertEquals(false, tokenText.contains(new String(verifierChars)));
    } finally {
      java.util.Arrays.fill(verifierChars, '\0');
    }
    assertTrue(tokenText.contains("<redacted>"));
    // PasswordChangeResult.toString neither leaks supplied passwords.
    PasswordChangeResult result = d.changeService.change(new PasswordChangeCommand(
        "alice",
        SecretValue.ofString("not-the-password"),
        SecretValue.ofString("new-very-secret-xyz")));
    assertEquals(false, result.toString().contains("new-very-secret-xyz"));
  }

  @Test
  @DisplayName("PasswordHashingService.verify on a wrong password leaves the credential untouched")
  void wrongPasswordKeepsCredentialIntact() {
    DemoWiring d = new DemoWiring();
    d.register("alice", "hunter222");
    String before = d.credentials.findByUsername("alice").orElseThrow().encodedHash();
    assertEquals(false, d.login("alice", "wrong"));
    String after = d.credentials.findByUsername("alice").orElseThrow().encodedHash();
    assertEquals(before, after);
    assertNotEquals("", before);
  }
}
