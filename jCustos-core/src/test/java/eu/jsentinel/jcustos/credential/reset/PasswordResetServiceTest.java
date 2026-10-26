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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.PasswordResetRequested;
import eu.jsentinel.jcustos.audit.PasswordResetCompleted;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import eu.jsentinel.jcustos.credential.token.SelectorVerifierToken;
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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordResetServiceTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");
  private static final Duration TTL = Duration.ofMinutes(15);

  private static final class RecordingAudit implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void publish(AuditEvent event) { events.add(event); }
    @Override public List<AuditEvent> query(AuditQuery q) { return List.copyOf(events); }
  }

  /** Mutable clock so tests can advance time across expiry. */
  private static final class MutableClock extends Clock {
    private final AtomicReference<Instant> now;

    MutableClock(Instant initial) {
      this.now = new AtomicReference<>(initial);
    }

    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId z) { return this; }
    @Override public Instant instant() { return now.get(); }

    void advance(Duration d) { now.updateAndGet(i -> i.plus(d)); }
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

  private static final class Fixture {
    final InMemoryCredentialStore credentials = new InMemoryCredentialStore();
    final InMemoryResetTokenStore tokens = new InMemoryResetTokenStore();
    final PasswordHashingService hashingService = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    final PasswordInputValidator validator = new PasswordInputValidator();
    final PasswordInputPolicy inputPolicy = PasswordInputPolicy.defaults();
    final RecordingAudit audit = new RecordingAudit();
    final MutableClock clock = new MutableClock(T0);
    final CredentialLifecycleService lifecycle =
        new CredentialLifecycleService(credentials, audit, clock);
    final TokenDigestService digestService = new TokenDigestService();
    final PasswordResetService service = new PasswordResetService(
        credentials, tokens, digestService, hashingService,
        validator, inputPolicy, lifecycle, clock, audit);

    String register(String username, String password, CredentialStatus status) {
      String encoded = hashingService.hash(password.toCharArray()).encodedHash();
      credentials.register(new CredentialRecord(
          username, encoded, status, 1L, T0, T0));
      return encoded;
    }
  }

  @Test
  @DisplayName("JS-SEC-074: a second issue retires the first link; issue and consume are audited")
  void issueRetiresOpenSiblingsAndAudits() {
    Fixture f = new Fixture();
    f.register("alice", "Old-Password-1", CredentialStatus.ACTIVE);
    ResetTokenCreationResult first = f.service.issue("alice", TTL);
    f.clock.advance(Duration.ofSeconds(1));
    ResetTokenCreationResult second = f.service.issue("alice", TTL);
    String firstWire = ((ResetTokenCreationResult.Created) first).token().encode();
    String secondWire = ((ResetTokenCreationResult.Created) second).token().encode();

    f.clock.advance(Duration.ofSeconds(1));
    assertInstanceOf(PasswordResetConsumeResult.Failed.class,
        f.service.consume(firstWire, SecretValue.ofChars("New-Password-1".toCharArray())),
        "the older link must be dead once a newer one was issued");
    assertInstanceOf(PasswordResetConsumeResult.Succeeded.class,
        f.service.consume(secondWire, SecretValue.ofChars("New-Password-1".toCharArray())));

    assertEquals(2, f.audit.events.stream().filter(PasswordResetRequested.class::isInstance).count(),
        "every issue is audited");
    assertEquals(1, f.audit.events.stream().filter(PasswordResetCompleted.class::isInstance).count(),
        "the completed reset is audited");
    PasswordResetCompleted completed = f.audit.events.stream()
        .filter(PasswordResetCompleted.class::isInstance).map(PasswordResetCompleted.class::cast).findFirst().orElseThrow();
    assertEquals("alice", completed.subjectId());
    assertEquals(((ResetTokenCreationResult.Created) second).token().selector(), completed.tokenHash(),
        "the audit carries the public selector, never the verifier");
  }

  @Test
  @DisplayName("JS-SEC-074: consume retires every other open token of the credential")
  void consumeRetiresRemainingSibling() {
    Fixture f = new Fixture();
    f.register("alice", "Old-Password-1", CredentialStatus.ACTIVE);
    ResetTokenCreationResult issued = f.service.issue("alice", TTL);
    // a second open token that bypassed issue(), e.g. written by another node
    SelectorVerifierToken stray = f.digestService.generate();
    f.tokens.save(new ResetTokenRecord(f.digestService.digest(stray), "alice",
        T0, T0.plus(TTL), ResetTokenStatus.ISSUED, 1L));
    f.clock.advance(Duration.ofSeconds(1));

    assertInstanceOf(PasswordResetConsumeResult.Succeeded.class,
        f.service.consume(((ResetTokenCreationResult.Created) issued).token().encode(),
            SecretValue.ofChars("New-Password-1".toCharArray())));

    assertEquals(ResetTokenStatus.EXPIRED, f.tokens.findBySelector(stray.selector()).orElseThrow().status(),
        "the sibling must be retired after a successful reset");
    assertInstanceOf(PasswordResetConsumeResult.Failed.class,
        f.service.consume(stray.encode(), SecretValue.ofChars("Another-Password-1".toCharArray())));
  }

  @Test
  @DisplayName("issue mints a token, persists the digest, and transitions credential to RESET_PENDING")
  void issueHappyPath() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);

    ResetTokenCreationResult result = f.service.issue("alice", TTL);
    ResetTokenCreationResult.Created created = assertInstanceOf(
        ResetTokenCreationResult.Created.class, result);
    assertEquals(1, f.tokens.size());
    assertEquals(CredentialStatus.RESET_PENDING,
        f.credentials.findByUsername("alice").orElseThrow().status());
    assertTrue(created.token().encode().contains("."));
  }

  @Test
  @DisplayName("issue for unknown user returns UnknownUser without writing anything")
  void issueUnknownUser() {
    Fixture f = new Fixture();
    ResetTokenCreationResult result = f.service.issue("ghost", TTL);
    assertSame(ResetTokenCreationResult.UnknownUser.INSTANCE, result);
    assertEquals(0, f.tokens.size());
  }

  @Test
  @DisplayName("issue against a DISABLED account returns Blocked without writing a token")
  void issueDisabledBlocked() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.DISABLED);
    ResetTokenCreationResult result = f.service.issue("alice", TTL);
    assertSame(ResetTokenCreationResult.Blocked.INSTANCE, result);
    assertEquals(0, f.tokens.size());
  }

  @Test
  @DisplayName("JS-SEC-076: a COMPROMISED credential may start a reset — the reset rotates the secret")
  void issueCompromisedStartsReset() {
    Fixture f = new Fixture();
    String oldHash = f.register("alice", "Old-Password-1", CredentialStatus.COMPROMISED);
    ResetTokenCreationResult issued = f.service.issue("alice", TTL);
    assertInstanceOf(ResetTokenCreationResult.Created.class, issued, "a reset is the way out of COMPROMISED");
    assertEquals(CredentialStatus.RESET_PENDING, f.credentials.findByUsername("alice").orElseThrow().status());

    f.clock.advance(Duration.ofSeconds(1));
    assertInstanceOf(PasswordResetConsumeResult.Succeeded.class,
        f.service.consume(((ResetTokenCreationResult.Created) issued).token().encode(),
            SecretValue.ofChars("New-Password-1".toCharArray())));
    CredentialRecord after = f.credentials.findByUsername("alice").orElseThrow();
    assertEquals(CredentialStatus.ACTIVE, after.status());
    assertFalse(oldHash.equals(after.encodedHash()), "the compromised hash must be gone");
  }

  @Test
  @DisplayName("JS-SEC-076: MUST_CHANGE still issues a reset token; DISABLED stays blocked")
  void issueMustChangeCreatedDisabledBlocked() {
    Fixture f = new Fixture();
    f.register("alice", "Old-Password-1", CredentialStatus.MUST_CHANGE);
    f.register("bob", "Old-Password-1", CredentialStatus.DISABLED);
    assertInstanceOf(ResetTokenCreationResult.Created.class, f.service.issue("alice", TTL));
    assertInstanceOf(ResetTokenCreationResult.Blocked.class, f.service.issue("bob", TTL));
  }

  @Test
  @DisplayName("consume happy path: hash updated, token consumed, credential ACTIVE again")
  void consumeHappyPath() {
    Fixture f = new Fixture();
    String oldEncoded = f.register("alice", "old-password", CredentialStatus.ACTIVE);

    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        f.service.issue("alice", TTL);
    String wire = created.token().encode();
    PasswordResetConsumeResult result = f.service.consume(
        wire, SecretValue.ofString("new-password-22"));
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE, result);

    CredentialRecord stored = f.credentials.findByUsername("alice").orElseThrow();
    assertNotEquals(oldEncoded, stored.encodedHash());
    assertEquals(CredentialStatus.ACTIVE, stored.status());
  }

  @Test
  @DisplayName("Second consume of the same token fails generically (single-use, CWE-640)")
  void consumeSingleUse() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);
    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        f.service.issue("alice", TTL);
    String wire = created.token().encode();

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        f.service.consume(wire, SecretValue.ofString("new-password-22")));
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        f.service.consume(wire, SecretValue.ofString("another-password-22")));
  }

  @Test
  @DisplayName("Expired token fails generically and is lazily marked EXPIRED")
  void consumeExpired() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);
    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        f.service.issue("alice", TTL);
    String wire = created.token().encode();

    f.clock.advance(TTL.plusSeconds(1));
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        f.service.consume(wire, SecretValue.ofString("new-password-22")));
    assertEquals(ResetTokenStatus.EXPIRED,
        f.tokens.findBySelector(created.token().selector()).orElseThrow().status());
  }

  @Test
  @DisplayName("Unknown selector fails generically")
  void consumeUnknownSelector() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);
    SelectorVerifierToken ghost = new TokenDigestService().generate();
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        f.service.consume(ghost.encode(),
            SecretValue.ofString("new-password-22")));
  }

  @Test
  @DisplayName("Malformed wire token fails generically")
  void consumeMalformed() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        f.service.consume("no-dot-here",
            SecretValue.ofString("new-password-22")));
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        f.service.consume(null, SecretValue.ofString("new-password-22")));
  }

  @Test
  @DisplayName("New password below the input policy minimum fails generically")
  void newPasswordRejectedByPolicy() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);
    ResetTokenCreationResult.Created created = (ResetTokenCreationResult.Created)
        f.service.issue("alice", TTL);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        f.service.consume(created.token().encode(),
            SecretValue.ofString("short")));
  }

  @Test
  @DisplayName("issue does NOT touch the credential hash; only the consume step rewrites it")
  void issueDoesNotChangeHash() {
    Fixture f = new Fixture();
    String oldEncoded = f.register("alice", "old-password", CredentialStatus.ACTIVE);
    f.service.issue("alice", TTL);
    assertEquals(oldEncoded,
        f.credentials.findByUsername("alice").orElseThrow().encodedHash());
  }

  @Test
  @DisplayName("ttl invariants: zero or negative ttl is rejected")
  void issueRejectsBadTtl() {
    Fixture f = new Fixture();
    f.register("alice", "old-password", CredentialStatus.ACTIVE);
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> f.service.issue("alice", Duration.ZERO));
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> f.service.issue("alice", Duration.ofSeconds(-1)));
  }
}
