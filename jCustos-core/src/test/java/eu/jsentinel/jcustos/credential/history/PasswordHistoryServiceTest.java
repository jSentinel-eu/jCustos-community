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
package eu.jsentinel.jcustos.credential.history;

import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordHistoryServiceTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

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
    final InMemoryPasswordHistoryStore store = new InMemoryPasswordHistoryStore();
    final PasswordHashingService hashingService = PasswordHashingServices.defaults(
        fastTestPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
    final PasswordHistoryService service = new PasswordHistoryService(
        store, hashingService);
  }

  @Test
  @DisplayName("History disabled: evaluate always Allows, recordNew is a no-op")
  void disabledIsNoOp() {
    Fixture f = new Fixture();
    PasswordHistoryPolicy disabled = PasswordHistoryPolicy.disabled();
    assertSame(PasswordHistoryDecision.Allowed.INSTANCE,
        f.service.evaluate("alice", SecretValue.ofString("hunter222"), disabled));
    PasswordHashResult hash = f.hashingService.hash("hunter222".toCharArray());
    f.service.recordNew("alice", hash.encodedHash(), T0, disabled);
    assertEquals(0, f.store.size("alice"));
  }

  @Test
  @DisplayName("Reuse of the most recent password is rejected")
  void reuseRejected() {
    Fixture f = new Fixture();
    PasswordHistoryPolicy policy = PasswordHistoryPolicy.retain(3);
    PasswordHashResult oldHash = f.hashingService.hash("hunter222".toCharArray());
    f.service.recordNew("alice", oldHash.encodedHash(), T0, policy);
    assertSame(PasswordHistoryDecision.Reused.INSTANCE,
        f.service.evaluate("alice",
            SecretValue.ofString("hunter222"), policy));
  }

  @Test
  @DisplayName("A different new password is allowed")
  void differentPasswordAllowed() {
    Fixture f = new Fixture();
    PasswordHistoryPolicy policy = PasswordHistoryPolicy.retain(3);
    PasswordHashResult oldHash = f.hashingService.hash("hunter222".toCharArray());
    f.service.recordNew("alice", oldHash.encodedHash(), T0, policy);
    assertSame(PasswordHistoryDecision.Allowed.INSTANCE,
        f.service.evaluate("alice",
            SecretValue.ofString("brand-new-password"), policy));
  }

  @Test
  @DisplayName("Retention cap: only retainLast entries are kept; older fall out")
  void retentionCap() {
    Fixture f = new Fixture();
    PasswordHistoryPolicy policy = PasswordHistoryPolicy.retain(2);
    PasswordHashResult h1 = f.hashingService.hash("pw1-xxxxxx".toCharArray());
    PasswordHashResult h2 = f.hashingService.hash("pw2-xxxxxx".toCharArray());
    PasswordHashResult h3 = f.hashingService.hash("pw3-xxxxxx".toCharArray());
    f.service.recordNew("alice", h1.encodedHash(), T0, policy);
    f.service.recordNew("alice", h2.encodedHash(), T0, policy);
    f.service.recordNew("alice", h3.encodedHash(), T0, policy);
    assertEquals(2, f.store.size("alice"),
        "history must respect retainLast (CWE-400)");
    // pw1 fell out of the window; reuse is allowed again.
    assertSame(PasswordHistoryDecision.Allowed.INSTANCE,
        f.service.evaluate("alice",
            SecretValue.ofString("pw1-xxxxxx"), policy));
    // pw3 is the freshest entry; reuse rejected.
    assertSame(PasswordHistoryDecision.Reused.INSTANCE,
        f.service.evaluate("alice",
            SecretValue.ofString("pw3-xxxxxx"), policy));
  }

  @Test
  @DisplayName("Unknown user yields Allowed")
  void unknownUserAllowed() {
    Fixture f = new Fixture();
    assertSame(PasswordHistoryDecision.Allowed.INSTANCE,
        f.service.evaluate("ghost",
            SecretValue.ofString("anything-22"),
            PasswordHistoryPolicy.retain(3)));
  }

  @Test
  @DisplayName("PasswordHistoryPolicy invariants reject retainLast<0 and enabled+0")
  void policyInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordHistoryPolicy(false, -1));
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordHistoryPolicy(true, 0));
  }

  @Test
  @DisplayName("PasswordHistoryEntry.toString never exposes the encoded hash")
  void entryToStringRedacted() {
    PasswordHistoryEntry entry = new PasswordHistoryEntry(
        "$pwh$v=1$ct=PASSWORD$alg=PBKDF2WithHmacSHA256$prov=pbkdf2-jdk"
            + "$pol=1$p=i=1000,l=32,s=AAAAAAAAAAAAAAAAAAAAAA=="
            + "$h=ZGVyaXZlZA==",
        T0);
    String text = entry.toString();
    org.junit.jupiter.api.Assertions.assertFalse(text.contains("ZGVyaXZlZA=="));
    org.junit.jupiter.api.Assertions.assertTrue(text.contains("<redacted>"));
  }

  @Test
  @DisplayName("InMemoryPasswordHistoryStore.recent returns newest-first")
  void recentNewestFirst() {
    InMemoryPasswordHistoryStore store = new InMemoryPasswordHistoryStore();
    store.appendAndTrim("alice", new PasswordHistoryEntry("h1", T0), 3);
    store.appendAndTrim("alice", new PasswordHistoryEntry("h2", T0.plusSeconds(1)), 3);
    store.appendAndTrim("alice", new PasswordHistoryEntry("h3", T0.plusSeconds(2)), 3);
    assertEquals("h3", store.recent("alice", 3).get(0).encodedHash());
    assertEquals("h1", store.recent("alice", 3).get(2).encodedHash());
  }

  @Test
  @DisplayName("InMemoryPasswordHistoryStore rejects retainLast<1 on appendAndTrim")
  void storeRejectsZeroRetain() {
    InMemoryPasswordHistoryStore store = new InMemoryPasswordHistoryStore();
    assertThrows(IllegalArgumentException.class,
        () -> store.appendAndTrim("alice",
            new PasswordHistoryEntry("h", T0), 0));
  }

  // ── JS-SEC-126 (CWE-636): "could not verify" is not "not reused" ──

  @Test
  @DisplayName("JS-SEC-126: saturated KDF limiter + old password -> Indeterminate (transient), never Allowed")
  void saturatedLimiterDoesNotLetAnOldPasswordThrough() {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(50)));
    PasswordHashingService hashing = PasswordHashingServices.defaults(fastTestPolicy(), limiter);
    InMemoryPasswordHistoryStore store = new InMemoryPasswordHistoryStore();
    PasswordHistoryService service = new PasswordHistoryService(store, hashing);
    PasswordHistoryPolicy policy = PasswordHistoryPolicy.retain(3);
    service.recordNew("alice", hashing.hash("hunter222".toCharArray()).encodedHash(), T0, policy);
    assertSame(PasswordHistoryCheck.Reused.INSTANCE,
        service.check("alice", SecretValue.ofString("hunter222"), policy), "idle limiter: detected");

    // one concurrent login holds the only permit while the user re-submits the old password
    try (KdfExecutionLimiter.Lease held = limiter.acquire().orElseThrow()) {
      PasswordHistoryCheck.Indeterminate indeterminate = assertInstanceOf(
          PasswordHistoryCheck.Indeterminate.class,
          service.check("alice", SecretValue.ofString("hunter222"), policy));
      assertEquals(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT, indeterminate.reason());
      assertTrue(indeterminate.transientCondition());

      assertNotSame(PasswordHistoryDecision.Allowed.INSTANCE,
          service.evaluate("alice", SecretValue.ofString("hunter222"), policy),
          "the two-valued form must fail closed");
      assertSame(PasswordHistoryDecision.Reused.INSTANCE,
          service.evaluate("alice", SecretValue.ofString("hunter222"), policy));
    }

    // permit back: the reuse is detected again, a new password passes
    assertSame(PasswordHistoryDecision.Reused.INSTANCE,
        service.evaluate("alice", SecretValue.ofString("hunter222"), policy));
    assertSame(PasswordHistoryCheck.NotReused.INSTANCE,
        service.check("alice", SecretValue.ofString("brand-new-1"), policy));
  }

  @Test
  @DisplayName("JS-SEC-126: a history entry that can no longer be verified -> Indeterminate (lasting), never Allowed")
  void unverifiableEntryDoesNotCountAsMiss() {
    Fixture f = new Fixture();
    PasswordHistoryPolicy policy = PasswordHistoryPolicy.retain(3);
    // what a migration leaves behind: an envelope whose provider is not registered any more
    String orphaned = f.hashingService.hash("hunter222".toCharArray()).encodedHash().replace(
        "$prov=" + Pbkdf2ParameterNames.PROVIDER_ID + "$", "$prov=retired-provider$");
    f.store.appendAndTrim("alice", new PasswordHistoryEntry(orphaned, T0), 3);

    PasswordHistoryCheck.Indeterminate indeterminate = assertInstanceOf(
        PasswordHistoryCheck.Indeterminate.class,
        f.service.check("alice", SecretValue.ofString("hunter222"), policy));
    assertEquals(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PROVIDER, indeterminate.reason());
    assertFalse(indeterminate.transientCondition());
    assertSame(PasswordHistoryDecision.Reused.INSTANCE,
        f.service.evaluate("alice", SecretValue.ofString("hunter222"), policy));
  }

  @Test
  @DisplayName("JS-SEC-126: a definite reuse wins over an unverifiable entry; a clean history still allows")
  void definiteAnswersAreUnchanged() {
    Fixture f = new Fixture();
    PasswordHistoryPolicy policy = PasswordHistoryPolicy.retain(3);
    String orphaned = f.hashingService.hash("other-pass-1".toCharArray()).encodedHash().replace(
        "$prov=" + Pbkdf2ParameterNames.PROVIDER_ID + "$", "$prov=retired-provider$");
    f.store.appendAndTrim("alice", new PasswordHistoryEntry(orphaned, T0), 3);
    f.service.recordNew("alice",
        f.hashingService.hash("hunter222".toCharArray()).encodedHash(), T0.plusSeconds(1), policy);

    assertSame(PasswordHistoryCheck.Reused.INSTANCE,
        f.service.check("alice", SecretValue.ofString("hunter222"), policy),
        "the verifiable entry proves the reuse whatever the orphaned one says");

    f.service.recordNew("bob",
        f.hashingService.hash("hunter222".toCharArray()).encodedHash(), T0, policy);
    assertSame(PasswordHistoryCheck.NotReused.INSTANCE,
        f.service.check("bob", SecretValue.ofString("brand-new-1"), policy));
    assertSame(PasswordHistoryDecision.Allowed.INSTANCE,
        f.service.evaluate("bob", SecretValue.ofString("brand-new-1"), policy));
    assertSame(PasswordHistoryCheck.NotReused.INSTANCE,
        f.service.check("bob", SecretValue.ofString("hunter222"), PasswordHistoryPolicy.disabled()));
  }
}
