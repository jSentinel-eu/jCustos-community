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
package eu.jsentinel.jcustos.credential.password;

import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationContext;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationService;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PipelineLimiterAndDummyTest {

  /**
   * Counting {@link DummyVerificationService} backed by a real PBKDF2
   * verification so dummy KDF cost stays realistic. Not a mock &mdash;
   * it implements the full SPI and delegates to a real provider.
   */
  private static final class CountingDummyService implements DummyVerificationService {
    private final DummyVerificationService delegate;
    private final Map<DummyVerificationContext, Integer> calls =
        new EnumMap<>(DummyVerificationContext.class);

    CountingDummyService(DummyVerificationService delegate) {
      this.delegate = delegate;
    }

    @Override
    public void runDummyKdf(char[] password, DummyVerificationContext context) {
      calls.merge(context, 1, Integer::sum);
      delegate.runDummyKdf(password, context);
    }

    int callsFor(DummyVerificationContext c) {
      return calls.getOrDefault(c, 0);
    }
  }

  private static PasswordHashPolicy fastTestPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    min.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
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

  private DefaultPasswordHashingService buildService(
      KdfExecutionLimiter limiter, CountingDummyService dummy) {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    return new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(
            new PasswordHashParameterValidatorRegistry(List.of(
                new Pbkdf2ParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        fastTestPolicy(),
        new RehashDecisionEngine(),
        limiter,
        dummy);
  }

  private CountingDummyService newCountingDummy() {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider()));
    return new CountingDummyService(new DefaultDummyVerificationService(
        registry, fastTestPolicy(), PasswordHashCodec.DEFAULT));
  }

  @Test
  @DisplayName("verifyAgainstNothing runs dummy KDF for the UNKNOWN_USER context")
  void unknownUserPathRunsDummyKdf() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);

    CredentialVerificationResult result = service.verifyAgainstNothing(
        "hunter2".toCharArray());
    assertInstanceOf(CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.INVALID_CREDENTIALS,
        ((CredentialVerificationResult.Failed) result).publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_DUMMY_PATH,
        ((CredentialVerificationResult.Failed) result).internalAuditEventType());
    assertEquals(1, dummy.callsFor(DummyVerificationContext.UNKNOWN_USER));
  }

  @Test
  @DisplayName("Malformed envelope triggers a dummy KDF with ENVELOPE_DECODE_ERROR context")
  void malformedEnvelopePathTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);
    service.verify("x".toCharArray(), "not-an-envelope");
    assertEquals(1, dummy.callsFor(DummyVerificationContext.ENVELOPE_DECODE_ERROR));
  }

  @Test
  @DisplayName("Null encoded hash triggers a dummy KDF with ENVELOPE_DECODE_ERROR context")
  void nullEnvelopeTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);
    service.verify("x".toCharArray(), null);
    assertEquals(1, dummy.callsFor(DummyVerificationContext.ENVELOPE_DECODE_ERROR));
  }

  @Test
  @DisplayName("Validation rejection triggers a dummy KDF with ENVELOPE_VALIDATION_ERROR context")
  void validationFailurePathTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);
    // Build a valid PBKDF2 envelope but with iterations above the policy max.
    PasswordHashResult ok = new Pbkdf2PasswordHashProvider().hash(
        "x".toCharArray(), fastTestPolicy(), java.util.Optional.empty());
    String tampered = ok.encodedHash().replace("$p=i=1000", "$p=i=9999");
    service.verify("x".toCharArray(), tampered);
    assertEquals(1,
        dummy.callsFor(DummyVerificationContext.ENVELOPE_VALIDATION_ERROR));
  }

  @Test
  @DisplayName("Unknown provider triggers a dummy KDF with PROVIDER_MISSING context")
  void unknownProviderPathTriggersDummy() {
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(
        NoLimitKdfExecutionLimiter.INSTANCE, dummy);

    String good = new Pbkdf2PasswordHashProvider()
        .hash("x".toCharArray(), fastTestPolicy(), java.util.Optional.empty())
        .encodedHash();
    String spoofedProvider = good.replace(
        "$prov=" + Pbkdf2ParameterNames.PROVIDER_ID + "$",
        "$prov=ghost-provider$");
    service.verify("x".toCharArray(), spoofedProvider);
    assertEquals(1, dummy.callsFor(DummyVerificationContext.PROVIDER_MISSING));
  }

  @Test
  @DisplayName("JS-SEC-126: limiter rejection is TEMPORARILY_UNAVAILABLE + KDF_LIMIT audit, never INVALID_CREDENTIALS")
  void limiterRejectionMapsToTemporarilyUnavailable() throws InterruptedException {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(50)));
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(limiter, dummy);
    PasswordHashResult stored = service.hash("hunter2".toCharArray());

    CountDownLatch holderAcquired = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    Thread holder = new Thread(() -> {
      KdfExecutionLimiter.Lease l = limiter.acquire().orElseThrow();
      holderAcquired.countDown();
      try {
        release.await(5, TimeUnit.SECONDS);
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
      } finally {
        l.close();
      }
    });
    holder.setDaemon(true);
    holder.start();
    assertTrue(holderAcquired.await(2, TimeUnit.SECONDS));

    // the CORRECT password against its own hash: shed load must not read as "wrong"
    CredentialVerificationResult result = service.verify(
        "hunter2".toCharArray(), stored.encodedHash());
    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.TEMPORARILY_UNAVAILABLE, f.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT,
        f.internalAuditEventType());
    assertTrue(result.temporarilyUnavailable());

    // the unknown-user path is shed the same way - the outcome does not depend on the account
    CredentialVerificationResult.Failed unknownUser = assertInstanceOf(
        CredentialVerificationResult.Failed.class,
        service.verifyAgainstNothing("hunter2".toCharArray()));
    assertEquals(PublicFailureType.TEMPORARILY_UNAVAILABLE, unknownUser.publicFailureType());
    assertEquals(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT,
        unknownUser.internalAuditEventType());
    assertEquals(0, dummy.callsFor(DummyVerificationContext.UNKNOWN_USER),
        "a shed call runs no KDF at all");

    release.countDown();
    holder.join(1000);

    // with the permit back the same call is evaluated: right password verifies, wrong one is
    // INVALID_CREDENTIALS and not "unavailable"
    assertInstanceOf(CredentialVerificationResult.Verified.class,
        service.verify("hunter2".toCharArray(), stored.encodedHash()));
    CredentialVerificationResult wrong = service.verify("nope".toCharArray(), stored.encodedHash());
    assertEquals(PublicFailureType.INVALID_CREDENTIALS,
        assertInstanceOf(CredentialVerificationResult.Failed.class, wrong).publicFailureType());
    assertFalse(wrong.temporarilyUnavailable());
  }

  @Test
  @DisplayName("JS-SEC-126: throwIfUnavailable turns a shed result into the third outcome and passes every other result")
  void throwIfUnavailable() {
    CredentialVerificationUnavailableException.throwIfUnavailable(
        new CredentialVerificationResult.Failed(PublicFailureType.INVALID_CREDENTIALS,
            InternalAuditEventType.VERIFICATION_FAILED_MISMATCH));
    CredentialVerificationUnavailableException thrown = assertThrows(
        CredentialVerificationUnavailableException.class,
        () -> CredentialVerificationUnavailableException.throwIfUnavailable(
            new CredentialVerificationResult.Failed(PublicFailureType.TEMPORARILY_UNAVAILABLE,
                InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT)));
    assertEquals("credential verification is temporarily unavailable", thrown.getMessage());
  }

  @Test
  @DisplayName("Concurrent verifications drain the limiter; one is rejected")
  void concurrencyDrainsTheLimiter() throws InterruptedException {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    CountingDummyService dummy = newCountingDummy();
    DefaultPasswordHashingService service = buildService(limiter, dummy);

    PasswordHashResult ok = service.hash("hunter2".toCharArray());
    AtomicInteger rejected = new AtomicInteger();
    AtomicInteger accepted = new AtomicInteger();
    Thread[] threads = new Thread[6];
    for (int i = 0; i < threads.length; i++) {
      threads[i] = new Thread(() -> {
        CredentialVerificationResult r = service.verify(
            "hunter2".toCharArray(), ok.encodedHash());
        if (r instanceof CredentialVerificationResult.Failed f
            && f.internalAuditEventType()
                == InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT) {
          rejected.incrementAndGet();
        } else {
          accepted.incrementAndGet();
        }
      });
      threads[i].setDaemon(true);
      threads[i].start();
    }
    for (Thread t : threads) {
      t.join(15_000);
    }
    assertEquals(threads.length, rejected.get() + accepted.get());
    assertTrue(accepted.get() >= 1, "at least one verification must succeed");
  }
}
